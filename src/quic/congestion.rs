//! QUIC congestion control implementation
//!
//! Implements multiple congestion control algorithms:
//! - NewReno (RFC 9002 Section 7)
//! - BBR (Bottleneck Bandwidth and Round-trip propagation time)

use crate::{
    util::time::{Duration, Instant},
    quic::bbr::{BBRController, BBRState as AdvancedBBRState},
    quic::cubic::{CubicController, CubicState},
    quic::pacing::{PacingController, PacingConfig, PacingStats},
    quic::ecn::{EcnController, EcnCodepoint, EcnCongestionEvent, EcnStats},
    error::{Result, Http3ErrorCode},
    error_context::ErrorConversion,
};
use std::collections::VecDeque;

/// Available congestion control algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionAlgorithm {
    /// NewReno (RFC 9002 Section 7)
    NewReno,
    /// BBR (Bottleneck Bandwidth and RTT-based)
    BBR,
    /// Advanced BBR with enhanced features
    BBRv2,
    /// CUBIC (RFC 8312)
    CUBIC,
}

impl Default for CongestionAlgorithm {
    fn default() -> Self {
        Self::NewReno
    }
}

/// Congestion control state following RFC 9002
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionState {
    /// Slow start phase
    SlowStart,
    /// Congestion avoidance phase  
    CongestionAvoidance,
    /// Recovery phase after loss detection
    Recovery,
}

/// BBR congestion control states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BBRState {
    /// Startup: exponentially grow sending rate
    Startup,
    /// Drain: drain the queue created during startup
    Drain,
    /// ProbeBW: probe for more bandwidth
    ProbeBW,
    /// ProbeRTT: probe for minimum RTT
    ProbeRTT,
}

/// BBR cycle phases for bandwidth probing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BBRCyclePhase {
    /// Gain bandwidth
    Up = 0,
    /// Drain queue
    Down = 1,
    /// Cruise control
    Cruise = 2,
}

/// RTT statistics for external monitoring
#[derive(Debug, Clone)]
pub struct RttStats {
    /// Smoothed RTT
    pub smoothed_rtt: Duration,
    /// Minimum RTT observed
    pub min_rtt: Duration,
    /// Latest RTT measurement
    pub latest_rtt: Duration,
    /// RTT variance
    pub rtt_var: Duration,
    /// Number of samples collected
    pub sample_count: u64,
}

/// Bandwidth measurement sample
#[derive(Debug, Clone)]
struct BandwidthSample {
    /// Bandwidth in bytes per second
    bandwidth: u64,
    /// RTT measurement
    rtt: Duration,
    /// Time when sample was taken
    timestamp: Instant,
    /// Bytes acknowledged
    bytes_acked: u64,
}

/// RTT tracking for production-grade measurements
#[derive(Debug, Clone)]
struct RttTracker {
    /// Smoothed RTT (SRTT) as per RFC 9002
    smoothed_rtt: Duration,
    /// RTT variance for timeout calculation
    rtt_var: Duration,
    /// Latest RTT measurement
    latest_rtt: Duration,
    /// Minimum RTT observed
    min_rtt: Duration,
    /// Maximum RTT observed
    max_rtt: Duration,
    /// Number of RTT samples collected
    sample_count: u64,
    /// First RTT sample flag
    first_sample: bool,
}

impl RttTracker {
    fn new() -> Self {
        Self {
            smoothed_rtt: Duration::from_millis(333), // Initial RTT per RFC 9002
            rtt_var: Duration::from_millis(333) / 2,
            latest_rtt: Duration::ZERO,
            min_rtt: Duration::MAX,
            max_rtt: Duration::ZERO,
            sample_count: 0,
            first_sample: true,
        }
    }
    
    /// Update RTT measurements with new sample
    fn update_rtt(&mut self, rtt_sample: Duration) {
        self.latest_rtt = rtt_sample;
        self.sample_count += 1;
        
        // Update min and max RTT
        if rtt_sample < self.min_rtt {
            self.min_rtt = rtt_sample;
        }
        if rtt_sample > self.max_rtt {
            self.max_rtt = rtt_sample;
        }
        
        // RFC 9002 Section 5.3: RTT estimation
        if self.first_sample {
            self.smoothed_rtt = rtt_sample;
            self.rtt_var = rtt_sample / 2;
            self.first_sample = false;
        } else {
            let rtt_var_sample = if self.smoothed_rtt > rtt_sample {
                self.smoothed_rtt - rtt_sample
            } else {
                rtt_sample - self.smoothed_rtt
            };
            
            self.rtt_var = self.rtt_var * 3 / 4 + rtt_var_sample / 4;
            self.smoothed_rtt = self.smoothed_rtt * 7 / 8 + rtt_sample / 8;
        }
    }
    
    /// Get current smoothed RTT
    fn smoothed_rtt(&self) -> Duration {
        self.smoothed_rtt
    }
    
    /// Get minimum RTT
    fn min_rtt(&self) -> Duration {
        if self.min_rtt == Duration::MAX {
            Duration::from_millis(333) // Default if no samples
        } else {
            self.min_rtt
        }
    }
    
    /// Get latest RTT
    fn latest_rtt(&self) -> Duration {
        self.latest_rtt
    }
    
    /// Get RTT variance
    fn rtt_var(&self) -> Duration {
        self.rtt_var
    }
}

/// Multi-algorithm congestion controller
pub struct CongestionController {
    /// Selected congestion control algorithm
    algorithm: CongestionAlgorithm,
    /// Maximum datagram size
    max_datagram_size: u64,
    /// Initial congestion window
    initial_window: u64,
    /// Minimum congestion window
    min_window: u64,
    
    // NewReno state
    pub newreno: NewRenoState,
    
    // BBR state (legacy)
    bbr: BBRState_,
    
    // Advanced BBR controller
    bbr_controller: Option<BBRController>,
    
    // CUBIC controller
    cubic_controller: Option<CubicController>,
    
    // Packet pacing controller
    pacing_controller: PacingController,
    
    // ECN controller
    ecn_controller: EcnController,
    
    // RTT tracking for production-grade measurements
    rtt_tracker: RttTracker,
}

/// NewReno algorithm state
#[derive(Debug, Clone)]
struct NewRenoState {
    /// Current congestion window (bytes)
    congestion_window: u64,
    /// Slow start threshold (bytes)
    ssthresh: u64,
    /// Bytes acknowledged in current congestion window
    bytes_acked: u64,
    /// Congestion control state
    state: CongestionState,
    /// Time when recovery period started
    recovery_start_time: Option<Instant>,
}

/// BBR algorithm state
#[derive(Debug, Clone)]
struct BBRState_ {
    /// Current BBR state
    state: BBRState,
    /// Current cycle phase for ProbeBW
    cycle_phase: BBRCyclePhase,
    /// Current sending rate (bytes per second)
    sending_rate: u64,
    /// Estimated bottleneck bandwidth
    bottleneck_bandwidth: u64,
    /// Minimum RTT observed
    min_rtt: Duration,
    /// Time when min_rtt was last updated
    min_rtt_timestamp: Instant,
    /// Bandwidth samples for estimation
    bandwidth_samples: VecDeque<BandwidthSample>,
    /// Current bandwidth filter window
    bandwidth_filter: BandwidthFilter,
    /// Pacing gain for current state
    pacing_gain: f64,
    /// Congestion window gain
    cwnd_gain: f64,
    /// Cycle index for ProbeBW
    cycle_index: usize,
    /// Time spent in current state
    state_duration: Duration,
    /// Last state transition time
    last_state_change: Instant,
    /// Target congestion window
    target_cwnd: u64,
    /// Probe RTT duration
    probe_rtt_duration: Duration,
    /// Whether we're in probe RTT mode
    probe_rtt_active: bool,
}

/// Bandwidth filter for BBR (maintains max bandwidth over time window)
#[derive(Debug, Clone)]
struct BandwidthFilter {
    /// Maximum bandwidth samples
    max_values: VecDeque<(u64, Instant)>,
    /// Window duration for bandwidth filter
    window_duration: Duration,
}

impl CongestionController {
    /// Create a new congestion controller with specified algorithm
    pub fn new() -> Self {
        Self::with_algorithm(CongestionAlgorithm::default())
    }
    
    /// Create a new congestion controller with specified algorithm
    pub fn with_algorithm(algorithm: CongestionAlgorithm) -> Self {
        let max_datagram_size = 1200; // Conservative estimate
        let initial_window = Self::initial_congestion_window(max_datagram_size);
        let now = Instant::now();
        
        let bbr_controller = if matches!(algorithm, CongestionAlgorithm::BBRv2) {
            Some(BBRController::new(max_datagram_size))
        } else {
            None
        };

        let cubic_controller = if matches!(algorithm, CongestionAlgorithm::CUBIC) {
            Some(CubicController::new((max_datagram_size as u32).max(1)))
        } else {
            None
        };

        Self {
            algorithm,
            max_datagram_size,
            initial_window,
            min_window: 2 * max_datagram_size,
            newreno: NewRenoState {
                congestion_window: initial_window,
                ssthresh: u64::MAX,
                bytes_acked: 0,
                state: CongestionState::SlowStart,
                recovery_start_time: None,
            },
            bbr: BBRState_ {
                state: BBRState::Startup,
                cycle_phase: BBRCyclePhase::Up,
                sending_rate: initial_window,
                bottleneck_bandwidth: 0,
                min_rtt: Duration::from_millis(1000), // Initial RTT estimate
                min_rtt_timestamp: now,
                bandwidth_samples: VecDeque::with_capacity(10),
                bandwidth_filter: BandwidthFilter {
                    max_values: VecDeque::with_capacity(10),
                    window_duration: Duration::from_secs(10),
                },
                pacing_gain: 2.77, // High gain for startup
                cwnd_gain: 2.0,
                cycle_index: 0,
                state_duration: Duration::ZERO,
                last_state_change: now,
                target_cwnd: initial_window,
                probe_rtt_duration: Duration::from_millis(200),
                probe_rtt_active: false,
            },
            bbr_controller,
            cubic_controller,
            pacing_controller: PacingController::new(PacingConfig::default()),
            ecn_controller: EcnController::new(),
            rtt_tracker: RttTracker::new(),
        }
    }

    /// Calculate initial congestion window per RFC 9002
    fn initial_congestion_window(max_datagram_size: u64) -> u64 {
        (10 * max_datagram_size).min(32768) // 10 packets or 32KB, whichever is smaller
    }

    /// Process acknowledgment of packets
    pub fn on_ack_received(&mut self, ack_ranges: &[(u64, u64)]) -> Result<()> {
        self.on_ack_received_with_rtt(ack_ranges, Duration::from_millis(100))
    }
    
    /// Process acknowledgment of packets with RTT measurement
    pub fn on_ack_received_with_rtt(&mut self, ack_ranges: &[(u64, u64)], rtt: Duration) -> Result<()> {
        let acked_bytes: u64 = ack_ranges.iter()
            .map(|(start, end)| (end - start + 1) * self.max_datagram_size)
            .sum();

        // Update RTT tracker with new measurement
        self.rtt_tracker.update_rtt(rtt);
        
        // Get smoothed RTT for congestion control algorithms
        let smoothed_rtt = self.rtt_tracker.smoothed_rtt();
        
        // Update pacing controller with ACK information
        self.pacing_controller.on_ack_received(acked_bytes, smoothed_rtt);
        
        // Update ECN controller with ACK information
        self.ecn_controller.on_ack_received(acked_bytes, smoothed_rtt);

        match self.algorithm {
            CongestionAlgorithm::NewReno => {
                self.newreno_on_ack_received(acked_bytes);
                Ok(())
            }
            CongestionAlgorithm::BBR => {
                self.bbr_on_ack_received(acked_bytes, smoothed_rtt);
                Ok(())
            }
            CongestionAlgorithm::BBRv2 => {
                if let Some(ref mut bbr) = self.bbr_controller {
                    bbr.on_ack(acked_bytes, smoothed_rtt, Instant::now())
                } else {
                    Err("BBRv2 controller not initialized".to_http3_error(Http3ErrorCode::InternalError))
                }
            }
            CongestionAlgorithm::CUBIC => {
                if let Some(ref mut cubic) = self.cubic_controller {
                    cubic.on_ack(acked_bytes, smoothed_rtt, Instant::now());
                    Ok(())
                } else {
                    Err("CUBIC controller not initialized".to_http3_error(Http3ErrorCode::InternalError))
                }
            }
        }
    }
    
    /// NewReno ACK processing
    fn newreno_on_ack_received(&mut self, acked_bytes: u64) {
        match self.newreno.state {
            CongestionState::SlowStart => {
                // In slow start, increase cwnd by acked bytes
                self.newreno.congestion_window += acked_bytes;
                
                // Check if we should exit slow start
                if self.newreno.congestion_window >= self.newreno.ssthresh {
                    self.newreno.state = CongestionState::CongestionAvoidance;
                    self.newreno.bytes_acked = 0;
                }
            }
            CongestionState::CongestionAvoidance => {
                // In congestion avoidance, increase cwnd by (acked * MSS) / cwnd
                self.newreno.bytes_acked += acked_bytes;
                if self.newreno.bytes_acked >= self.newreno.congestion_window {
                    self.newreno.congestion_window += self.max_datagram_size;
                    self.newreno.bytes_acked = 0;
                }
            }
            CongestionState::Recovery => {
                // In recovery, don't increase window
                // Will exit recovery when we get ACK for packet sent after recovery started
            }
        }
    }
    
    /// BBR ACK processing using Rust 2024 let chains
    fn bbr_on_ack_received(&mut self, acked_bytes: u64, rtt: Duration) {
        let now = Instant::now();
        
        // Update minimum RTT
        if rtt < self.bbr.min_rtt {
            self.bbr.min_rtt = rtt;
            self.bbr.min_rtt_timestamp = now;
        }
        
        // Add bandwidth sample using let chains (Rust 2024)
        if acked_bytes > 0 && rtt > Duration::ZERO {
            let bandwidth = (acked_bytes * 1_000_000) / rtt.as_micros() as u64; // bytes per second
            let sample = BandwidthSample {
                bandwidth,
                rtt,
                timestamp: now,
                bytes_acked: acked_bytes,
            };
            
            self.bbr.bandwidth_samples.push_back(sample);
            self.bbr_update_bandwidth_filter(bandwidth, now);
            
            // Keep only recent samples
            if self.bbr.bandwidth_samples.len() > 10 {
                self.bbr.bandwidth_samples.pop_front();
            }
        }
        
        // Update BBR state machine
        self.bbr_update_state(now);
        
        // Calculate target congestion window
        self.bbr_update_congestion_window();
    }

    /// Handle packet loss detection
    pub fn on_packet_lost(&mut self, lost_bytes: u64) -> Result<()> {
        // Update pacing controller with loss information
        self.pacing_controller.on_packet_lost(lost_bytes);
        
        // Update ECN controller with loss information
        self.ecn_controller.on_packet_lost(lost_bytes);
        
        match self.algorithm {
            CongestionAlgorithm::NewReno => {
                self.newreno_on_packet_lost(lost_bytes);
                Ok(())
            }
            CongestionAlgorithm::BBR => {
                self.bbr_on_packet_lost(lost_bytes);
                Ok(())
            }
            CongestionAlgorithm::BBRv2 => {
                if let Some(ref mut bbr) = self.bbr_controller {
                    bbr.on_loss(lost_bytes, Instant::now())
                } else {
                    Err("BBRv2 controller not initialized".to_http3_error(Http3ErrorCode::InternalError))
                }
            }
            CongestionAlgorithm::CUBIC => {
                if let Some(ref mut cubic) = self.cubic_controller {
                    cubic.on_loss(lost_bytes, Instant::now());
                    Ok(())
                } else {
                    Err("CUBIC controller not initialized".to_http3_error(Http3ErrorCode::InternalError))
                }
            }
        }
    }
    
    /// NewReno loss handling
    fn newreno_on_packet_lost(&mut self, _lost_bytes: u64) {
        // Enter recovery state
        if self.newreno.state != CongestionState::Recovery {
            self.newreno.state = CongestionState::Recovery;
            self.newreno.recovery_start_time = Some(Instant::now());
            
            // Reduce congestion window and ssthresh
            self.newreno.ssthresh = (self.newreno.congestion_window / 2).max(self.min_window);
            self.newreno.congestion_window = self.newreno.ssthresh;
            self.newreno.bytes_acked = 0;
        }
    }
    
    /// BBR loss handling (BBR is less reactive to individual losses)
    fn bbr_on_packet_lost(&mut self, _lost_bytes: u64) {
        // BBR doesn't react strongly to individual packet losses
        // It relies more on bandwidth and RTT measurements
        // Only react if loss rate becomes significant
        let now = Instant::now();
        
        // If in startup and seeing losses, consider transitioning to drain
        if matches!(self.bbr.state, BBRState::Startup) {
            self.bbr.state = BBRState::Drain;
            self.bbr.last_state_change = now;
            self.bbr.pacing_gain = 1.0 / 2.77; // Reciprocal of startup gain
            self.bbr.state_duration = Duration::ZERO;
        }
    }
    
    /// BBR ECN congestion handling
    fn bbr_on_ecn_congestion(&mut self) {
        let now = Instant::now();
        
        // ECN provides early congestion signal - reduce pacing gain
        match self.bbr.state {
            BBRState::Startup => {
                // Reduce startup gain on ECN signal
                self.bbr.pacing_gain = 1.5; // Reduced from 2.77
            }
            BBRState::ProbeBW => {
                // Reduce probing aggressiveness
                if self.bbr.pacing_gain > 1.0 {
                    self.bbr.pacing_gain = 1.0;
                }
            }
            _ => {
                // Other states: reduce pacing gain slightly
                self.bbr.pacing_gain = (self.bbr.pacing_gain * 0.9).max(0.5);
            }
        }
        
        // Update state change time
        self.bbr.last_state_change = now;
        self.bbr.state_duration = Duration::ZERO;
    }

    /// Handle congestion event (when persistent congestion is detected)
    pub fn on_congestion_event(&mut self) {
        match self.algorithm {
            CongestionAlgorithm::NewReno => {
                // Reset to initial conditions on persistent congestion
                self.newreno.congestion_window = self.initial_window;
                self.newreno.ssthresh = u64::MAX;
                self.newreno.state = CongestionState::SlowStart;
                self.newreno.recovery_start_time = None;
                self.newreno.bytes_acked = 0;
            }
            CongestionAlgorithm::BBR => {
                // BBR resets to startup on persistent congestion
                let now = Instant::now();
                self.bbr.state = BBRState::Startup;
                self.bbr.last_state_change = now;
                self.bbr.pacing_gain = 2.77;
                self.bbr.cwnd_gain = 2.0;
                self.bbr.state_duration = Duration::ZERO;
                self.bbr.target_cwnd = self.initial_window;
                self.bbr.bandwidth_samples.clear();
                self.bbr.bandwidth_filter.max_values.clear();
            }
            CongestionAlgorithm::BBRv2 => {
                // Reset BBRv2 controller
                if let Some(ref mut bbr) = self.bbr_controller {
                    let now = Instant::now();
                    let _ = bbr.reset(now);
                }
            }
            CongestionAlgorithm::CUBIC => {
                // Reset CUBIC controller
                if let Some(ref mut cubic) = self.cubic_controller {
                    let now = Instant::now();
                    cubic.on_persistent_congestion(now);
                }
            }
        }
    }
    
    /// BBR bandwidth filter update
    fn bbr_update_bandwidth_filter(&mut self, bandwidth: u64, now: Instant) {
        // Remove old samples outside the window
        let cutoff = now - self.bbr.bandwidth_filter.window_duration;
        self.bbr.bandwidth_filter.max_values.retain(|(_, timestamp)| *timestamp >= cutoff);
        
        // Add new sample
        self.bbr.bandwidth_filter.max_values.push_back((bandwidth, now));
        
        // Update bottleneck bandwidth (max over the window)
        self.bbr.bottleneck_bandwidth = self.bbr.bandwidth_filter.max_values
            .iter()
            .map(|(bw, _)| *bw)
            .max()
            .unwrap_or(self.bbr.bottleneck_bandwidth);
    }
    
    /// BBR state machine update using Rust 2024 let chains
    fn bbr_update_state(&mut self, now: Instant) {
        self.bbr.state_duration = now - self.bbr.last_state_change;
        
        match self.bbr.state {
            BBRState::Startup => {
                // Exit startup if bandwidth stops growing
                if let Some(prev_bw) = self.bbr.bandwidth_samples.back().map(|s| s.bandwidth)
                    && let Some(prev_prev_bw) = self.bbr.bandwidth_samples.get(self.bbr.bandwidth_samples.len().saturating_sub(2)).map(|s| s.bandwidth)
                    && prev_bw < prev_prev_bw * 125 / 100 // Less than 25% growth
                {
                    self.bbr.state = BBRState::Drain;
                    self.bbr.pacing_gain = 1.0 / 2.77;
                    self.bbr.last_state_change = now;
                    self.bbr.state_duration = Duration::ZERO;
                }
            }
            BBRState::Drain => {
                // Exit drain when queue is drained (inflight < BDP)
                let bdp = self.bbr.bottleneck_bandwidth * (self.bbr.min_rtt.as_millis() as f64 / 1000.0) as u64;
                if self.bbr.target_cwnd <= bdp {
                    self.bbr.state = BBRState::ProbeBW;
                    self.bbr.pacing_gain = 1.0;
                    self.bbr.cycle_index = 0;
                    self.bbr.last_state_change = now;
                    self.bbr.state_duration = Duration::ZERO;
                }
            }
            BBRState::ProbeBW => {
                // Cycle through gain values for bandwidth probing
                if self.bbr.state_duration >= self.bbr.min_rtt {
                    self.bbr_advance_cycle_phase();
                    self.bbr.last_state_change = now;
                    self.bbr.state_duration = Duration::ZERO;
                }
                
                // Periodically probe for min RTT
                if now - self.bbr.min_rtt_timestamp >= Duration::from_secs(10) {
                    self.bbr.state = BBRState::ProbeRTT;
                    self.bbr.last_state_change = now;
                    self.bbr.state_duration = Duration::ZERO;
                    self.bbr.probe_rtt_active = true;
                }
            }
            BBRState::ProbeRTT => {
                // Stay in ProbeRTT for minimum duration
                if self.bbr.state_duration >= self.bbr.probe_rtt_duration {
                    self.bbr.state = BBRState::ProbeBW;
                    self.bbr.pacing_gain = 1.0;
                    self.bbr.last_state_change = now;
                    self.bbr.state_duration = Duration::ZERO;
                    self.bbr.probe_rtt_active = false;
                }
            }
        }
    }
    
    /// Advance BBR cycle phase for ProbeBW
    fn bbr_advance_cycle_phase(&mut self) {
        let gains = [1.25, 0.75, 1.0]; // Up, Down, Cruise
        self.bbr.cycle_index = (self.bbr.cycle_index + 1) % gains.len();
        self.bbr.pacing_gain = gains[self.bbr.cycle_index];
        self.bbr.cycle_phase = match self.bbr.cycle_index {
            0 => BBRCyclePhase::Up,
            1 => BBRCyclePhase::Down,
            _ => BBRCyclePhase::Cruise,
        };
    }
    
    /// Update BBR congestion window
    fn bbr_update_congestion_window(&mut self) {
        if self.bbr.bottleneck_bandwidth > 0 {
            let bdp = self.bbr.bottleneck_bandwidth * (self.bbr.min_rtt.as_millis() as f64 / 1000.0) as u64;
            self.bbr.target_cwnd = (bdp as f64 * self.bbr.cwnd_gain) as u64;
            self.bbr.target_cwnd = self.bbr.target_cwnd.max(self.min_window);
            
            // In ProbeRTT, use minimal window
            if matches!(self.bbr.state, BBRState::ProbeRTT) {
                self.bbr.target_cwnd = self.min_window;
            }
        }
    }

    /// Check if we can send more data (considers congestion window and pacing)
    pub fn can_send(&self, bytes_in_flight: u64) -> bool {
        // First check congestion window
        if bytes_in_flight >= self.congestion_window() {
            return false;
        }
        
        // Then check pacing constraints
        self.pacing_controller.can_send_now()
    }

    /// Get available sending window (considering both congestion window and pacing)
    pub fn sending_window(&self, bytes_in_flight: u64) -> u64 {
        let cwnd_available = self.congestion_window().saturating_sub(bytes_in_flight);
        let pacing_available = self.pacing_controller.available_window();
        
        // Return the minimum of congestion window and pacing constraints
        cwnd_available.min(pacing_available)
    }

    /// Get current congestion window
    pub fn congestion_window(&self) -> u64 {
        match self.algorithm {
            CongestionAlgorithm::NewReno => self.newreno.congestion_window,
            CongestionAlgorithm::BBR => self.bbr.target_cwnd,
            CongestionAlgorithm::BBRv2 => {
                self.bbr_controller
                    .as_ref()
                    .map(|bbr| bbr.congestion_window())
                    .unwrap_or(self.initial_window)
            }
            CongestionAlgorithm::CUBIC => {
                self.cubic_controller
                    .as_ref()
                    .map(|cubic| cubic.congestion_window())
                    .unwrap_or(self.initial_window)
            }
        }
    }

    /// Get current slow start threshold
    pub fn ssthresh(&self) -> u64 {
        match self.algorithm {
            CongestionAlgorithm::NewReno => self.newreno.ssthresh,
            CongestionAlgorithm::BBR => u64::MAX, // BBR doesn't use ssthresh
            CongestionAlgorithm::BBRv2 => u64::MAX, // BBRv2 doesn't use ssthresh
            CongestionAlgorithm::CUBIC => {
                self.cubic_controller
                    .as_ref()
                    .map(|cubic| cubic.stats().ssthresh as u64 * self.max_datagram_size) // Convert packets to bytes
                    .unwrap_or(u64::MAX)
            }
        }
    }

    /// Check if in slow start
    pub fn in_slow_start(&self) -> bool {
        match self.algorithm {
            CongestionAlgorithm::NewReno => matches!(self.newreno.state, CongestionState::SlowStart),
            CongestionAlgorithm::BBR => matches!(self.bbr.state, BBRState::Startup),
            CongestionAlgorithm::BBRv2 => {
                self.bbr_controller
                    .as_ref()
                    .map(|bbr| matches!(bbr.state(), AdvancedBBRState::Startup))
                    .unwrap_or(false)
            }
            CongestionAlgorithm::CUBIC => {
                self.cubic_controller
                    .as_ref()
                    .map(|cubic| matches!(cubic.state(), CubicState::SlowStart))
                    .unwrap_or(false)
            }
        }
    }

    /// Check if in recovery
    pub fn in_recovery(&self) -> bool {
        match self.algorithm {
            CongestionAlgorithm::NewReno => matches!(self.newreno.state, CongestionState::Recovery),
            CongestionAlgorithm::BBR => false, // BBR doesn't have traditional recovery state
            CongestionAlgorithm::BBRv2 => false, // BBRv2 doesn't have traditional recovery state
            CongestionAlgorithm::CUBIC => {
                self.cubic_controller
                    .as_ref()
                    .map(|cubic| matches!(cubic.state(), CubicState::FastRecovery))
                    .unwrap_or(false)
            }
        }
    }
    
    /// Get current congestion control algorithm
    pub fn algorithm(&self) -> CongestionAlgorithm {
        self.algorithm
    }
    
    /// Get BBR sending rate (bytes per second)
    pub fn sending_rate(&self) -> Option<u64> {
        match self.algorithm {
            CongestionAlgorithm::BBR => Some(self.bbr.sending_rate),
            CongestionAlgorithm::NewReno => None,
            CongestionAlgorithm::BBRv2 => self.bbr_controller.as_ref().map(|bbr| bbr.pacing_rate()),
            CongestionAlgorithm::CUBIC => None, // CUBIC doesn't provide explicit sending rate
        }
    }
    
    /// Get estimated bottleneck bandwidth for BBR
    pub fn bottleneck_bandwidth(&self) -> Option<u64> {
        match self.algorithm {
            CongestionAlgorithm::BBR => Some(self.bbr.bottleneck_bandwidth),
            CongestionAlgorithm::NewReno => None,
            CongestionAlgorithm::BBRv2 => self.bbr_controller.as_ref().map(|bbr| bbr.bottleneck_bandwidth()),
            CongestionAlgorithm::CUBIC => None, // CUBIC doesn't track bottleneck bandwidth
        }
    }
    
    /// Get minimum RTT for BBR
    pub fn min_rtt(&self) -> Option<Duration> {
        match self.algorithm {
            CongestionAlgorithm::BBR => Some(self.bbr.min_rtt),
            CongestionAlgorithm::NewReno => Some(self.rtt_tracker.min_rtt()),
            CongestionAlgorithm::BBRv2 => self.bbr_controller.as_ref().map(|bbr| bbr.min_rtt()),
            CongestionAlgorithm::CUBIC => self.cubic_controller.as_ref().map(|cubic| cubic.stats().min_rtt),
        }
    }
    
    /// Get smoothed RTT from RTT tracker
    pub fn smoothed_rtt(&self) -> Duration {
        self.rtt_tracker.smoothed_rtt()
    }
    
    /// Get latest RTT measurement
    pub fn latest_rtt(&self) -> Duration {
        self.rtt_tracker.latest_rtt()
    }
    
    /// Get RTT variance for timeout calculations
    pub fn rtt_var(&self) -> Duration {
        self.rtt_tracker.rtt_var()
    }
    
    /// Get RTT statistics
    pub fn rtt_stats(&self) -> RttStats {
        RttStats {
            smoothed_rtt: self.rtt_tracker.smoothed_rtt(),
            min_rtt: self.rtt_tracker.min_rtt(),
            latest_rtt: self.rtt_tracker.latest_rtt(),
            rtt_var: self.rtt_tracker.rtt_var(),
            sample_count: self.rtt_tracker.sample_count,
        }
    }
    
    /// Handle ECN congestion event
    pub fn on_ecn_congestion_event(&mut self, ecn_event: &EcnCongestionEvent) -> Result<()> {
        // Update ECN controller
        self.ecn_controller.on_congestion_event(ecn_event.clone());
        
        match self.algorithm {
            CongestionAlgorithm::NewReno => {
                // NewReno treats ECN like packet loss
                self.newreno_on_packet_lost(self.max_datagram_size);
                Ok(())
            }
            CongestionAlgorithm::BBR => {
                // BBR can use ECN as early congestion signal
                self.bbr_on_ecn_congestion();
                Ok(())
            }
            CongestionAlgorithm::BBRv2 => {
                if let Some(ref mut bbr) = self.bbr_controller {
                    bbr.on_ecn_congestion(ecn_event, Instant::now())
                } else {
                    Err("BBRv2 controller not initialized".to_http3_error(Http3ErrorCode::InternalError))
                }
            }
            CongestionAlgorithm::CUBIC => {
                if let Some(ref mut cubic) = self.cubic_controller {
                    cubic.on_ecn_congestion(ecn_event, Instant::now())?;
                    Ok(())
                } else {
                    Err("CUBIC controller not initialized".to_http3_error(Http3ErrorCode::InternalError))
                }
            }
        }
    }
    
    /// Get ECN statistics
    pub fn ecn_stats(&self) -> EcnStats {
        self.ecn_controller.stats()
    }
    
    /// Get pacing statistics
    pub fn pacing_stats(&self) -> PacingStats {
        self.pacing_controller.stats()
    }
    
    /// Check if pacing is enabled
    pub fn is_pacing_enabled(&self) -> bool {
        self.pacing_controller.is_enabled()
    }
    
    /// Enable/disable pacing
    pub fn set_pacing_enabled(&mut self, enabled: bool) {
        self.pacing_controller.set_enabled(enabled);
    }

    /// Update controller state (called periodically)
    pub fn update(&mut self) {
        let now = Instant::now();
        
        // Update pacing controller
        self.pacing_controller.update();
        
        // Update ECN controller
        self.ecn_controller.update();
        
        match self.algorithm {
            CongestionAlgorithm::NewReno => {
                // Check if we can exit recovery using Rust 2024 let chains
                if let (CongestionState::Recovery, Some(recovery_start)) = (self.newreno.state, self.newreno.recovery_start_time)
                    && recovery_start.elapsed() > Duration::from_millis(100)
                {
                    self.newreno.state = CongestionState::CongestionAvoidance;
                    self.newreno.recovery_start_time = None;
                }
            }
            CongestionAlgorithm::BBR => {
                // Update BBR state machine
                self.bbr_update_state(now);
                
                // Update sending rate based on current state and pacing gain
                if self.bbr.bottleneck_bandwidth > 0 {
                    self.bbr.sending_rate = (self.bbr.bottleneck_bandwidth as f64 * self.bbr.pacing_gain) as u64;
                    
                    // Update pacing controller with new rate
                    self.pacing_controller.update_pacing_rate(self.bbr.sending_rate);
                }
            }
            CongestionAlgorithm::BBRv2 => {
                // BBRv2 updates are handled internally by the controller
                // Update pacing rate from BBRv2 controller
                if let Some(ref bbr) = self.bbr_controller {
                    let pacing_rate = bbr.pacing_rate();
                    self.pacing_controller.update_pacing_rate(pacing_rate);
                }
            }
            CongestionAlgorithm::CUBIC => {
                // CUBIC updates are handled internally by the controller
                // Update pacing rate if available
                if let Some(ref cubic) = self.cubic_controller {
                    let stats = cubic.stats();
                    // Calculate pacing rate based on cwnd and RTT
                    if stats.min_rtt > Duration::ZERO {
                        let cwnd_bytes = stats.cwnd as u64 * self.max_datagram_size;
                        let pacing_rate = (cwnd_bytes * 1_000_000) / stats.min_rtt.as_micros() as u64;
                        self.pacing_controller.update_pacing_rate(pacing_rate);
                    }
                }
            }
        }
    }

    /// Set maximum datagram size
    pub fn set_max_datagram_size(&mut self, size: u64) {
        let old_size = self.max_datagram_size;
        self.max_datagram_size = size;
        self.min_window = 2 * size;
        
        // Adjust windows proportionally for both algorithms
        if old_size > 0 {
            let scale_factor = size as f64 / old_size as f64;
            
            // Scale NewReno windows
            self.newreno.congestion_window = (self.newreno.congestion_window as f64 * scale_factor) as u64;
            self.newreno.ssthresh = (self.newreno.ssthresh as f64 * scale_factor) as u64;
            
            // Scale BBR windows
            self.bbr.target_cwnd = (self.bbr.target_cwnd as f64 * scale_factor) as u64;
        }
    }

    /// Get congestion controller statistics
    pub fn stats(&self) -> CongestionStats {
        CongestionStats {
            algorithm: self.algorithm,
            congestion_window: self.congestion_window(),
            ssthresh: self.ssthresh(),
            bytes_acked: match self.algorithm {
                CongestionAlgorithm::NewReno => self.newreno.bytes_acked,
                CongestionAlgorithm::BBR => 0, // BBR doesn't track bytes_acked the same way
                CongestionAlgorithm::BBRv2 => 0, // BBRv2 doesn't track bytes_acked the same way
                CongestionAlgorithm::CUBIC => 0, // CUBIC doesn't track bytes_acked the same way
            },
            newreno_state: match self.algorithm {
                CongestionAlgorithm::NewReno => Some(self.newreno.state),
                CongestionAlgorithm::BBR => None,
                CongestionAlgorithm::BBRv2 => None,
                CongestionAlgorithm::CUBIC => None,
            },
            bbr_state: match self.algorithm {
                CongestionAlgorithm::BBR => Some(self.bbr.state),
                CongestionAlgorithm::NewReno => None,
                CongestionAlgorithm::BBRv2 => self.bbr_controller.as_ref().map(|bbr| bbr.state()).map(|state| match state {
                    AdvancedBBRState::Startup => BBRState::Startup,
                    AdvancedBBRState::Drain => BBRState::Drain,
                    AdvancedBBRState::ProbeBW => BBRState::ProbeBW,
                    AdvancedBBRState::ProbeRTT => BBRState::ProbeRTT,
                }),
                CongestionAlgorithm::CUBIC => None,
            },
            in_recovery: self.in_recovery(),
            max_datagram_size: self.max_datagram_size,
            sending_rate: self.sending_rate().unwrap_or(0),
            bottleneck_bandwidth: self.bottleneck_bandwidth(),
            min_rtt: self.min_rtt(),
            ecn_stats: Some(self.ecn_controller.stats()),
        }
    }

    // Pacing-related methods

    /// Check if a packet can be sent immediately
    pub fn can_send_packet(&mut self, packet_size: usize) -> bool {
        let now = Instant::now();
        self.pacing_controller.can_send(packet_size, now)
    }

    /// Get the delay required before sending a packet
    pub fn packet_send_delay(&mut self, packet_size: usize) -> Duration {
        let now = Instant::now();
        self.pacing_controller.send_delay(packet_size, now)
    }

    /// Record that a packet was sent
    pub fn on_packet_sent(&mut self, packet_size: usize) {
        let now = Instant::now();
        self.pacing_controller.on_packet_sent(packet_size, now);
        
        // Update pacing rate based on current congestion control state
        self.update_pacing_rate();
    }

    /// Update pacing rate based on congestion control algorithm
    fn update_pacing_rate(&mut self) {
        let now = Instant::now();
        let pacing_rate = match self.algorithm {
            CongestionAlgorithm::NewReno => {
                // For NewReno, base pacing on congestion window and RTT
                // Estimate: rate = cwnd / RTT
                let cwnd = self.newreno.congestion_window;
                let estimated_rtt = Duration::from_millis(100); // Conservative estimate
                if estimated_rtt > Duration::ZERO {
                    (cwnd * 1000) / estimated_rtt.as_millis() as u64
                } else {
                    1_000_000 // 1 MB/s fallback
                }
            }
            CongestionAlgorithm::BBR => {
                // BBR has explicit sending rate
                self.bbr.sending_rate
            }
            CongestionAlgorithm::BBRv2 => {
                // BBRv2 controller provides pacing rate
                self.bbr_controller
                    .as_ref()
                    .map(|bbr| bbr.pacing_rate())
                    .unwrap_or(1_000_000)
            }
            CongestionAlgorithm::CUBIC => {
                // CUBIC: estimate based on congestion window and RTT
                if let Some(cubic) = &self.cubic_controller {
                    let cwnd = cubic.congestion_window();
                    let rtt = cubic.stats().srtt;
                    if rtt > Duration::ZERO {
                        (cwnd * 1000) / rtt.as_millis() as u64
                    } else {
                        1_000_000 // 1 MB/s fallback
                    }
                } else {
                    1_000_000
                }
            }
        };

        self.pacing_controller.update_pacing_rate(pacing_rate);
    }

    /// Update RTT for pacing calculations
    pub fn update_pacing_rtt(&mut self, rtt: Duration) {
        self.pacing_controller.update_rtt(rtt);
        // Also trigger pacing rate update since RTT affects rate calculation
        self.update_pacing_rate();
    }

    /// Handle congestion event for pacing
    pub fn on_pacing_congestion_event(&mut self) {
        let now = Instant::now();
        self.pacing_controller.on_congestion_event(now);
    }

    /// Signal that application is limiting sends
    pub fn set_pacing_app_limited(&mut self) {
        let now = Instant::now();
        self.pacing_controller.set_app_limited(now);
    }

}

impl Default for CongestionController {
    fn default() -> Self {
        Self::new()
    }
}

/// Congestion control statistics
#[derive(Debug, Clone)]
pub struct CongestionStats {
    /// Current congestion control algorithm
    pub algorithm: CongestionAlgorithm,
    /// Current congestion window size in bytes
    pub congestion_window: u64,
    /// Slow start threshold (NewReno only)
    pub ssthresh: u64,
    /// Total bytes acknowledged (NewReno only)
    pub bytes_acked: u64,
    /// Current NewReno state (if using NewReno)
    pub newreno_state: Option<CongestionState>,
    /// Current BBR state (if using BBR)
    pub bbr_state: Option<BBRState>,
    /// Whether currently in recovery
    pub in_recovery: bool,
    /// Maximum datagram size
    pub max_datagram_size: u64,
    /// Current sending rate (BBR only)
    pub sending_rate: u64,
    /// Estimated bottleneck bandwidth (BBR only)
    pub bottleneck_bandwidth: Option<u64>,
    /// Minimum RTT observed (BBR only)
    pub min_rtt: Option<Duration>,
    /// ECN statistics
    pub ecn_stats: Option<EcnStats>,
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_congestion_window() {
        let controller = CongestionController::new();
        let window = controller.congestion_window();
        assert!(window >= 2 * 1200); // At least 2 packets
        assert!(window <= 10 * 1200); // At most 10 packets for default MTU
    }

    #[test]
    fn test_congestion_algorithm_selection() {
        let newreno = CongestionController::with_algorithm(CongestionAlgorithm::NewReno);
        assert_eq!(newreno.algorithm(), CongestionAlgorithm::NewReno);

        let bbr = CongestionController::with_algorithm(CongestionAlgorithm::BBR);
        assert_eq!(bbr.algorithm(), CongestionAlgorithm::BBR);

        let cubic = CongestionController::with_algorithm(CongestionAlgorithm::CUBIC);
        assert_eq!(cubic.algorithm(), CongestionAlgorithm::CUBIC);
    }

    #[test]
    fn test_newreno_slow_start() {
        let mut controller = CongestionController::with_algorithm(CongestionAlgorithm::NewReno);
        let initial_cwnd = controller.congestion_window();
        
        // Acknowledge some packets (should increase window in slow start)
        let _ = controller.on_ack_received_with_rtt(&[(1, 10)], Duration::from_millis(50));
        
        // In slow start, window should increase
        assert!(controller.congestion_window() >= initial_cwnd);
    }

    #[test]
    fn test_newreno_loss_recovery() {
        let mut controller = CongestionController::with_algorithm(CongestionAlgorithm::NewReno);
        let initial_cwnd = controller.congestion_window();
        
        // Simulate packet loss
        let _ = controller.on_packet_lost(1200);
        
        // Window should decrease and enter recovery
        assert!(controller.congestion_window() < initial_cwnd);
        assert!(controller.in_recovery());
    }

    #[test]
    fn test_bbr_initialization() {
        let controller = CongestionController::with_algorithm(CongestionAlgorithm::BBR);
        let stats = controller.stats();
        
        assert_eq!(stats.algorithm, CongestionAlgorithm::BBR);
        assert!(stats.congestion_window > 0);
    }

    #[test]
    fn test_cubic_initialization() {
        let controller = CongestionController::with_algorithm(CongestionAlgorithm::CUBIC);
        let stats = controller.stats();
        
        assert_eq!(stats.algorithm, CongestionAlgorithm::CUBIC);
        assert!(stats.congestion_window > 0);
    }

    #[test]
    fn test_pacing_integration() {
        let mut controller = CongestionController::new();
        
        // Test basic pacing functionality
        assert!(controller.can_send_packet(1200)); // Should be able to send initially
        
        let delay = controller.packet_send_delay(1200);
        // Delay should be reasonable (could be zero for initial burst)
        assert!(delay <= Duration::from_millis(100));
        
        // Record packet send
        controller.on_packet_sent(1200);
        
        // Should have valid pacing rate
        assert!(controller.pacing_rate() > 0);
    }

    #[test]
    fn test_pacing_rate_updates() {
        let mut controller = CongestionController::new();
        let initial_rate = controller.pacing_rate();
        
        // Update RTT which should affect pacing rate
        controller.update_pacing_rtt(Duration::from_millis(50));
        
        // Rate should be updated
        let new_rate = controller.pacing_rate();
        assert!(new_rate > 0);
        // Rate might change based on RTT update
    }

    #[test]
    fn test_bbrv2_stats() {
        let controller = CongestionController::with_algorithm(CongestionAlgorithm::BBRv2);
        let stats = controller.stats();
        
        assert_eq!(stats.algorithm, CongestionAlgorithm::BBRv2);
        assert!(stats.congestion_window > 0);
        assert!(!stats.in_recovery); // BBR doesn't have traditional recovery
    }
}

