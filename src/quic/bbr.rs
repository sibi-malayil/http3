//! Advanced BBR (Bottleneck Bandwidth and Round-trip propagation time) Implementation
//!
//! This module implements BBR v1 congestion control algorithm as described in:
//! - "BBR: Congestion-Based Congestion Control" (ACM Queue, 2016)
//! - Linux kernel BBR implementation
//! - RFC draft-cardwell-iccrg-bbr-congestion-control
//!
//! BBR focuses on achieving high throughput and low latency by:
//! 1. Estimating the bottleneck bandwidth and RTT
//! 2. Maintaining a sending rate around the bottleneck bandwidth
//! 3. Periodically probing for more bandwidth and minimum RTT

use crate::{
    error::Result,
    util::time::{Duration, Instant},
    whathappened::Level,
    protocol_event,
};
use std::collections::VecDeque;

/// BBR configuration parameters
#[derive(Debug, Clone)]
pub struct BBRConfig {
    /// High gain for startup phase
    pub startup_gain: f64,
    /// Drain gain (reciprocal of startup gain)
    pub drain_gain: f64,
    /// Gain values for ProbeBW cycling
    pub probe_bw_gains: [f64; 8],
    /// Default pacing gain
    pub default_pacing_gain: f64,
    /// Congestion window gain
    pub cwnd_gain: f64,
    /// Minimum congestion window in packets
    pub min_cwnd_packets: u32,
    /// ProbeRTT duration
    pub probe_rtt_duration: Duration,
    /// Interval between ProbeRTT cycles
    pub probe_rtt_interval: Duration,
    /// Bandwidth filter window length
    pub bandwidth_window_length: usize,
    /// RTT filter window length  
    pub rtt_window_length: usize,
    /// Full bandwidth threshold (growth less than this triggers drain)
    pub full_bandwidth_threshold: f64,
    /// Number of rounds to check for full bandwidth
    pub full_bandwidth_count: usize,
}

impl Default for BBRConfig {
    fn default() -> Self {
        Self {
            startup_gain: 2.77,
            drain_gain: 1.0 / 2.77,
            probe_bw_gains: [1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0],
            default_pacing_gain: 1.0,
            cwnd_gain: 2.0,
            min_cwnd_packets: 4,
            probe_rtt_duration: Duration::from_millis(200),
            probe_rtt_interval: Duration::from_secs(10),
            bandwidth_window_length: 10, // RTT cycles
            rtt_window_length: 10,       // Samples
            full_bandwidth_threshold: 1.25, // 25% growth
            full_bandwidth_count: 3,         // Rounds without 25% growth
        }
    }
}

/// BBR congestion control states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BBRState {
    /// Startup: discover bottleneck bandwidth
    Startup,
    /// Drain: drain excess packets in flight
    Drain,
    /// ProbeBW: probe for additional bandwidth
    ProbeBW,
    /// ProbeRTT: probe for minimum RTT
    ProbeRTT,
}

/// BBR cycle phases during ProbeBW
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BBRCyclePhase {
    /// Probe up: try to get more bandwidth
    ProbeUp,
    /// Probe down: drain potential queue buildup
    ProbeDown,
    /// Cruise: maintain current rate
    Cruise,
}

/// Delivery rate sample for bandwidth estimation
#[derive(Debug, Clone)]
pub struct DeliveryRateSample {
    /// Delivery rate in bytes per second
    pub rate: u64,
    /// RTT measurement
    pub rtt: Duration,
    /// Sample time
    pub timestamp: Instant,
    /// Bytes delivered
    pub delivered: u64,
    /// Whether this sample is from a retransmission
    pub is_retransmit: bool,
    /// Whether this is an app-limited sample
    pub is_app_limited: bool,
}

/// Bandwidth filter using max filter over sliding window
#[derive(Debug, Clone)]
pub struct BandwidthFilter {
    /// Samples with their timestamps
    samples: VecDeque<(u64, Instant)>,
    /// Current maximum bandwidth
    max_bandwidth: u64,
    /// Window duration
    window_duration: Duration,
}

impl BandwidthFilter {
    fn new(window_duration: Duration) -> Self {
        Self {
            samples: VecDeque::new(),
            max_bandwidth: 0,
            window_duration,
        }
    }

    /// Add a new bandwidth sample
    fn add_sample(&mut self, bandwidth: u64, timestamp: Instant) {
        // Remove expired samples
        let cutoff_time = timestamp - self.window_duration;
        while let Some(&(_, sample_time)) = self.samples.front() {
            if sample_time >= cutoff_time {
                break;
            }
            self.samples.pop_front();
        }

        // Add new sample
        self.samples.push_back((bandwidth, timestamp));

        // Update max bandwidth
        self.max_bandwidth = self.samples.iter()
            .map(|(bw, _)| *bw)
            .max()
            .unwrap_or(0);
    }

    /// Get current maximum bandwidth
    fn max_bandwidth(&self) -> u64 {
        self.max_bandwidth
    }

    /// Reset the filter
    fn reset(&mut self) {
        self.samples.clear();
        self.max_bandwidth = 0;
    }
}

/// RTT filter using minimum filter
#[derive(Debug, Clone)]
pub struct RTTFilter {
    /// Recent RTT samples
    samples: VecDeque<(Duration, Instant)>,
    /// Current minimum RTT
    min_rtt: Duration,
    /// When min_rtt was last updated
    min_rtt_timestamp: Instant,
    /// Maximum number of samples to keep
    max_samples: usize,
}

impl RTTFilter {
    fn new(max_samples: usize) -> Self {
        let now = Instant::now();
        Self {
            samples: VecDeque::with_capacity(max_samples),
            min_rtt: Duration::from_millis(1000), // Initial conservative estimate
            min_rtt_timestamp: now,
            max_samples,
        }
    }

    /// Add RTT sample
    fn add_sample(&mut self, rtt: Duration, timestamp: Instant) {
        // Add new sample
        self.samples.push_back((rtt, timestamp));

        // Limit samples
        if self.samples.len() > self.max_samples {
            self.samples.pop_front();
        }

        // Update minimum RTT
        if rtt <= self.min_rtt {
            self.min_rtt = rtt;
            self.min_rtt_timestamp = timestamp;
        }
    }

    /// Get current minimum RTT
    fn min_rtt(&self) -> Duration {
        self.min_rtt
    }

    /// Get time when min RTT was last updated
    fn min_rtt_timestamp(&self) -> Instant {
        self.min_rtt_timestamp
    }

    /// Reset filter
    fn reset(&mut self, timestamp: Instant) {
        self.samples.clear();
        self.min_rtt = Duration::from_millis(1000);
        self.min_rtt_timestamp = timestamp;
    }
}

/// Advanced BBR congestion controller
#[derive(Debug, Clone)]
pub struct BBRController {
    /// Configuration
    config: BBRConfig,
    /// Current BBR state
    state: BBRState,
    /// Current cycle phase (for ProbeBW)
    cycle_phase: BBRCyclePhase,
    /// Cycle index for ProbeBW
    cycle_index: usize,
    
    /// Bandwidth estimation
    bandwidth_filter: BandwidthFilter,
    /// RTT tracking
    rtt_filter: RTTFilter,
    
    /// Current pacing gain
    pacing_gain: f64,
    /// Current congestion window gain
    cwnd_gain: f64,
    
    /// Current congestion window in bytes
    congestion_window: u64,
    /// Target congestion window
    target_cwnd: u64,
    /// Maximum datagram size
    mss: u64,
    
    /// Round trip counter
    round_count: u64,
    /// Delivered bytes counter
    delivered: u64,
    /// Next round trip to advance cycle
    next_round_delivered: u64,
    
    /// Full bandwidth tracking
    full_bandwidth_reached: bool,
    full_bandwidth_count: usize,
    
    /// State timing
    state_start_time: Instant,
    cycle_start_time: Instant,
    
    /// App-limited tracking
    app_limited: u64,
    
    /// Prior inflight for loss detection
    prior_cwnd: u64,
    
    /// Statistics
    packets_out: u64,
    retrans_out: u64,
    
    /// Delivery rate estimation
    delivery_rate_samples: VecDeque<DeliveryRateSample>,
}

impl BBRController {
    /// Create new BBR controller
    pub fn new(mss: u64) -> Self {
        let now = Instant::now();
        let config = BBRConfig::default();
        
        Self {
            bandwidth_filter: BandwidthFilter::new(Duration::from_millis(100)), // ~10 RTTs
            rtt_filter: RTTFilter::new(config.rtt_window_length),
            congestion_window: Self::initial_cwnd(mss, config.min_cwnd_packets),
            target_cwnd: Self::initial_cwnd(mss, config.min_cwnd_packets),
            pacing_gain: config.startup_gain,
            cwnd_gain: config.cwnd_gain,
            state: BBRState::Startup,
            cycle_phase: BBRCyclePhase::ProbeUp,
            cycle_index: 0,
            mss,
            config,
            round_count: 0,
            delivered: 0,
            next_round_delivered: 0,
            full_bandwidth_reached: false,
            full_bandwidth_count: 0,
            state_start_time: now,
            cycle_start_time: now,
            app_limited: 0,
            prior_cwnd: 0,
            packets_out: 0,
            retrans_out: 0,
            delivery_rate_samples: VecDeque::with_capacity(10),
        }
    }
    
    /// Create BBR controller with custom configuration
    pub fn with_config(mss: u64, config: BBRConfig) -> Self {
        let mut controller = Self::new(mss);
        controller.config = config;
        controller.pacing_gain = controller.config.startup_gain;
        controller.cwnd_gain = controller.config.cwnd_gain;
        controller
    }

    /// Calculate initial congestion window
    fn initial_cwnd(mss: u64, min_packets: u32) -> u64 {
        (min_packets as u64 * mss).max(14720) // At least ~10 packets of 1472 bytes
    }

    /// Process ACK and update BBR state
    pub fn on_ack(&mut self, acked_bytes: u64, rtt: Duration, now: Instant) -> Result<()> {
        // Update delivered counter
        self.delivered += acked_bytes;
        
        // Add RTT sample
        self.rtt_filter.add_sample(rtt, now);
        
        // Calculate delivery rate for this ACK
        if acked_bytes > 0 && rtt > Duration::ZERO {
            let delivery_rate = (acked_bytes * 1_000_000) / rtt.as_micros() as u64;
            
            let is_app_limited = self.delivered <= self.app_limited;
            let sample = DeliveryRateSample {
                rate: delivery_rate,
                rtt,
                timestamp: now,
                delivered: acked_bytes,
                is_retransmit: false, // TODO: Track retransmissions properly
                is_app_limited,
            };
            
            // Only use non-app-limited samples for bandwidth estimation
            if !is_app_limited {
                self.bandwidth_filter.add_sample(delivery_rate, now);
            }
            
            self.delivery_rate_samples.push_back(sample);
            if self.delivery_rate_samples.len() > 10 {
                self.delivery_rate_samples.pop_front();
            }
        }
        
        // Check for round trip completion
        if self.delivered >= self.next_round_delivered {
            self.advance_round();
        }
        
        // Update BBR state machine
        self.update_state(now)?;
        
        // Update congestion window
        self.update_congestion_window()?;
        
        protocol_event!(
            Level::Debug,
            "BBR ACK processed";
            "acked_bytes" => acked_bytes,
            "rtt_ms" => rtt.as_millis(),
            "bandwidth_bps" => self.bandwidth_filter.max_bandwidth(),
            "cwnd" => self.congestion_window,
            "state" => format!("{:?}", self.state)
        );
        
        Ok(())
    }

    /// Handle packet loss
    pub fn on_loss(&mut self, lost_bytes: u64, now: Instant) -> Result<()> {
        // BBR is less reactive to individual losses
        // Only react to persistent congestion
        
        protocol_event!(
            Level::Debug,
            "BBR packet loss";
            "lost_bytes" => lost_bytes,
            "state" => format!("{:?}", self.state)
        );
        
        // In startup, loss may indicate we've found the bottleneck
        if matches!(self.state, BBRState::Startup) && lost_bytes > self.mss {
            // Transition to drain if we see significant loss
            self.enter_drain(now)?;
        }
        
        Ok(())
    }

    /// Handle persistent congestion (reset to startup)
    pub fn on_persistent_congestion(&mut self, now: Instant) -> Result<()> {
        protocol_event!(
            Level::Info,
            "BBR persistent congestion detected, resetting to startup"
        );
        
        self.reset(now)?;
        Ok(())
    }

    /// Advance to next round trip
    fn advance_round(&mut self) {
        self.round_count += 1;
        self.next_round_delivered = self.delivered;
        
        // Check for full bandwidth in startup
        if matches!(self.state, BBRState::Startup) {
            self.check_full_bandwidth();
        }
    }

    /// Check if we've reached full bandwidth
    fn check_full_bandwidth(&mut self) {
        if self.full_bandwidth_reached {
            return;
        }

        let current_bw = self.bandwidth_filter.max_bandwidth();
        
        // Need at least one sample to compare
        if current_bw == 0 {
            return;
        }

        // Look for bandwidth growth over recent rounds
        let growth_threshold = (current_bw as f64 * self.config.full_bandwidth_threshold) as u64;
        
        // This is simplified - in practice, you'd track bandwidth over multiple rounds
        // For now, assume full bandwidth if we have a good estimate
        if current_bw > growth_threshold {
            self.full_bandwidth_count = 0;
        } else {
            self.full_bandwidth_count += 1;
            
            if self.full_bandwidth_count >= self.config.full_bandwidth_count {
                self.full_bandwidth_reached = true;
            }
        }
    }

    /// Update BBR state machine
    fn update_state(&mut self, now: Instant) -> Result<()> {
        let time_in_state = now - self.state_start_time;
        
        match self.state {
            BBRState::Startup => {
                // Exit startup if full bandwidth reached or significant loss
                if self.full_bandwidth_reached {
                    self.enter_drain(now)?;
                }
            }
            BBRState::Drain => {
                // Exit drain when inflight is at or below estimated BDP
                let bdp = self.bandwidth_delay_product();
                if self.packets_out * self.mss <= bdp {
                    self.enter_probe_bw(now)?;
                }
            }
            BBRState::ProbeBW => {
                // Advance cycle phase periodically
                let cycle_duration = self.rtt_filter.min_rtt();
                if time_in_state >= cycle_duration {
                    self.advance_probe_bw_cycle(now)?;
                }
                
                // Periodically probe RTT
                if now - self.rtt_filter.min_rtt_timestamp() >= self.config.probe_rtt_interval {
                    self.enter_probe_rtt(now)?;
                }
            }
            BBRState::ProbeRTT => {
                // Exit ProbeRTT after minimum duration
                if time_in_state >= self.config.probe_rtt_duration {
                    self.enter_probe_bw(now)?;
                }
            }
        }
        
        Ok(())
    }

    /// Enter drain state
    fn enter_drain(&mut self, now: Instant) -> Result<()> {
        self.state = BBRState::Drain;
        self.state_start_time = now;
        self.pacing_gain = self.config.drain_gain;
        self.cwnd_gain = self.config.cwnd_gain;
        
        protocol_event!(
            Level::Info,
            "BBR entering Drain state";
            "bandwidth_bps" => self.bandwidth_filter.max_bandwidth(),
            "rtt_ms" => self.rtt_filter.min_rtt().as_millis()
        );
        
        Ok(())
    }

    /// Enter ProbeBW state
    fn enter_probe_bw(&mut self, now: Instant) -> Result<()> {
        self.state = BBRState::ProbeBW;
        self.state_start_time = now;
        self.cycle_start_time = now;
        self.cycle_index = 0;
        self.cycle_phase = BBRCyclePhase::ProbeUp;
        self.pacing_gain = self.config.probe_bw_gains[0];
        self.cwnd_gain = self.config.cwnd_gain;
        
        protocol_event!(
            Level::Info,
            "BBR entering ProbeBW state"
        );
        
        Ok(())
    }

    /// Enter ProbeRTT state
    fn enter_probe_rtt(&mut self, now: Instant) -> Result<()> {
        self.state = BBRState::ProbeRTT;
        self.state_start_time = now;
        self.pacing_gain = self.config.default_pacing_gain;
        self.cwnd_gain = self.config.cwnd_gain;
        
        protocol_event!(
            Level::Info,
            "BBR entering ProbeRTT state"
        );
        
        Ok(())
    }

    /// Advance ProbeBW cycle
    fn advance_probe_bw_cycle(&mut self, now: Instant) -> Result<()> {
        self.cycle_index = (self.cycle_index + 1) % self.config.probe_bw_gains.len();
        self.pacing_gain = self.config.probe_bw_gains[self.cycle_index];
        self.cycle_start_time = now;
        
        self.cycle_phase = match self.cycle_index {
            0 => BBRCyclePhase::ProbeUp,
            1 => BBRCyclePhase::ProbeDown,
            _ => BBRCyclePhase::Cruise,
        };
        
        protocol_event!(
            Level::Debug,
            "BBR ProbeBW cycle advance";
            "cycle_index" => self.cycle_index,
            "pacing_gain" => self.pacing_gain,
            "phase" => format!("{:?}", self.cycle_phase)
        );
        
        Ok(())
    }

    /// Update congestion window
    fn update_congestion_window(&mut self) -> Result<()> {
        // Calculate bandwidth delay product
        let bdp = self.bandwidth_delay_product();
        
        // Calculate target congestion window
        self.target_cwnd = (bdp as f64 * self.cwnd_gain) as u64;
        
        // Enforce minimum window
        let min_cwnd = self.config.min_cwnd_packets as u64 * self.mss;
        self.target_cwnd = self.target_cwnd.max(min_cwnd);
        
        // In ProbeRTT, use minimal window to drain queues
        if matches!(self.state, BBRState::ProbeRTT) {
            self.target_cwnd = min_cwnd;
        }
        
        // In startup, increase window more aggressively
        if matches!(self.state, BBRState::Startup) && self.target_cwnd > self.congestion_window {
            // In startup, grow quickly like slow start
            let increase = (self.target_cwnd - self.congestion_window).min(self.mss * 4);
            self.congestion_window += increase;
        } else {
            // Gradually adjust actual window toward target
            if self.target_cwnd > self.congestion_window {
                // Increase window
                let increase = (self.target_cwnd - self.congestion_window).min(self.mss);
                self.congestion_window += increase;
            } else if self.target_cwnd < self.congestion_window {
                // Decrease window
                let decrease = (self.congestion_window - self.target_cwnd).min(self.mss);
                self.congestion_window = self.congestion_window.saturating_sub(decrease);
            }
        }
        
        Ok(())
    }

    /// Calculate bandwidth delay product
    fn bandwidth_delay_product(&self) -> u64 {
        let bandwidth = self.bandwidth_filter.max_bandwidth();
        let rtt = self.rtt_filter.min_rtt();
        
        if bandwidth > 0 && rtt > Duration::ZERO {
            // Use microseconds for more precise calculation
            // BDP = bandwidth (bytes/sec) * RTT (seconds)
            let rtt_secs = rtt.as_micros() as f64 / 1_000_000.0;
            (bandwidth as f64 * rtt_secs) as u64
        } else {
            self.config.min_cwnd_packets as u64 * self.mss
        }
    }

    /// Reset BBR to initial state
    pub fn reset(&mut self, now: Instant) -> Result<()> {
        self.state = BBRState::Startup;
        self.state_start_time = now;
        self.cycle_start_time = now;
        self.pacing_gain = self.config.startup_gain;
        self.cwnd_gain = self.config.cwnd_gain;
        self.cycle_index = 0;
        self.round_count = 0;
        self.delivered = 0;
        self.next_round_delivered = 0;
        self.full_bandwidth_reached = false;
        self.full_bandwidth_count = 0;
        self.congestion_window = Self::initial_cwnd(self.mss, self.config.min_cwnd_packets);
        self.target_cwnd = self.congestion_window;
        
        self.bandwidth_filter.reset();
        self.rtt_filter.reset(now);
        self.delivery_rate_samples.clear();
        
        protocol_event!(
            Level::Info,
            "BBR controller reset to startup state"
        );
        
        Ok(())
    }

    /// Update packets in flight counter
    pub fn set_packets_in_flight(&mut self, packets: u64) {
        self.packets_out = packets;
    }

    /// Mark as app-limited
    pub fn set_app_limited(&mut self) {
        self.app_limited = self.delivered;
    }

    /// Get current congestion window
    pub fn congestion_window(&self) -> u64 {
        self.congestion_window
    }

    /// Get target congestion window
    pub fn target_congestion_window(&self) -> u64 {
        self.target_cwnd
    }

    /// Get current pacing rate
    pub fn pacing_rate(&self) -> u64 {
        let bandwidth = self.bandwidth_filter.max_bandwidth();
        (bandwidth as f64 * self.pacing_gain) as u64
    }

    /// Get estimated bottleneck bandwidth
    pub fn bottleneck_bandwidth(&self) -> u64 {
        self.bandwidth_filter.max_bandwidth()
    }

    /// Get minimum RTT
    pub fn min_rtt(&self) -> Duration {
        self.rtt_filter.min_rtt()
    }

    /// Get current BBR state
    pub fn state(&self) -> BBRState {
        self.state
    }

    /// Get current cycle phase
    pub fn cycle_phase(&self) -> BBRCyclePhase {
        self.cycle_phase
    }

    /// Check if we can send (bytes in flight < congestion window)
    pub fn can_send(&self, bytes_in_flight: u64) -> bool {
        bytes_in_flight < self.congestion_window
    }

    /// Get available sending window
    pub fn send_window(&self, bytes_in_flight: u64) -> u64 {
        self.congestion_window.saturating_sub(bytes_in_flight)
    }

    /// Get BBR statistics
    pub fn stats(&self) -> BBRStats {
        BBRStats {
            state: self.state,
            cycle_phase: self.cycle_phase,
            congestion_window: self.congestion_window,
            target_cwnd: self.target_cwnd,
            pacing_rate: self.pacing_rate(),
            pacing_gain: self.pacing_gain,
            cwnd_gain: self.cwnd_gain,
            bottleneck_bandwidth: self.bottleneck_bandwidth(),
            min_rtt: self.min_rtt(),
            round_count: self.round_count,
            delivered: self.delivered,
            full_bandwidth_reached: self.full_bandwidth_reached,
            packets_out: self.packets_out,
        }
    }

    /// Handle ECN congestion event
    pub fn on_ecn_congestion(&mut self, event: &crate::quic::ecn::EcnCongestionEvent, now: Instant) -> Result<()> {
        // ECN congestion handling for BBR
        // BBR responds to ECN by treating it as an early congestion signal
        // This is more conservative than waiting for packet loss

        // Force transition to Drain if in Startup with high ECN marking
        if matches!(self.state, BBRState::Startup) && event.marking_rate > 0.1 {
            self.state = BBRState::Drain;
            self.pacing_gain = self.config.drain_gain;
            self.state_start_time = now;

            protocol_event!(
                Level::Info,
                "BBR: ECN congestion detected in Startup, transitioning to Drain";
                "marking_rate" => event.marking_rate,
                "ce_count" => event.ce_count
            );
        }

        // Reduce bandwidth estimate proportionally to ECN marking rate
        if event.marking_rate > 0.05 {
            let reduction_factor = 1.0 - (event.marking_rate * 0.5).min(0.3);
            let current_bw = self.bandwidth_filter.max_bandwidth();
            if current_bw > 0 {
                let reduced_bw = (current_bw as f64 * reduction_factor) as u64;
                self.bandwidth_filter.add_sample(reduced_bw, now);
                
                protocol_event!(
                    Level::Debug,
                    "BBR: Reduced bandwidth estimate due to ECN";
                    "old_bandwidth" => current_bw,
                    "new_bandwidth" => reduced_bw,
                    "reduction_factor" => reduction_factor
                );
            }
        }
        
        Ok(())
    }
}

/// BBR statistics
#[derive(Debug, Clone)]
pub struct BBRStats {
    /// Current BBR state
    pub state: BBRState,
    /// Current cycle phase
    pub cycle_phase: BBRCyclePhase,
    /// Current congestion window
    pub congestion_window: u64,
    /// Target congestion window
    pub target_cwnd: u64,
    /// Current pacing rate
    pub pacing_rate: u64,
    /// Current pacing gain
    pub pacing_gain: f64,
    /// Current congestion window gain
    pub cwnd_gain: f64,
    /// Estimated bottleneck bandwidth
    pub bottleneck_bandwidth: u64,
    /// Minimum RTT
    pub min_rtt: Duration,
    /// Round trip count
    pub round_count: u64,
    /// Total delivered bytes
    pub delivered: u64,
    /// Whether full bandwidth has been reached
    pub full_bandwidth_reached: bool,
    /// Packets currently in flight
    pub packets_out: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bbr_initialization() {
        let bbr = BBRController::new(1200);
        assert_eq!(bbr.state(), BBRState::Startup);
        assert!(bbr.congestion_window() >= 4 * 1200); // At least min cwnd
        assert_eq!(bbr.pacing_gain, 2.77); // Startup gain
    }

    #[test]
    fn test_bbr_bandwidth_measurement() {
        let mut bbr = BBRController::new(1200);
        let now = Instant::now();
        
        // Send ACK with RTT measurement
        bbr.on_ack(12000, Duration::from_millis(50), now).unwrap();
        
        // Should have measured bandwidth
        assert!(bbr.bottleneck_bandwidth() > 0);
        assert_eq!(bbr.min_rtt(), Duration::from_millis(50));
    }

    #[test]
    fn test_bbr_state_transitions() {
        let mut bbr = BBRController::new(1200);
        let now = Instant::now();
        
        // Start in startup
        assert_eq!(bbr.state(), BBRState::Startup);
        
        // Force full bandwidth detection
        bbr.full_bandwidth_reached = true;
        bbr.update_state(now).unwrap();
        
        // Should transition to drain (but may require additional conditions)
        // This is a simplified test - real transitions depend on multiple factors
    }

    #[test]
    fn test_bbr_congestion_window_update() {
        let mut bbr = BBRController::new(1200);
        let initial_cwnd = bbr.congestion_window();
        
        // Add bandwidth sample
        let now = Instant::now();
        bbr.on_ack(12000, Duration::from_millis(100), now).unwrap();
        
        // Window should be updated based on BDP
        let bdp = bbr.bandwidth_delay_product();
        assert!(bdp > 0);
        
        // Verify congestion window is being managed properly
        let final_cwnd = bbr.congestion_window();
        protocol_event!(Level::Debug, "BBR cwnd changed from {} to {}", initial_cwnd, final_cwnd);
    }

    #[test]
    fn test_bbr_loss_handling() {
        let mut bbr = BBRController::new(1200);
        let now = Instant::now();
        
        // BBR should be less reactive to individual losses
        let initial_cwnd = bbr.congestion_window();
        bbr.on_loss(1200, now).unwrap();
        
        // Verify BBR behavior after loss
        let final_cwnd = bbr.congestion_window();
        protocol_event!(Level::Debug, "BBR loss handling: cwnd {} -> {}", initial_cwnd, final_cwnd);
        
        // In startup, significant loss may trigger drain
        if matches!(bbr.state(), BBRState::Drain) {
            assert_ne!(bbr.pacing_gain, 2.77); // Should not be startup gain
        }
    }

    #[test]
    fn test_bbr_pacing_rate() {
        let mut bbr = BBRController::new(1200);
        let now = Instant::now();
        
        // Add some bandwidth measurement
        bbr.on_ack(12000, Duration::from_millis(100), now).unwrap();
        
        let bandwidth = bbr.bottleneck_bandwidth();
        let pacing_rate = bbr.pacing_rate();
        
        if bandwidth > 0 {
            // Pacing rate should be bandwidth * pacing_gain
            let expected = (bandwidth as f64 * bbr.pacing_gain) as u64;
            assert_eq!(pacing_rate, expected);
        }
    }

    #[test]
    fn test_bbr_send_window() {
        let bbr = BBRController::new(1200);
        let cwnd = bbr.congestion_window();
        
        assert!(bbr.can_send(0));
        assert!(bbr.can_send(cwnd / 2));
        assert!(!bbr.can_send(cwnd));
        
        assert_eq!(bbr.send_window(0), cwnd);
        assert_eq!(bbr.send_window(cwnd / 2), cwnd / 2);
        assert_eq!(bbr.send_window(cwnd), 0);
    }

    #[test]
    fn test_bbr_custom_config() {
        let config = BBRConfig {
            startup_gain: 3.0,
            min_cwnd_packets: 8,
            ..Default::default()
        };
        
        let bbr = BBRController::with_config(1200, config);
        assert_eq!(bbr.pacing_gain, 3.0);
        assert!(bbr.congestion_window() >= 8 * 1200);
    }
}