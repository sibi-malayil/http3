//! CUBIC Congestion Control Algorithm Implementation
//!
//! This module implements the CUBIC congestion control algorithm as described in:
//! - RFC 8312: "CUBIC for Fast Long-Distance Networks"
//! - "CUBIC: A New TCP-Friendly High-Speed TCP Variant" (Computer Networks, 2008)
//!
//! CUBIC is designed to be more scalable and efficient than traditional TCP congestion
//! control algorithms, especially in high-bandwidth, high-latency networks.

use crate::{
    util::time::{Duration, Instant},
    error::Result,
    whathappened::Level,
    protocol_event,
};
use std::cmp::{max, min};

/// CUBIC configuration parameters
#[derive(Debug, Clone)]
pub struct CubicConfig {
    /// CUBIC scaling constant C
    pub cubic_c: f64,
    /// TCP-friendly mode scaling factor
    pub tcp_friendliness: bool,
    /// Beta - multiplicative decrease factor for fast convergence
    pub beta: f64,
    /// Alpha - additive increase factor for fast convergence
    pub alpha: f64,
    /// Fast convergence enabled
    pub fast_convergence: bool,
    /// HyStart enabled (Hybrid Slow Start)
    pub hystart_enabled: bool,
    /// HyStart ACK train threshold
    pub hystart_ack_train: Duration,
    /// HyStart delay increase threshold
    pub hystart_delay_min: Duration,
    /// HyStart round counter threshold
    pub hystart_round_thresh: u32,
    /// Minimum congestion window
    pub min_cwnd: u32,
    /// Initial slow start threshold
    pub initial_ssthresh: u32,
}

impl Default for CubicConfig {
    fn default() -> Self {
        Self {
            cubic_c: 0.4,  // Standard CUBIC constant
            tcp_friendliness: true,
            beta: 0.7,     // CUBIC uses beta = 0.7 instead of 0.5
            alpha: 3.0,    // Fast convergence alpha
            fast_convergence: true,
            hystart_enabled: true,
            hystart_ack_train: Duration::from_micros(2000), // 2ms
            hystart_delay_min: Duration::from_micros(4000), // 4ms  
            hystart_round_thresh: 8,
            min_cwnd: 2,
            initial_ssthresh: u32::MAX / 2, // Effectively infinite initially
        }
    }
}

/// CUBIC congestion control state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CubicState {
    /// Slow start phase
    SlowStart,
    /// Congestion avoidance phase
    CongestionAvoidance,
    /// Fast recovery phase
    FastRecovery,
    /// HyStart delay increase phase
    HyStartDelayIncrease,
}

/// HyStart (Hybrid Slow Start) state
#[derive(Debug, Clone)]
struct HyStart {
    /// Enabled flag
    enabled: bool,
    /// Round counter for ACK train detection
    round_counter: u32,
    /// Minimum RTT in current round
    curr_round_min_rtt: Duration,
    /// Last round's minimum RTT
    last_round_min_rtt: Duration,
    /// ACK train start time
    ack_train_start: Option<Instant>,
    /// Sample RTT measurements for delay increase detection
    rtt_samples: Vec<Duration>,
    /// Round start time
    round_start: Instant,
    /// Found exit point
    found_exit: bool,
}

impl HyStart {
    fn new(enabled: bool) -> Self {
        let now = Instant::now();
        Self {
            enabled,
            round_counter: 0,
            curr_round_min_rtt: Duration::MAX,
            last_round_min_rtt: Duration::MAX,
            ack_train_start: None,
            rtt_samples: Vec::new(),
            round_start: now,
            found_exit: false,
        }
    }

    fn reset(&mut self) {
        self.round_counter = 0;
        self.curr_round_min_rtt = Duration::MAX;
        self.last_round_min_rtt = Duration::MAX;
        self.ack_train_start = None;
        self.rtt_samples.clear();
        self.round_start = Instant::now();
        self.found_exit = false;
    }
}

/// CUBIC congestion controller
#[derive(Debug, Clone)]
pub struct CubicController {
    /// Configuration
    config: CubicConfig,
    /// Current state
    state: CubicState,
    /// Current congestion window (in packets)
    cwnd: u32,
    /// Slow start threshold
    ssthresh: u32,
    /// Congestion window before last reduction
    cwnd_last_max: u32,
    /// Time when last reduction occurred
    epoch_start: Option<Instant>,
    /// Origin point for CUBIC function
    origin_point: f64,
    /// Current target congestion window
    w_tcp: f64,
    /// CUBIC window size
    w_cubic: f64,
    /// Maximum segment size
    mss: u32,
    /// HyStart state
    hystart: HyStart,
    /// TCP-friendly window calculation
    tcp_cwnd: f64,
    /// ACK count for slow start
    ack_count: u32,
    /// Round counter
    round_count: u32,
    /// Packets acknowledged this round
    acked_bytes_this_round: u64,
    /// Start time of current round
    round_start_time: Instant,
    /// Last RTT measurement
    last_rtt: Duration,
    /// Minimum RTT seen
    min_rtt: Duration,
    /// Maximum RTT seen  
    max_rtt: Duration,
    /// RTT variance
    rtt_var: Duration,
    /// Smoothed RTT
    srtt: Duration,
    /// Fast convergence active
    fast_convergence_active: bool,
    /// Bytes in flight
    bytes_in_flight: u64,
}

impl CubicController {
    /// Create a new CUBIC controller
    pub fn new(mss: u32) -> Self {
        let config = CubicConfig::default();
        let now = Instant::now();
        
        Self {
            cwnd: max(config.min_cwnd, 10), // Start with reasonable initial window
            ssthresh: config.initial_ssthresh,
            cwnd_last_max: max(config.min_cwnd, 10),
            epoch_start: None,
            origin_point: 0.0,
            w_tcp: 0.0,
            w_cubic: 0.0,
            tcp_cwnd: max(config.min_cwnd, 10) as f64,
            ack_count: 0,
            round_count: 0,
            acked_bytes_this_round: 0,
            round_start_time: now,
            last_rtt: Duration::from_millis(100), // Default RTT estimate
            min_rtt: Duration::MAX,
            max_rtt: Duration::ZERO,
            rtt_var: Duration::ZERO,
            srtt: Duration::from_millis(100),
            fast_convergence_active: false,
            bytes_in_flight: 0,
            state: CubicState::SlowStart,
            hystart: HyStart::new(config.hystart_enabled),
            config,
            mss,
        }
    }

    /// Create CUBIC controller with custom configuration
    pub fn with_config(mss: u32, config: CubicConfig) -> Self {
        let mut controller = Self::new(mss);
        controller.hystart.enabled = config.hystart_enabled;
        controller.config = config;
        controller
    }

    /// Process ACK reception
    pub fn on_ack(&mut self, acked_bytes: u64, rtt: Duration, now: Instant) {
        // Update RTT measurements
        self.update_rtt(rtt);
        self.acked_bytes_this_round += acked_bytes;
        
        // Check for round completion
        if self.is_new_round(now) {
            self.on_round_complete(now);
        }

        match self.state {
            CubicState::SlowStart => {
                if self.hystart.enabled && !self.hystart.found_exit {
                    if self.hystart_exit_point(rtt, now) {
                        self.exit_slow_start(now);
                        return;
                    }
                }
                
                // Standard slow start - increase cwnd by 1 for each ACK
                let acked_packets = (acked_bytes + self.mss as u64 - 1) / self.mss as u64;
                self.cwnd = min(self.cwnd + acked_packets as u32, u32::MAX - 1000);
                
                // Check if we should exit slow start
                if self.cwnd >= self.ssthresh {
                    self.exit_slow_start(now);
                }
            }
            CubicState::CongestionAvoidance => {
                self.cubic_update(now);
            }
            CubicState::FastRecovery => {
                // In fast recovery, inflate window for each ack
                self.cwnd += (acked_bytes / self.mss as u64) as u32;
            }
            CubicState::HyStartDelayIncrease => {
                // Limited increase during delay increase detection
                if self.ack_count >= self.cwnd {
                    self.cwnd += 1;
                    self.ack_count = 0;
                } else {
                    self.ack_count += (acked_bytes / self.mss as u64) as u32;
                }
            }
        }

        protocol_event!(
            Level::Debug,
            "CUBIC ACK processed";
            "state" => format!("{:?}", self.state),
            "cwnd" => self.cwnd,
            "ssthresh" => self.ssthresh,
            "rtt_ms" => rtt.as_millis(),
            "acked_bytes" => acked_bytes
        );
    }

    /// Handle packet loss
    pub fn on_loss(&mut self, lost_bytes: u64, now: Instant) {
        // Enter fast recovery if not already there
        if !matches!(self.state, CubicState::FastRecovery) {
            self.enter_fast_recovery(lost_bytes, now);
        }

        protocol_event!(
            Level::Info,
            "CUBIC packet loss";
            "lost_bytes" => lost_bytes,
            "cwnd_before" => self.cwnd,
            "state" => format!("{:?}", self.state)
        );
    }

    /// Handle persistent congestion
    pub fn on_persistent_congestion(&mut self, now: Instant) {
        self.ssthresh = max(self.cwnd / 2, self.config.min_cwnd);
        self.cwnd = self.config.min_cwnd;
        self.state = CubicState::SlowStart;
        self.epoch_start = None;
        self.hystart.reset();
        
        protocol_event!(
            Level::Warn,
            "CUBIC persistent congestion reset";
            "new_cwnd" => self.cwnd,
            "new_ssthresh" => self.ssthresh
        );
    }

    /// Get current congestion window in bytes
    pub fn congestion_window(&self) -> u64 {
        self.cwnd as u64 * self.mss as u64
    }

    /// Get current state
    pub fn state(&self) -> CubicState {
        self.state
    }

    /// Check if can send more data
    pub fn can_send(&self, bytes_in_flight: u64) -> bool {
        bytes_in_flight < self.congestion_window()
    }

    /// Get available sending window
    pub fn send_window(&self, bytes_in_flight: u64) -> u64 {
        self.congestion_window().saturating_sub(bytes_in_flight)
    }

    /// Update bytes in flight
    pub fn set_bytes_in_flight(&mut self, bytes: u64) {
        self.bytes_in_flight = bytes;
    }

    /// Get CUBIC statistics
    pub fn stats(&self) -> CubicStats {
        CubicStats {
            state: self.state,
            cwnd: self.cwnd,
            ssthresh: self.ssthresh,
            cwnd_last_max: self.cwnd_last_max,
            w_cubic: self.w_cubic,
            w_tcp: self.w_tcp,
            min_rtt: self.min_rtt,
            srtt: self.srtt,
            round_count: self.round_count,
            hystart_enabled: self.hystart.enabled,
            fast_convergence_active: self.fast_convergence_active,
        }
    }

    // Private helper methods

    fn update_rtt(&mut self, rtt: Duration) {
        self.last_rtt = rtt;
        
        if self.min_rtt == Duration::MAX || rtt < self.min_rtt {
            self.min_rtt = rtt;
        }
        if rtt > self.max_rtt {
            self.max_rtt = rtt;
        }

        // Update smoothed RTT (SRTT) using exponential moving average
        if self.srtt == Duration::ZERO {
            self.srtt = rtt;
            self.rtt_var = rtt / 2;
        } else {
            let diff = if rtt >= self.srtt {
                rtt - self.srtt
            } else {
                self.srtt - rtt
            };
            self.rtt_var = (self.rtt_var * 3 + diff) / 4;
            self.srtt = (self.srtt * 7 + rtt) / 8;
        }
    }

    fn is_new_round(&self, now: Instant) -> bool {
        now.duration_since(self.round_start_time) >= self.srtt
    }

    fn on_round_complete(&mut self, now: Instant) {
        self.round_count += 1;
        self.round_start_time = now;
        
        // Update HyStart round tracking
        if self.hystart.enabled && matches!(self.state, CubicState::SlowStart) {
            self.hystart.last_round_min_rtt = self.hystart.curr_round_min_rtt;
            self.hystart.curr_round_min_rtt = Duration::MAX;
            self.hystart.round_counter += 1;
        }
        
        self.acked_bytes_this_round = 0;
    }

    fn hystart_exit_point(&mut self, rtt: Duration, now: Instant) -> bool {
        if !self.hystart.enabled || self.hystart.found_exit {
            return false;
        }

        // Update current round minimum RTT
        if rtt < self.hystart.curr_round_min_rtt {
            self.hystart.curr_round_min_rtt = rtt;
        }

        // ACK train detection
        if let Some(train_start) = self.hystart.ack_train_start {
            if now.duration_since(train_start) >= self.config.hystart_ack_train {
                protocol_event!(Level::Debug, "HyStart ACK train detected");
                self.hystart.found_exit = true;
                return true;
            }
        } else {
            self.hystart.ack_train_start = Some(now);
        }

        // Delay increase detection
        if self.hystart.round_counter >= self.config.hystart_round_thresh {
            if self.hystart.last_round_min_rtt != Duration::MAX {
                let delay_increase = self.hystart.curr_round_min_rtt
                    .saturating_sub(self.hystart.last_round_min_rtt);
                
                if delay_increase >= self.config.hystart_delay_min {
                    protocol_event!(
                        Level::Debug, 
                        "HyStart delay increase detected";
                        "delay_increase_us" => delay_increase.as_micros()
                    );
                    self.hystart.found_exit = true;
                    return true;
                }
            }
        }

        false
    }

    fn exit_slow_start(&mut self, now: Instant) {
        self.state = CubicState::CongestionAvoidance;
        self.ssthresh = self.cwnd;
        self.epoch_start = Some(now);
        self.ack_count = 0;
        
        protocol_event!(
            Level::Info,
            "CUBIC exiting slow start";
            "cwnd" => self.cwnd,
            "ssthresh" => self.ssthresh
        );
    }

    fn cubic_update(&mut self, now: Instant) {
        let epoch_start = self.epoch_start.unwrap_or(now);
        let t = now.duration_since(epoch_start).as_secs_f64();
        
        // Calculate CUBIC window: W_cubic(t) = C * (t - K)^3 + W_max
        let k = self.calculate_k();
        let w_cubic = self.config.cubic_c * (t - k).powi(3) + self.cwnd_last_max as f64;
        self.w_cubic = w_cubic.max(self.config.min_cwnd as f64);

        // Calculate TCP-friendly window if enabled
        if self.config.tcp_friendliness {
            self.update_tcp_friendly_window(t);
            
            // Use the larger of CUBIC and TCP-friendly windows
            let target_cwnd = if self.w_cubic < self.w_tcp {
                self.w_tcp
            } else {
                self.w_cubic
            };
            
            self.update_cwnd_toward_target(target_cwnd);
        } else {
            self.update_cwnd_toward_target(self.w_cubic);
        }
    }

    fn calculate_k(&self) -> f64 {
        // K = cube_root(W_max * beta / C)
        let w_max = self.cwnd_last_max as f64;
        let k_val = w_max * (1.0 - self.config.beta) / self.config.cubic_c;
        k_val.cbrt()
    }

    fn update_tcp_friendly_window(&mut self, t: f64) {
        // TCP-friendly window: W_tcp(t) = W_max * beta + 3 * (1-beta) / (1+beta) * t / RTT
        let w_max = self.cwnd_last_max as f64;
        let rtt_secs = self.srtt.as_secs_f64();
        
        if rtt_secs > 0.0 {
            self.w_tcp = w_max * self.config.beta + 
                3.0 * (1.0 - self.config.beta) / (1.0 + self.config.beta) * t / rtt_secs;
        } else {
            self.w_tcp = w_max * self.config.beta;
        }
    }

    fn update_cwnd_toward_target(&mut self, target: f64) {
        let target_cwnd = target as u32;
        
        if target_cwnd > self.cwnd {
            // Increase window gradually (standard additive increase)
            if self.ack_count >= self.cwnd {
                self.cwnd = min(self.cwnd + 1, target_cwnd);
                self.ack_count = 0;
            } else {
                self.ack_count += 1;
            }
        } else if target_cwnd < self.cwnd {
            // Decrease window (should not happen in congestion avoidance)
            self.cwnd = max(target_cwnd, self.config.min_cwnd);
        }
    }

    fn enter_fast_recovery(&mut self, _lost_bytes: u64, now: Instant) {
        // Fast convergence
        if self.config.fast_convergence && self.cwnd < self.cwnd_last_max {
            self.cwnd_last_max = self.cwnd;
            self.cwnd = (self.cwnd as f64 * (1.0 + self.config.beta) / 2.0) as u32;
            self.fast_convergence_active = true;
        } else {
            self.cwnd_last_max = self.cwnd;
            self.cwnd = (self.cwnd as f64 * self.config.beta) as u32;
            self.fast_convergence_active = false;
        }

        self.cwnd = max(self.cwnd, self.config.min_cwnd);
        self.ssthresh = self.cwnd;
        self.state = CubicState::FastRecovery;
        self.epoch_start = Some(now);

        protocol_event!(
            Level::Info,
            "CUBIC entering fast recovery";
            "old_cwnd_max" => self.cwnd_last_max,
            "new_cwnd" => self.cwnd,
            "fast_convergence" => self.fast_convergence_active
        );
    }

    /// Exit fast recovery (typically called when all lost packets are recovered)
    pub fn exit_fast_recovery(&mut self, now: Instant) {
        self.state = CubicState::CongestionAvoidance;
        self.epoch_start = Some(now);
        self.ack_count = 0;
        
        protocol_event!(
            Level::Info,
            "CUBIC exiting fast recovery";
            "cwnd" => self.cwnd
        );
    }

    /// Handle ECN congestion event
    pub fn on_ecn_congestion(&mut self, _event: &crate::quic::ecn::EcnCongestionEvent, _now: Instant) -> Result<()> {
        // ECN congestion handling for CUBIC
        // CUBIC responds to ECN by reducing the congestion window
        // but more conservatively than packet loss
        
        if matches!(self.state, CubicState::SlowStart) {
            // Exit slow start due to ECN marking
            self.ssthresh = self.cwnd;
            self.state = CubicState::CongestionAvoidance;
            self.cwnd_last_max = self.cwnd;
            self.epoch_start = Some(_now);
            
            protocol_event!(
                Level::Info,
                "CUBIC: ECN congestion detected in SlowStart, transitioning to CongestionAvoidance";
                "marking_rate" => _event.marking_rate,
                "cwnd" => self.cwnd,
                "ssthresh" => self.ssthresh
            );
        }
        
        // Reduce congestion window based on ECN marking rate
        let reduction_factor = match _event.marking_rate {
            rate if rate > 0.2 => 0.5,  // High marking rate
            rate if rate > 0.1 => 0.7,  // Medium marking rate
            _ => 0.8,                   // Low marking rate
        };
        
        let new_cwnd = ((self.cwnd as f64 * reduction_factor) as u32).max(self.config.min_cwnd);
        
        // Apply fast convergence if the new window is smaller than last max
        if new_cwnd < self.cwnd_last_max {
            self.cwnd_last_max = new_cwnd;
            self.fast_convergence_active = true;
        }
        
        self.cwnd = new_cwnd;
        self.ssthresh = self.cwnd;
        self.epoch_start = Some(_now);
        
        protocol_event!(
            Level::Debug,
            "CUBIC: Applied ECN congestion response";
            "old_cwnd" => self.cwnd,
            "new_cwnd" => new_cwnd,
            "reduction_factor" => reduction_factor,
            "marking_rate" => _event.marking_rate
        );
        
        Ok(())
    }
}

/// CUBIC statistics
#[derive(Debug, Clone)]
pub struct CubicStats {
    /// Current state
    pub state: CubicState,
    /// Current congestion window (packets)
    pub cwnd: u32,
    /// Slow start threshold
    pub ssthresh: u32,
    /// Last maximum congestion window
    pub cwnd_last_max: u32,
    /// CUBIC window calculation
    pub w_cubic: f64,
    /// TCP-friendly window calculation
    pub w_tcp: f64,
    /// Minimum RTT observed
    pub min_rtt: Duration,
    /// Smoothed RTT
    pub srtt: Duration,
    /// Round counter
    pub round_count: u32,
    /// HyStart enabled
    pub hystart_enabled: bool,
    /// Fast convergence active
    pub fast_convergence_active: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cubic_initialization() {
        let cubic = CubicController::new(1200);
        assert_eq!(cubic.state(), CubicState::SlowStart);
        assert!(cubic.cwnd >= 2);
        assert_eq!(cubic.mss, 1200);
    }

    #[test]
    fn test_cubic_slow_start() {
        let mut cubic = CubicController::new(1200);
        let now = Instant::now();
        
        // Initial window should be small
        let initial_cwnd = cubic.cwnd;
        
        // ACK 1200 bytes (1 packet)
        cubic.on_ack(1200, Duration::from_millis(50), now);
        
        // In slow start, cwnd should increase by 1 packet per ACK
        assert_eq!(cubic.cwnd, initial_cwnd + 1);
        assert_eq!(cubic.state(), CubicState::SlowStart);
    }

    #[test]
    fn test_cubic_congestion_avoidance() {
        let mut cubic = CubicController::new(1200);
        let now = Instant::now();
        
        // Force into congestion avoidance - start with a smaller window than cwnd_last_max
        cubic.cwnd = 50;
        cubic.ssthresh = 50;
        cubic.cwnd_last_max = 100; // Previous maximum before reduction
        cubic.state = CubicState::CongestionAvoidance;
        cubic.epoch_start = Some(now);
        
        let initial_cwnd = cubic.cwnd;
        
        // ACK processing in congestion avoidance with some time elapsed
        let later = now + Duration::from_millis(100);
        cubic.on_ack(1200, Duration::from_millis(50), later);
        
        // Window should increase more gradually than slow start
        assert!(cubic.cwnd >= initial_cwnd, "CUBIC window should not decrease in congestion avoidance");
    }

    #[test]
    fn test_cubic_loss_handling() {
        let mut cubic = CubicController::new(1200);
        let now = Instant::now();
        
        cubic.cwnd = 100;
        cubic.state = CubicState::CongestionAvoidance;
        let initial_cwnd = cubic.cwnd;
        
        // Simulate packet loss
        cubic.on_loss(1200, now);
        
        // Should enter fast recovery and reduce window
        assert_eq!(cubic.state(), CubicState::FastRecovery);
        assert!(cubic.cwnd < initial_cwnd);
        assert!(cubic.cwnd as f64 <= initial_cwnd as f64 * cubic.config.beta + 1.0);
    }

    #[test]
    fn test_cubic_fast_convergence() {
        let mut cubic = CubicController::new(1200);
        let now = Instant::now();
        
        // Set up for fast convergence scenario
        cubic.cwnd = 80;
        cubic.cwnd_last_max = 100;
        cubic.state = CubicState::CongestionAvoidance;
        
        let initial_cwnd = cubic.cwnd;
        
        // Trigger loss (should activate fast convergence)
        cubic.on_loss(1200, now);
        
        // Fast convergence should be active
        assert!(cubic.fast_convergence_active);
        assert!(cubic.cwnd < initial_cwnd);
    }

    #[test]
    fn test_cubic_hystart_config() {
        let config = CubicConfig {
            hystart_enabled: false,
            ..Default::default()
        };
        
        let cubic = CubicController::with_config(1200, config);
        assert!(!cubic.hystart.enabled);
    }

    #[test]
    fn test_cubic_window_calculation() {
        let cubic = CubicController::new(1200);
        let window_bytes = cubic.congestion_window();
        
        // Window should be cwnd * mss
        assert_eq!(window_bytes, cubic.cwnd as u64 * 1200);
    }

    #[test]
    fn test_cubic_can_send() {
        let cubic = CubicController::new(1200);
        let window = cubic.congestion_window();
        
        assert!(cubic.can_send(0));
        assert!(cubic.can_send(window / 2));
        assert!(!cubic.can_send(window));
        assert!(!cubic.can_send(window + 1));
    }

    #[test]
    fn test_cubic_persistent_congestion() {
        let mut cubic = CubicController::new(1200);
        let now = Instant::now();
        
        cubic.cwnd = 100;
        cubic.ssthresh = 50;
        
        cubic.on_persistent_congestion(now);
        
        // Should reset to minimum values
        assert_eq!(cubic.cwnd, cubic.config.min_cwnd);
        assert_eq!(cubic.state(), CubicState::SlowStart);
    }
}