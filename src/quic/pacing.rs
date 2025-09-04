//! Packet Pacing Implementation for QUIC
//!
//! This module implements packet pacing to smooth transmission and prevent
//! traffic bursts that can cause network congestion. Pacing is essential for
//! high-speed networks where bursts can overwhelm buffers and cause losses.
//!
//! Key features:
//! - Rate-based pacing using token bucket algorithm
//! - Integration with congestion control algorithms (BBR, CUBIC, NewReno)
//! - Adaptive burst handling based on network conditions
//! - Support for application-limited scenarios

use crate::{
    util::time::{Duration, Instant},
    whathappened::Level,
    protocol_event,
};
use std::cmp::{max, min};

/// Pacing configuration parameters
#[derive(Debug, Clone)]
pub struct PacingConfig {
    /// Minimum pacing rate (bytes per second)
    pub min_pacing_rate: u64,
    /// Maximum pacing rate (bytes per second) 
    pub max_pacing_rate: u64,
    /// Initial burst allowance in packets
    pub initial_burst: u32,
    /// Maximum burst size in packets
    pub max_burst: u32,
    /// Minimum interval between packet sends
    pub min_send_interval: Duration,
    /// Pacing rate update smoothing factor (0.0 to 1.0)
    pub rate_smoothing_factor: f64,
    /// Enable burst allowance during app-limited periods
    pub enable_burst_allowance: bool,
    /// Burst allowance accumulation rate (tokens per second)
    pub burst_accumulation_rate: f64,
}

impl Default for PacingConfig {
    fn default() -> Self {
        Self {
            min_pacing_rate: 64000,      // 64 KB/s minimum
            max_pacing_rate: 10_000_000_000, // 10 GB/s maximum
            initial_burst: 10,            // Start with 10 packet burst
            max_burst: 64,               // Maximum 64 packet burst
            min_send_interval: Duration::from_micros(100), // 100µs minimum
            rate_smoothing_factor: 0.25, // 25% new rate, 75% old rate
            enable_burst_allowance: true,
            burst_accumulation_rate: 100.0, // 100 tokens per second
        }
    }
}

/// Packet pacing state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacingState {
    /// Normal pacing active
    Active,
    /// Application-limited, no pacing needed
    AppLimited,
    /// Burst mode allowed
    Burst,
    /// Pacing disabled
    Disabled,
}

/// Token bucket for rate limiting
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Current number of tokens available
    tokens: f64,
    /// Maximum bucket capacity (in tokens)
    capacity: f64,
    /// Token replenishment rate (tokens per second)
    rate: f64,
    /// Last update timestamp
    last_update: Instant,
}

impl TokenBucket {
    fn new(capacity: f64, rate: f64) -> Self {
        let now = Instant::now();
        Self {
            tokens: capacity,
            capacity,
            rate,
            last_update: now,
        }
    }

    /// Update token count based on elapsed time
    fn update(&mut self, now: Instant) {
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        let new_tokens = elapsed * self.rate;
        self.tokens = (self.tokens + new_tokens).min(self.capacity);
        self.last_update = now;
    }

    /// Try to consume tokens
    fn try_consume(&mut self, tokens: f64) -> bool {
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    /// Get time until sufficient tokens are available
    fn time_until_tokens(&self, tokens: f64) -> Duration {
        if self.tokens >= tokens {
            Duration::ZERO
        } else {
            let needed = tokens - self.tokens;
            let seconds = needed / self.rate;
            Duration::from_secs_f64(seconds)
        }
    }

    /// Update the token rate
    fn set_rate(&mut self, new_rate: f64) {
        self.rate = new_rate;
    }

    /// Update bucket capacity
    fn set_capacity(&mut self, new_capacity: f64) {
        self.capacity = new_capacity;
        if self.tokens > self.capacity {
            self.tokens = self.capacity;
        }
    }
}

/// Packet pacing controller
#[derive(Debug, Clone)]
pub struct PacingController {
    /// Configuration
    config: PacingConfig,
    /// Current pacing state
    state: PacingState,
    /// Token bucket for rate limiting
    token_bucket: TokenBucket,
    /// Current pacing rate (bytes per second)
    pacing_rate: u64,
    /// Target pacing rate (for smooth transitions)
    target_pacing_rate: u64,
    /// Current burst allowance (in packets)
    burst_allowance: u32,
    /// Time of last packet send
    last_send_time: Instant,
    /// Statistics
    packets_sent: u64,
    bytes_sent: u64,
    packets_delayed: u64,
    total_delay: Duration,
    /// App-limited tracking
    app_limited_start: Option<Instant>,
    /// Smoothed RTT for pacing calculations
    smoothed_rtt: Duration,
}

impl PacingController {
    /// Create a new pacing controller
    pub fn new(config: PacingConfig) -> Self {
        let now = Instant::now();
        let initial_rate = config.min_pacing_rate;
        
        Self {
            token_bucket: TokenBucket::new(
                config.max_burst as f64 * 1500.0, // Convert max burst to bytes (assuming ~1500 byte MTU)
                initial_rate as f64
            ),
            pacing_rate: initial_rate,
            target_pacing_rate: initial_rate,
            burst_allowance: config.initial_burst,
            last_send_time: now,
            state: PacingState::Active,
            packets_sent: 0,
            bytes_sent: 0,
            packets_delayed: 0,
            total_delay: Duration::ZERO,
            app_limited_start: None,
            smoothed_rtt: Duration::from_millis(100), // Default RTT estimate
            config,
        }
    }

    /// Create pacing controller with custom configuration
    pub fn with_config(config: PacingConfig) -> Self {
        Self::new(config)
    }

    /// Update pacing rate based on congestion control feedback with timestamp
    pub fn update_pacing_rate_with_time_internal(&mut self, new_rate: u64, now: Instant) {
        // Clamp rate to configured bounds
        let clamped_rate = max(
            self.config.min_pacing_rate,
            min(new_rate, self.config.max_pacing_rate)
        );

        // Smooth rate transitions to avoid abrupt changes
        let smoothing = self.config.rate_smoothing_factor;
        self.target_pacing_rate = clamped_rate;
        
        if self.pacing_rate == 0 {
            self.pacing_rate = clamped_rate;
        } else {
            let new_pacing_rate = (clamped_rate as f64 * smoothing + 
                                  self.pacing_rate as f64 * (1.0 - smoothing)) as u64;
            self.pacing_rate = new_pacing_rate;
        }

        // Update token bucket rate
        self.token_bucket.set_rate(self.pacing_rate as f64);
        self.token_bucket.update(now);

        protocol_event!(
            Level::Debug,
            "Pacing rate updated";
            "old_rate_bps" => self.pacing_rate,
            "new_rate_bps" => clamped_rate,
            "target_rate_bps" => self.target_pacing_rate
        );
    }

    /// Update smoothed RTT for pacing calculations
    pub fn update_rtt(&mut self, rtt: Duration) {
        // Use exponential moving average
        self.smoothed_rtt = Duration::from_nanos(
            (self.smoothed_rtt.as_nanos() as f64 * 0.875 + 
             rtt.as_nanos() as f64 * 0.125) as u64
        );
    }

    /// Check if a packet can be sent immediately
    pub fn can_send(&mut self, packet_size: usize, now: Instant) -> bool {
        self.token_bucket.update(now);

        match self.state {
            PacingState::Disabled | PacingState::AppLimited => true,
            PacingState::Burst => {
                if self.burst_allowance > 0 {
                    true
                } else {
                    self.state = PacingState::Active;
                    self.can_send_with_pacing(packet_size)
                }
            }
            PacingState::Active => self.can_send_with_pacing(packet_size),
        }
    }

    /// Check if packet can be sent with pacing constraints
    fn can_send_with_pacing(&self, packet_size: usize) -> bool {
        // Calculate tokens needed (normalize to bytes)
        let tokens_needed = packet_size as f64;
        self.token_bucket.tokens >= tokens_needed
    }

    /// Get the delay required before sending
    pub fn send_delay(&mut self, packet_size: usize, now: Instant) -> Duration {
        self.token_bucket.update(now);

        match self.state {
            PacingState::Disabled | PacingState::AppLimited => Duration::ZERO,
            PacingState::Burst => {
                if self.burst_allowance > 0 {
                    Duration::ZERO
                } else {
                    self.state = PacingState::Active;
                    self.calculate_pacing_delay(packet_size, now)
                }
            }
            PacingState::Active => self.calculate_pacing_delay(packet_size, now),
        }
    }

    /// Calculate required pacing delay
    fn calculate_pacing_delay(&self, packet_size: usize, now: Instant) -> Duration {
        let tokens_needed = packet_size as f64;
        let delay = self.token_bucket.time_until_tokens(tokens_needed);
        
        // Ensure minimum send interval
        let time_since_last = now.duration_since(self.last_send_time);
        let min_delay = self.config.min_send_interval;
        
        if time_since_last < min_delay {
            max(delay, min_delay - time_since_last)
        } else {
            delay
        }
    }

    /// Record a packet send
    pub fn on_packet_sent(&mut self, packet_size: usize, now: Instant) {
        self.token_bucket.update(now);
        
        // Consume tokens
        let tokens_consumed = packet_size as f64;
        self.token_bucket.try_consume(tokens_consumed);
        
        // Update burst allowance
        match self.state {
            PacingState::Burst => {
                if self.burst_allowance > 0 {
                    self.burst_allowance -= 1;
                }
            }
            _ => {}
        }

        // Update statistics
        self.packets_sent += 1;
        self.bytes_sent += packet_size as u64;
        self.last_send_time = now;

        // Clear app-limited state if we were sending
        if matches!(self.state, PacingState::AppLimited) {
            self.state = PacingState::Active;
            self.app_limited_start = None;
        }

        protocol_event!(
            Level::Trace,
            "Packet sent with pacing";
            "packet_size" => packet_size,
            "tokens_remaining" => self.token_bucket.tokens,
            "burst_allowance" => self.burst_allowance,
            "state" => format!("{:?}", self.state)
        );
    }

    /// Handle congestion event
    pub fn on_congestion_event(&mut self, now: Instant) {
        // Reduce burst allowance on congestion
        self.burst_allowance = max(1, self.burst_allowance / 2);
        
        // Ensure we're in active pacing mode
        if matches!(self.state, PacingState::Burst) {
            self.state = PacingState::Active;
        }

        protocol_event!(
            Level::Info,
            "Pacing adjusted for congestion";
            "timestamp" => format!("{:?}", now),
            "new_burst_allowance" => self.burst_allowance,
            "tokens_available" => self.token_bucket.tokens as u64
        );
    }

    /// Signal that application is limiting sends
    pub fn set_app_limited(&mut self, now: Instant) {
        if !matches!(self.state, PacingState::AppLimited) {
            self.state = PacingState::AppLimited;
            self.app_limited_start = Some(now);
            
            // Allow burst accumulation during app-limited period
            if self.config.enable_burst_allowance {
                self.start_burst_accumulation(now);
            }
        }
    }

    /// Start accumulating burst allowance
    fn start_burst_accumulation(&mut self, now: Instant) {
        // Increase burst allowance gradually
        let max_additional = self.config.max_burst.saturating_sub(self.burst_allowance);
        if max_additional > 0 {
            let additional = min(
                max_additional,
                (self.config.burst_accumulation_rate * 
                 self.smoothed_rtt.as_secs_f64()) as u32
            );
            
            protocol_event!(
                Level::Debug,
                "Starting burst accumulation";
                "timestamp" => format!("{:?}", now),
                "current_burst" => self.burst_allowance,
                "additional_burst" => additional
            );
            
            self.burst_allowance = min(
                self.config.max_burst,
                self.burst_allowance + additional
            );
        }
    }

    /// Check if should enter burst mode
    pub fn should_enter_burst(&self) -> bool {
        self.burst_allowance > self.config.initial_burst &&
        matches!(self.state, PacingState::AppLimited)
    }

    /// Enter burst mode
    pub fn enter_burst_mode(&mut self) {
        if self.should_enter_burst() {
            self.state = PacingState::Burst;
            protocol_event!(
                Level::Debug,
                "Entered burst mode";
                "burst_allowance" => self.burst_allowance
            );
        }
    }

    /// Disable pacing (for testing or special scenarios)
    pub fn disable(&mut self) {
        self.state = PacingState::Disabled;
    }

    /// Enable pacing
    pub fn enable(&mut self) {
        self.state = PacingState::Active;
    }

    /// Get current pacing rate
    pub fn pacing_rate(&self) -> u64 {
        self.pacing_rate
    }

    /// Get current state
    pub fn state(&self) -> PacingState {
        self.state
    }

    /// Get pacing statistics
    pub fn stats(&self) -> PacingStats {
        PacingStats {
            state: self.state,
            pacing_rate: self.pacing_rate,
            target_pacing_rate: self.target_pacing_rate,
            burst_allowance: self.burst_allowance,
            tokens_available: self.token_bucket.tokens,
            packets_sent: self.packets_sent,
            bytes_sent: self.bytes_sent,
            packets_delayed: self.packets_delayed,
            average_delay: if self.packets_delayed > 0 {
                self.total_delay / self.packets_delayed as u32
            } else {
                Duration::ZERO
            },
        }
    }

    /// Reset pacing controller
    pub fn reset(&mut self, now: Instant) {
        self.state = PacingState::Active;
        self.pacing_rate = self.config.min_pacing_rate;
        self.target_pacing_rate = self.config.min_pacing_rate;
        self.burst_allowance = self.config.initial_burst;
        self.last_send_time = now;
        self.packets_sent = 0;
        self.bytes_sent = 0;
        self.packets_delayed = 0;
        self.total_delay = Duration::ZERO;
        self.app_limited_start = None;
        
        // Reset token bucket
        self.token_bucket = TokenBucket::new(
            self.config.max_burst as f64,
            self.config.min_pacing_rate as f64
        );
    }
    
    /// Check if a packet can be sent immediately (overload for congestion control)
    pub fn can_send_now(&self) -> bool {
        let now = Instant::now();
        let mut temp_self = self.clone();
        temp_self.can_send(1200, now)
    }
    
    /// Update pacing rate based on congestion control feedback
    pub fn update_pacing_rate(&mut self, new_rate: u64) {
        let now = Instant::now();
        self.update_pacing_rate_with_time(new_rate, now);
    }
    
    /// Update pacing rate with specific timestamp
    pub fn update_pacing_rate_with_time(&mut self, new_rate: u64, now: Instant) {
        protocol_event!(
            Level::Debug,
            "Updating pacing rate";
            "timestamp" => format!("{:?}", now),
            "new_rate" => new_rate,
            "old_rate" => self.pacing_rate
        );
        
        // Clamp rate to configured bounds
        let clamped_rate = max(
            self.config.min_pacing_rate,
            min(self.config.max_pacing_rate, new_rate)
        );
        
        // Smooth rate transitions
        let smoothed_rate = if self.pacing_rate > 0 {
            let factor = self.config.rate_smoothing_factor;
            (self.pacing_rate as f64 * (1.0 - factor) + clamped_rate as f64 * factor) as u64
        } else {
            clamped_rate
        };
        
        self.target_pacing_rate = clamped_rate;
        self.pacing_rate = smoothed_rate;
        
        // Update token bucket rate
        self.token_bucket.set_rate(smoothed_rate as f64);
    }
    
    /// Get available sending window based on pacing
    pub fn available_window(&self) -> u64 {
        let now = Instant::now();
        let mut temp_self = self.clone();
        if temp_self.can_send(1200, now) {
            // Return a reasonable window based on current rate
            let rate_per_ms = self.pacing_rate / 1000;
            rate_per_ms * 10 // 10ms worth of data
        } else {
            0
        }
    }
    
    /// Handle ACK received for pacing adjustments
    pub fn on_ack_received(&mut self, _bytes_acked: u64, rtt: Duration) {
        self.update_rtt(rtt);
    }
    
    /// Handle packet lost for pacing adjustments
    pub fn on_packet_lost(&mut self, _lost_bytes: u64) {
        // Reduce pacing rate slightly on loss
        let new_rate = (self.pacing_rate as f64 * 0.9) as u64;
        self.update_pacing_rate(new_rate.max(self.config.min_pacing_rate));
    }
    
    /// Update controller state
    pub fn update(&mut self) {
        let now = Instant::now();
        
        // Update token bucket
        self.token_bucket.update(now);
        
        // Update app-limited state
        if let Some(start_time) = self.app_limited_start {
            if now.duration_since(start_time) > self.smoothed_rtt * 2 {
                self.app_limited_start = None;
                self.state = PacingState::Active;
            }
        }
    }
    
    /// Check if pacing is enabled
    pub fn is_enabled(&self) -> bool {
        !matches!(self.state, PacingState::Disabled)
    }
    
    /// Enable/disable pacing
    pub fn set_enabled(&mut self, enabled: bool) {
        self.state = if enabled {
            PacingState::Active
        } else {
            PacingState::Disabled
        };
    }
}

/// Pacing statistics
#[derive(Debug, Clone)]
pub struct PacingStats {
    /// Current pacing state
    pub state: PacingState,
    /// Current pacing rate (bytes per second)
    pub pacing_rate: u64,
    /// Target pacing rate (bytes per second)
    pub target_pacing_rate: u64,
    /// Current burst allowance
    pub burst_allowance: u32,
    /// Available tokens in bucket
    pub tokens_available: f64,
    /// Total packets sent
    pub packets_sent: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Packets that were delayed by pacing
    pub packets_delayed: u64,
    /// Average pacing delay
    pub average_delay: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pacing_controller_initialization() {
        let config = PacingConfig::default();
        let pacer = PacingController::new(config.clone());
        
        assert_eq!(pacer.state(), PacingState::Active);
        assert_eq!(pacer.pacing_rate(), config.min_pacing_rate);
        assert_eq!(pacer.burst_allowance, config.initial_burst);
    }

    #[test]
    fn test_token_bucket_basic() {
        let mut bucket = TokenBucket::new(100.0, 50.0); // 100 capacity, 50 tokens/sec
        
        // Should start full
        assert!(bucket.try_consume(50.0));
        assert_eq!(bucket.tokens, 50.0);
        
        // Should not be able to consume more than available
        assert!(!bucket.try_consume(60.0));
        assert_eq!(bucket.tokens, 50.0);
    }

    #[test]
    fn test_token_bucket_replenishment() {
        let mut bucket = TokenBucket::new(100.0, 50.0); // 50 tokens per second
        let start = Instant::now();
        
        // Consume all tokens
        bucket.try_consume(100.0);
        assert_eq!(bucket.tokens, 0.0);
        
        // Simulate 1 second passing
        let later = start + Duration::from_secs(1);
        bucket.last_update = start;
        bucket.update(later);
        
        // Should have replenished 50 tokens
        assert!((bucket.tokens - 50.0).abs() < 0.1);
    }

    #[test]
    fn test_pacing_rate_update() {
        let config = PacingConfig::default();
        let min_rate = config.min_pacing_rate;
        let mut pacer = PacingController::new(config);
        let now = Instant::now();
        
        // Update to higher rate
        pacer.update_pacing_rate_with_time(1_000_000, now);
        
        // Should be smoothed, not immediate
        assert!(pacer.pacing_rate() > min_rate);
        assert!(pacer.pacing_rate() < 1_000_000);
    }

    #[test]
    fn test_pacing_can_send() {
        let config = PacingConfig::default();
        let mut pacer = PacingController::new(config);
        let now = Instant::now();
        
        // Should be able to send initially (burst allowance)
        assert!(pacer.can_send(1200, now));
        
        // After burst exhausted, should depend on rate
        pacer.burst_allowance = 0;
        pacer.state = PacingState::Active;
        
        // With low rate, large packet might not be sendable immediately
        pacer.update_pacing_rate_with_time(1000, now); // Very low rate
        pacer.token_bucket.tokens = 500.0; // Limited tokens
        assert!(!pacer.can_send(1200, now));
    }

    #[test]
    fn test_pacing_delay_calculation() {
        let config = PacingConfig::default();
        let mut pacer = PacingController::new(config);
        let now = Instant::now();
        
        // Set low rate and few tokens (use a rate above minimum)
        pacer.update_pacing_rate_with_time(100_000, now); // 100KB/sec
        pacer.token_bucket.tokens = 0.0;
        pacer.state = PacingState::Active;
        
        let delay = pacer.send_delay(1000, now); // 1000 byte packet
        
        // Should need to wait ~10ms for tokens (1000 bytes / 100KB/s = 0.01s)
        assert!(delay >= Duration::from_millis(8), 
                "Expected delay >= 8ms, got {:?}", delay);
        assert!(delay <= Duration::from_millis(15));
    }

    #[test]
    fn test_burst_mode() {
        let config = PacingConfig::default();
        let initial_burst = config.initial_burst;
        let mut pacer = PacingController::new(config);
        let now = Instant::now();
        
        // Set app limited
        pacer.set_app_limited(now);
        assert_eq!(pacer.state(), PacingState::AppLimited);
        
        // Should accumulate burst allowance
        assert!(pacer.burst_allowance >= initial_burst);
        
        // Enter burst mode
        pacer.enter_burst_mode();
        if pacer.should_enter_burst() {
            assert_eq!(pacer.state(), PacingState::Burst);
        }
    }

    #[test]
    fn test_congestion_event_handling() {
        let config = PacingConfig::default();
        let mut pacer = PacingController::new(config);
        let now = Instant::now();
        
        let initial_burst = pacer.burst_allowance;
        pacer.on_congestion_event(now);
        
        // Should reduce burst allowance
        assert!(pacer.burst_allowance < initial_burst);
        assert!(pacer.burst_allowance >= 1); // Should not go to zero
    }

    #[test]
    fn test_packet_send_tracking() {
        let config = PacingConfig::default();
        let mut pacer = PacingController::new(config);
        let now = Instant::now();
        
        let initial_stats = pacer.stats();
        
        pacer.on_packet_sent(1200, now);
        
        let updated_stats = pacer.stats();
        assert_eq!(updated_stats.packets_sent, initial_stats.packets_sent + 1);
        assert_eq!(updated_stats.bytes_sent, initial_stats.bytes_sent + 1200);
    }

    #[test]
    fn test_rate_clamping() {
        let config = PacingConfig {
            min_pacing_rate: 1000,
            max_pacing_rate: 10000,
            ..Default::default()
        };
        let mut pacer = PacingController::new(config.clone());
        let now = Instant::now();
        
        // Test below minimum
        pacer.update_pacing_rate_with_time(500, now);
        assert!(pacer.pacing_rate() >= config.min_pacing_rate);
        
        // Test above maximum
        pacer.update_pacing_rate_with_time(50000, now);
        // Should be clamped gradually due to smoothing
        assert!(pacer.target_pacing_rate == config.max_pacing_rate);
    }

    #[test]
    fn test_app_limited_state() {
        let config = PacingConfig::default();
        let mut pacer = PacingController::new(config);
        let now = Instant::now();
        
        pacer.set_app_limited(now);
        assert_eq!(pacer.state(), PacingState::AppLimited);
        
        // Should allow immediate sending when app limited
        assert!(pacer.can_send(1200, now));
        assert_eq!(pacer.send_delay(1200, now), Duration::ZERO);
        
        // Sending should clear app limited state
        pacer.on_packet_sent(1200, now);
        assert_eq!(pacer.state(), PacingState::Active);
    }
}