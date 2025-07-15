//! Explicit Congestion Notification (ECN) Support for QUIC
//!
//! This module implements ECN (Explicit Congestion Notification) support for QUIC
//! congestion control as defined in:
//! - RFC 3168: "The Addition of Explicit Congestion Notification (ECN) to IP"
//! - RFC 9000: "QUIC: A UDP-Based Multiplexed and Secure Transport"
//! - RFC 9002: "QUIC Loss Detection and Congestion Control"
//!
//! ECN allows routers to mark packets instead of dropping them when congestion
//! occurs, providing earlier congestion signals to improve performance.

use crate::{
    util::time::{Duration, Instant},
    whathappened::Level,
    protocol_event,
};
use std::collections::VecDeque;

/// ECN codepoints as defined in RFC 3168
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcnCodepoint {
    /// Not-ECT (Not ECN-Capable Transport) - 00
    NotEct = 0b00,
    /// ECT(1) (ECN-Capable Transport) - 01
    Ect1 = 0b01,
    /// ECT(0) (ECN-Capable Transport) - 10
    Ect0 = 0b10,
    /// CE (Congestion Experienced) - 11
    Ce = 0b11,
}

impl EcnCodepoint {
    /// Create ECN codepoint from raw bits
    pub fn from_bits(bits: u8) -> Option<Self> {
        match bits & 0b11 {
            0b00 => Some(EcnCodepoint::NotEct),
            0b01 => Some(EcnCodepoint::Ect1),
            0b10 => Some(EcnCodepoint::Ect0),
            0b11 => Some(EcnCodepoint::Ce),
            _ => None,
        }
    }

    /// Convert to raw bits
    pub fn to_bits(self) -> u8 {
        self as u8
    }

    /// Check if this codepoint indicates ECN capability
    pub fn is_ect(self) -> bool {
        matches!(self, EcnCodepoint::Ect0 | EcnCodepoint::Ect1)
    }

    /// Check if this codepoint indicates congestion
    pub fn is_ce(self) -> bool {
        matches!(self, EcnCodepoint::Ce)
    }
}

/// ECN counters for tracking received marks
#[derive(Debug, Clone, Default)]
pub struct EcnCounters {
    /// ECT(0) packets received
    pub ect0_count: u64,
    /// ECT(1) packets received  
    pub ect1_count: u64,
    /// CE packets received
    pub ce_count: u64,
    /// Total ECN-capable packets received
    pub total_ect_count: u64,
}

impl EcnCounters {
    /// Update counters with received ECN marking
    pub fn update(&mut self, ecn: EcnCodepoint) {
        match ecn {
            EcnCodepoint::Ect0 => {
                self.ect0_count += 1;
                self.total_ect_count += 1;
            }
            EcnCodepoint::Ect1 => {
                self.ect1_count += 1;
                self.total_ect_count += 1;
            }
            EcnCodepoint::Ce => {
                self.ce_count += 1;
                self.total_ect_count += 1;
            }
            EcnCodepoint::NotEct => {
                // No update for non-ECN packets
            }
        }
    }

    /// Get total ECN marks (CE packets)
    pub fn total_marks(&self) -> u64 {
        self.ce_count
    }

    /// Get ECN marking rate
    pub fn marking_rate(&self) -> f64 {
        if self.total_ect_count == 0 {
            0.0
        } else {
            self.ce_count as f64 / self.total_ect_count as f64
        }
    }
}

/// ECN validation state for connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcnState {
    /// ECN validation not started
    Unknown,
    /// Testing ECN capability
    Testing,
    /// ECN capability confirmed
    Capable,
    /// ECN validation failed
    Failed,
}

/// ECN validation configuration
#[derive(Debug, Clone)]
pub struct EcnValidationConfig {
    /// Number of packets to send for ECN validation
    pub validation_packets: u32,
    /// Maximum time to wait for ECN validation
    pub validation_timeout: Duration,
    /// Minimum number of ECN-marked packets to consider path capable
    pub min_ecn_packets: u32,
    /// Enable conservative ECN validation
    pub conservative_validation: bool,
}

impl Default for EcnValidationConfig {
    fn default() -> Self {
        Self {
            validation_packets: 10,
            validation_timeout: Duration::from_secs(5),
            min_ecn_packets: 3,
            conservative_validation: true,
        }
    }
}

/// ECN validation tracker
#[derive(Debug, Clone)]
struct EcnValidation {
    /// Current validation state
    state: EcnState,
    /// Configuration
    config: EcnValidationConfig,
    /// Packets sent with ECN marking during validation
    packets_sent: u32,
    /// ECN-capable packets received during validation
    ecn_packets_received: u32,
    /// Validation start time
    validation_start: Option<Instant>,
    /// Last ECN test packet sent
    last_test_packet: Option<Instant>,
}

impl EcnValidation {
    fn new(config: EcnValidationConfig) -> Self {
        Self {
            state: EcnState::Unknown,
            config,
            packets_sent: 0,
            ecn_packets_received: 0,
            validation_start: None,
            last_test_packet: None,
        }
    }

    fn start_validation(&mut self, now: Instant) {
        if matches!(self.state, EcnState::Unknown) {
            self.state = EcnState::Testing;
            self.validation_start = Some(now);
            self.packets_sent = 0;
            self.ecn_packets_received = 0;
            
            protocol_event!(
                Level::Info,
                "Starting ECN validation"
            );
        }
    }

    fn should_send_test_packet(&self, now: Instant) -> bool {
        match self.state {
            EcnState::Testing => {
                if self.packets_sent < self.config.validation_packets {
                    // Send test packets with some spacing
                    if let Some(last_test) = self.last_test_packet {
                        now.duration_since(last_test) >= Duration::from_millis(100)
                    } else {
                        true
                    }
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn on_test_packet_sent(&mut self, now: Instant) {
        if matches!(self.state, EcnState::Testing) {
            self.packets_sent += 1;
            self.last_test_packet = Some(now);
        }
    }

    fn on_ecn_packet_received(&mut self, ecn: EcnCodepoint, now: Instant) {
        if matches!(self.state, EcnState::Testing) && ecn.is_ect() {
            self.ecn_packets_received += 1;
            self.check_validation_complete(now);
        }
    }

    fn check_validation_complete(&mut self, now: Instant) {
        if !matches!(self.state, EcnState::Testing) {
            return;
        }

        let validation_elapsed = if let Some(start) = self.validation_start {
            now.duration_since(start)
        } else {
            return;
        };

        // Check if validation period has expired
        if validation_elapsed >= self.config.validation_timeout {
            self.complete_validation();
            return;
        }

        // Check if we've sent all test packets
        if self.packets_sent >= self.config.validation_packets {
            self.complete_validation();
        }
    }

    fn complete_validation(&mut self) {
        if self.ecn_packets_received >= self.config.min_ecn_packets {
            self.state = EcnState::Capable;
            protocol_event!(
                Level::Info,
                "ECN validation successful";
                "packets_sent" => self.packets_sent,
                "ecn_received" => self.ecn_packets_received
            );
        } else {
            self.state = EcnState::Failed;
            protocol_event!(
                Level::Info,
                "ECN validation failed";
                "packets_sent" => self.packets_sent,
                "ecn_received" => self.ecn_packets_received,
                "min_required" => self.config.min_ecn_packets
            );
        }
    }

    fn is_capable(&self) -> bool {
        matches!(self.state, EcnState::Capable)
    }

    fn has_failed(&self) -> bool {
        matches!(self.state, EcnState::Failed)
    }
}

/// ECN congestion event information
#[derive(Debug, Clone)]
pub struct EcnCongestionEvent {
    /// Time when congestion was detected
    pub timestamp: Instant,
    /// Number of CE marks that triggered this event
    pub ce_count: u64,
    /// ECN marking rate at time of event
    pub marking_rate: f64,
    /// Bytes in flight when event occurred
    pub bytes_in_flight: u64,
}

/// ECN controller for QUIC connections
#[derive(Debug, Clone)]
pub struct EcnController {
    /// ECN validation tracker
    validation: EcnValidation,
    /// ECN counters for received packets
    counters: EcnCounters,
    /// Last reported CE count to congestion control
    last_reported_ce: u64,
    /// ECN marking history for rate calculation
    marking_history: VecDeque<(Instant, u64)>,
    /// Recent congestion events
    congestion_events: VecDeque<EcnCongestionEvent>,
    /// Maximum history size
    max_history_size: usize,
    /// Enable ECN usage (can be disabled by application)
    enabled: bool,
    /// Conservative ECN reaction (reduce aggressiveness)
    conservative_reaction: bool,
}

impl EcnController {
    /// Create a new ECN controller
    pub fn new() -> Self {
        Self::with_config(EcnValidationConfig::default())
    }

    /// Create ECN controller with custom configuration
    pub fn with_config(config: EcnValidationConfig) -> Self {
        Self {
            validation: EcnValidation::new(config),
            counters: EcnCounters::default(),
            last_reported_ce: 0,
            marking_history: VecDeque::new(),
            congestion_events: VecDeque::new(),
            max_history_size: 100,
            enabled: true,
            conservative_reaction: true,
        }
    }

    /// Enable or disable ECN usage
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if !enabled {
            protocol_event!(Level::Info, "ECN disabled");
        }
    }

    /// Check if ECN is enabled and validated
    pub fn is_ecn_capable(&self) -> bool {
        self.enabled && self.validation.is_capable()
    }

    /// Check if ECN validation has failed
    pub fn has_validation_failed(&self) -> bool {
        self.validation.has_failed()
    }

    /// Get ECN codepoint to use for outgoing packets
    pub fn outgoing_ecn_codepoint(&mut self, now: Instant) -> EcnCodepoint {
        if !self.enabled {
            return EcnCodepoint::NotEct;
        }

        match self.validation.state {
            EcnState::Unknown => {
                self.validation.start_validation(now);
                EcnCodepoint::Ect0
            }
            EcnState::Testing => {
                if self.validation.should_send_test_packet(now) {
                    self.validation.on_test_packet_sent(now);
                    EcnCodepoint::Ect0
                } else {
                    EcnCodepoint::NotEct
                }
            }
            EcnState::Capable => EcnCodepoint::Ect0,
            EcnState::Failed => EcnCodepoint::NotEct,
        }
    }

    /// Process received packet with ECN marking
    pub fn on_packet_received(&mut self, ecn: EcnCodepoint, now: Instant) {
        if !self.enabled {
            return;
        }

        // Update counters
        self.counters.update(ecn);

        // Update validation if in progress
        self.validation.on_ecn_packet_received(ecn, now);
        self.validation.check_validation_complete(now);

        // Track marking history
        if ecn.is_ce() {
            self.update_marking_history(now);
        }

        protocol_event!(
            Level::Trace,
            "ECN packet received";
            "ecn_codepoint" => format!("{:?}", ecn),
            "ce_count" => self.counters.ce_count,
            "marking_rate" => self.counters.marking_rate()
        );
    }

    /// Check for new congestion events and return them
    pub fn check_congestion_events(&mut self, bytes_in_flight: u64, now: Instant) -> Vec<EcnCongestionEvent> {
        if !self.is_ecn_capable() {
            return Vec::new();
        }

        let mut events = Vec::new();
        let current_ce = self.counters.ce_count;

        // Detect new CE marks
        if current_ce > self.last_reported_ce {
            let new_ce_marks = current_ce - self.last_reported_ce;
            
            let event = EcnCongestionEvent {
                timestamp: now,
                ce_count: new_ce_marks,
                marking_rate: self.counters.marking_rate(),
                bytes_in_flight,
            };

            events.push(event.clone());
            self.congestion_events.push_back(event);
            self.last_reported_ce = current_ce;

            // Limit congestion event history
            while self.congestion_events.len() > self.max_history_size {
                self.congestion_events.pop_front();
            }

            protocol_event!(
                Level::Info,
                "ECN congestion event detected";
                "new_ce_marks" => new_ce_marks,
                "total_ce" => current_ce,
                "marking_rate" => self.counters.marking_rate(),
                "bytes_in_flight" => bytes_in_flight
            );
        }

        events
    }

    /// Get current ECN statistics
    pub fn stats(&self) -> EcnStats {
        EcnStats {
            state: self.validation.state,
            enabled: self.enabled,
            counters: self.counters.clone(),
            marking_rate: self.counters.marking_rate(),
            validation_packets_sent: self.validation.packets_sent,
            congestion_events: self.congestion_events.len() as u64,
            total_marks: self.counters.total_marks(),
        }
    }

    /// Reset ECN state (for connection migration, etc.)
    pub fn reset(&mut self) {
        self.validation = EcnValidation::new(self.validation.config.clone());
        self.counters = EcnCounters::default();
        self.last_reported_ce = 0;
        self.marking_history.clear();
        self.congestion_events.clear();
        
        protocol_event!(Level::Info, "ECN state reset");
    }

    /// Get recent congestion event rate
    pub fn recent_congestion_rate(&self, window: Duration, now: Instant) -> f64 {
        let cutoff = now.saturating_sub(window);
        
        let recent_events: u64 = self.congestion_events
            .iter()
            .filter(|event| event.timestamp >= cutoff)
            .map(|event| event.ce_count)
            .sum();

        let total_recent_packets = self.marking_history
            .iter()
            .filter(|(timestamp, _)| *timestamp >= cutoff)
            .count() as u64;

        if total_recent_packets == 0 {
            0.0
        } else {
            recent_events as f64 / total_recent_packets as f64
        }
    }

    /// Check if ECN reaction should be conservative
    pub fn should_react_conservatively(&self) -> bool {
        self.conservative_reaction
    }

    // Private helper methods

    fn update_marking_history(&mut self, now: Instant) {
        self.marking_history.push_back((now, self.counters.ce_count));
        
        // Limit history size
        while self.marking_history.len() > self.max_history_size {
            self.marking_history.pop_front();
        }

        // Remove old entries (older than 30 seconds)
        let cutoff = now.saturating_sub(Duration::from_secs(30));
        while let Some((timestamp, _)) = self.marking_history.front() {
            if *timestamp < cutoff {
                self.marking_history.pop_front();
            } else {
                break;
            }
        }
    }
    
    /// Handle ACK received for ECN processing
    pub fn on_ack_received(&mut self, _bytes_acked: u64, _rtt: Duration) {
        // ECN processing is handled in process_ack_frame
        // This method is for compatibility with congestion control interface
    }
    
    /// Handle packet lost for ECN processing
    pub fn on_packet_lost(&mut self, _lost_bytes: u64) {
        // ECN loss processing would be handled elsewhere
        // This method is for compatibility with congestion control interface
    }
    
    /// Handle congestion event
    pub fn on_congestion_event(&mut self, _event: EcnCongestionEvent) {
        // Process congestion event - this is called from congestion controller
        // The actual work is done in check_congestion_events
    }
    
    /// Update ECN controller state
    pub fn update(&mut self) {
        let now = Instant::now();
        
        // Update marking history
        self.update_marking_history(now);
        
        // Check if validation timed out
        if matches!(self.validation.state, EcnState::Testing) {
            if let Some(start_time) = self.validation.validation_start {
                if now.duration_since(start_time) > self.validation.config.validation_timeout {
                    self.validation.state = EcnState::Failed;
                    protocol_event!(Level::Warn, "ECN validation timed out");
                }
            }
        }
    }
    
    /// Get total ECN marks
    pub fn total_marks(&self) -> u64 {
        self.counters.total_marks()
    }
}

impl Default for EcnController {
    fn default() -> Self {
        Self::new()
    }
}


/// ECN statistics
#[derive(Debug, Clone)]
pub struct EcnStats {
    /// Current ECN validation state
    pub state: EcnState,
    /// ECN enabled flag
    pub enabled: bool,
    /// ECN counters
    pub counters: EcnCounters,
    /// Current marking rate
    pub marking_rate: f64,
    /// Validation packets sent
    pub validation_packets_sent: u32,
    /// Total congestion events detected
    pub congestion_events: u64,
    /// Total ECN marks
    pub total_marks: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecn_codepoint_conversion() {
        assert_eq!(EcnCodepoint::from_bits(0b00), Some(EcnCodepoint::NotEct));
        assert_eq!(EcnCodepoint::from_bits(0b01), Some(EcnCodepoint::Ect1));
        assert_eq!(EcnCodepoint::from_bits(0b10), Some(EcnCodepoint::Ect0));
        assert_eq!(EcnCodepoint::from_bits(0b11), Some(EcnCodepoint::Ce));

        assert_eq!(EcnCodepoint::NotEct.to_bits(), 0b00);
        assert_eq!(EcnCodepoint::Ect1.to_bits(), 0b01);
        assert_eq!(EcnCodepoint::Ect0.to_bits(), 0b10);
        assert_eq!(EcnCodepoint::Ce.to_bits(), 0b11);
    }

    #[test]
    fn test_ecn_codepoint_properties() {
        assert!(!EcnCodepoint::NotEct.is_ect());
        assert!(EcnCodepoint::Ect0.is_ect());
        assert!(EcnCodepoint::Ect1.is_ect());
        assert!(!EcnCodepoint::Ce.is_ect());

        assert!(!EcnCodepoint::NotEct.is_ce());
        assert!(!EcnCodepoint::Ect0.is_ce());
        assert!(!EcnCodepoint::Ect1.is_ce());
        assert!(EcnCodepoint::Ce.is_ce());
    }

    #[test]
    fn test_ecn_counters() {
        let mut counters = EcnCounters::default();
        
        assert_eq!(counters.total_marks(), 0);
        assert_eq!(counters.marking_rate(), 0.0);

        counters.update(EcnCodepoint::Ect0);
        counters.update(EcnCodepoint::Ect1);
        counters.update(EcnCodepoint::Ce);
        counters.update(EcnCodepoint::NotEct);

        assert_eq!(counters.ect0_count, 1);
        assert_eq!(counters.ect1_count, 1);
        assert_eq!(counters.ce_count, 1);
        assert_eq!(counters.total_ect_count, 3);
        assert_eq!(counters.total_marks(), 1);
        assert!((counters.marking_rate() - (1.0 / 3.0)).abs() < 0.001);
    }

    #[test]
    fn test_ecn_controller_initialization() {
        let controller = EcnController::new();
        
        assert!(!controller.is_ecn_capable()); // Not validated yet
        assert!(!controller.has_validation_failed());
        
        let stats = controller.stats();
        assert_eq!(stats.state, EcnState::Unknown);
        assert!(stats.enabled);
    }

    #[test]
    fn test_ecn_validation_start() {
        let mut controller = EcnController::new();
        let now = Instant::now();
        
        // First outgoing packet should start validation
        let ecn = controller.outgoing_ecn_codepoint(now);
        assert_eq!(ecn, EcnCodepoint::Ect0);
        assert_eq!(controller.validation.state, EcnState::Testing);
    }

    #[test]
    fn test_ecn_disabled() {
        let mut controller = EcnController::new();
        controller.set_enabled(false);
        let now = Instant::now();
        
        let ecn = controller.outgoing_ecn_codepoint(now);
        assert_eq!(ecn, EcnCodepoint::NotEct);
        assert!(!controller.is_ecn_capable());
    }

    #[test]
    fn test_ecn_congestion_detection() {
        let mut controller = EcnController::new();
        let now = Instant::now();
        
        // Set to capable state
        controller.validation.state = EcnState::Capable;
        
        // Process CE-marked packet
        controller.on_packet_received(EcnCodepoint::Ce, now);
        
        let events = controller.check_congestion_events(1000, now);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].ce_count, 1);
        assert_eq!(events[0].bytes_in_flight, 1000);
    }

    #[test]
    fn test_ecn_validation_success() {
        let config = EcnValidationConfig {
            validation_packets: 3,
            min_ecn_packets: 2,
            ..Default::default()
        };
        
        let mut controller = EcnController::with_config(config);
        let now = Instant::now();
        
        // Start validation
        controller.outgoing_ecn_codepoint(now);
        assert_eq!(controller.validation.state, EcnState::Testing);
        
        // Send validation packets and receive ECN responses
        for _ in 0..3 {
            controller.validation.on_test_packet_sent(now);
            controller.on_packet_received(EcnCodepoint::Ect0, now);
        }
        
        // Should be capable now
        assert_eq!(controller.validation.state, EcnState::Capable);
        assert!(controller.is_ecn_capable());
    }

    #[test]
    fn test_ecn_validation_failure() {
        let config = EcnValidationConfig {
            validation_packets: 3,
            min_ecn_packets: 2,
            ..Default::default()
        };
        
        let mut controller = EcnController::with_config(config);
        let now = Instant::now();
        
        // Start validation
        controller.outgoing_ecn_codepoint(now);
        
        // Send validation packets but receive no ECN responses
        for _ in 0..3 {
            controller.validation.on_test_packet_sent(now);
            controller.on_packet_received(EcnCodepoint::NotEct, now);
        }
        
        // Complete validation manually
        controller.validation.complete_validation();
        
        // Should have failed
        assert_eq!(controller.validation.state, EcnState::Failed);
        assert!(controller.has_validation_failed());
        assert!(!controller.is_ecn_capable());
    }

    #[test]
    fn test_ecn_marking_rate_calculation() {
        let mut controller = EcnController::new();
        let now = Instant::now();
        
        // Process mixed ECN packets
        controller.on_packet_received(EcnCodepoint::Ect0, now);
        controller.on_packet_received(EcnCodepoint::Ect0, now);
        controller.on_packet_received(EcnCodepoint::Ce, now);
        controller.on_packet_received(EcnCodepoint::Ect0, now);
        
        let stats = controller.stats();
        assert_eq!(stats.counters.total_ect_count, 4);
        assert_eq!(stats.counters.ce_count, 1);
        assert!((stats.marking_rate - 0.25).abs() < 0.001);
    }
}