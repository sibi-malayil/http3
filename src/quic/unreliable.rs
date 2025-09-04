//! QUIC Unreliable Delivery Implementation
//!
//! This module implements unreliable data transmission mechanisms for QUIC,
//! supporting HTTP/3 datagrams and providing the transport-level foundation
//! for unreliable delivery protocols like WebTransport.
//!
//! Features:
//! - Unreliable datagram transmission
//! - No retransmission guarantees
//! - Congestion control integration
//! - Flow control respecting
//! - Packet loss tolerance

use crate::{
    error::{Result, ConnectionErrorCode},
    error_context::ErrorConversion,
    quic::{
        packet::{ConnectionId},
        connection::ConnectionRole,
        congestion::CongestionController,
    },
    util::time::Instant,
    whathappened::Level,
    protocol_event,
};
use bytes::Bytes;
use std::collections::VecDeque;

/// Maximum datagram size for unreliable delivery
const MAX_UNRELIABLE_DATAGRAM_SIZE: usize = 1200;

/// Default maximum queued datagrams per connection
const DEFAULT_MAX_QUEUED_DATAGRAMS: usize = 100;

/// Unreliable delivery configuration
#[derive(Debug, Clone)]
pub struct UnreliableConfig {
    /// Enable unreliable delivery
    pub enabled: bool,
    /// Maximum datagram size
    pub max_datagram_size: usize,
    /// Maximum number of queued datagrams
    pub max_queued_datagrams: usize,
    /// Respect congestion control for unreliable datagrams
    pub respect_congestion_control: bool,
    /// Maximum burst size for datagram transmission
    pub max_burst_size: usize,
    /// Enable statistics collection
    pub collect_stats: bool,
}

impl Default for UnreliableConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_datagram_size: MAX_UNRELIABLE_DATAGRAM_SIZE,
            max_queued_datagrams: DEFAULT_MAX_QUEUED_DATAGRAMS,
            respect_congestion_control: true,
            max_burst_size: 10,
            collect_stats: true,
        }
    }
}

/// Unreliable delivery statistics
#[derive(Debug, Clone, Default)]
pub struct UnreliableStats {
    /// Total datagrams sent
    pub datagrams_sent: u64,
    /// Total datagrams received
    pub datagrams_received: u64,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Datagrams dropped due to queue full
    pub dropped_queue_full: u64,
    /// Datagrams dropped due to size limit
    pub dropped_too_large: u64,
    /// Datagrams dropped due to congestion control
    pub dropped_congestion: u64,
    /// Current queue size
    pub current_queue_size: usize,
    /// Peak queue size
    pub peak_queue_size: usize,
    /// Average datagram size
    pub avg_datagram_size: f64,
}

/// Queued datagram for unreliable transmission
#[derive(Debug, Clone)]
struct QueuedDatagram {
    /// Datagram data
    data: Bytes,
    /// Time when datagram was queued
    queued_at: Instant,
    /// Priority (0 = highest, higher values = lower priority)
    priority: u8,
    /// Source identifier (for debugging/tracking)
    source_id: Option<u64>,
}

impl QueuedDatagram {
    fn new(data: Bytes, priority: u8, source_id: Option<u64>) -> Self {
        Self {
            data,
            queued_at: Instant::now(),
            priority,
            source_id,
        }
    }

    fn age(&self) -> crate::util::time::Duration {
        self.queued_at.elapsed()
    }
}

/// Result of unreliable datagram transmission attempt
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnreliableResult {
    /// Datagram was sent immediately
    Sent,
    /// Datagram was queued for later transmission
    Queued,
    /// Datagram was dropped due to size constraints
    TooLarge,
    /// Datagram was dropped due to queue being full
    QueueFull,
    /// Datagram was dropped due to congestion control
    CongestionDropped,
    /// Unreliable delivery not enabled
    NotEnabled,
    /// Connection not ready for datagram transmission
    NotReady,
}

/// Received unreliable datagram
#[derive(Debug, Clone)]
pub struct ReceivedDatagram {
    /// Connection ID that received the datagram
    pub connection_id: ConnectionId,
    /// Datagram data
    pub data: Bytes,
    /// Time when datagram was received
    pub received_at: Instant,
    /// Size of the datagram
    pub size: usize,
}

/// QUIC Unreliable Delivery Manager
///
/// Manages unreliable datagram transmission and reception over QUIC connections.
/// Integrates with congestion control and provides backpressure mechanisms.
#[derive(Debug)]
pub struct UnreliableDeliveryManager {
    /// Configuration
    config: UnreliableConfig,
    /// Outgoing datagram queue (priority-based)
    outgoing_queue: VecDeque<QueuedDatagram>,
    /// Statistics
    stats: UnreliableStats,
    /// Recent received datagrams for application processing
    received_datagrams: VecDeque<ReceivedDatagram>,
    /// Connection state tracking
    connection_ready: bool,
    /// Connection role
    connection_role: ConnectionRole,
    /// Last transmission time (for rate limiting)
    last_transmission: Option<Instant>,
    /// Transmission burst counter
    current_burst_count: usize,
    /// Burst window start time
    burst_window_start: Option<Instant>,
}

impl UnreliableDeliveryManager {
    /// Create a new unreliable delivery manager
    pub fn new(config: UnreliableConfig, connection_role: ConnectionRole) -> Self {
        Self {
            config,
            outgoing_queue: VecDeque::new(),
            stats: UnreliableStats::default(),
            received_datagrams: VecDeque::new(),
            connection_ready: false,
            connection_role,
            last_transmission: None,
            current_burst_count: 0,
            burst_window_start: None,
        }
    }

    /// Create manager with default configuration
    pub fn default_for_role(connection_role: ConnectionRole) -> Self {
        Self::new(UnreliableConfig::default(), connection_role)
    }

    /// Check if unreliable delivery is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Set connection readiness for datagram transmission
    pub fn set_connection_ready(&mut self, ready: bool) {
        let was_ready = self.connection_ready;
        self.connection_ready = ready;
        
        if ready && !was_ready {
            protocol_event!(
                Level::Info,
                "Unreliable delivery enabled for connection";
                "connection_role" => self.connection_role,
                "queue_size" => self.outgoing_queue.len()
            );
        } else if !ready && was_ready {
            protocol_event!(
                Level::Info,
                "Unreliable delivery disabled for connection";
                "connection_role" => self.connection_role,
                "dropped_datagrams" => self.outgoing_queue.len()
            );
            
            // Clear queue when connection becomes not ready
            let dropped_count = self.outgoing_queue.len();
            self.outgoing_queue.clear();
            self.stats.dropped_congestion += dropped_count as u64;
        }
    }

    /// Send an unreliable datagram
    pub fn send_datagram(
        &mut self,
        data: Bytes,
        priority: u8,
        source_id: Option<u64>,
        congestion_controller: Option<&CongestionController>,
    ) -> UnreliableResult {
        if !self.config.enabled {
            return UnreliableResult::NotEnabled;
        }

        if !self.connection_ready {
            return UnreliableResult::NotReady;
        }

        // Check size limit
        if data.len() > self.config.max_datagram_size {
            self.stats.dropped_too_large += 1;
            protocol_event!(
                Level::Warn,
                "Unreliable datagram dropped - too large";
                "size" => data.len(),
                "max_size" => self.config.max_datagram_size,
                "source_id" => source_id
            );
            return UnreliableResult::TooLarge;
        }

        // Check congestion control if enabled and available
        if self.config.respect_congestion_control {
            if let Some(cc) = congestion_controller {
                // Use a conservative approach - if congestion window is small, drop datagram
                let sending_window = cc.sending_window(0); // Assuming no bytes in flight for simplicity
                if sending_window < data.len() as u64 * 2 {
                    self.stats.dropped_congestion += 1;
                    protocol_event!(
                        Level::Debug,
                        "Unreliable datagram dropped - congestion control";
                        "sending_window" => sending_window,
                        "congestion_window" => cc.congestion_window(),
                        "data_size" => data.len(),
                        "source_id" => source_id
                    );
                    return UnreliableResult::CongestionDropped;
                }
            }
        }

        // Check queue limit
        if self.outgoing_queue.len() >= self.config.max_queued_datagrams {
            // Drop the oldest, lowest priority datagram
            if let Some(pos) = self.find_droppable_datagram() {
                let dropped = self.outgoing_queue.remove(pos);
                protocol_event!(
                    Level::Debug,
                    "Dropped queued datagram to make room";
                    "dropped_age_ms" => dropped.as_ref().unwrap().age().as_millis(),
                    "dropped_priority" => dropped.as_ref().unwrap().priority,
                    "dropped_size" => dropped.as_ref().unwrap().data.len()
                );
            } else {
                self.stats.dropped_queue_full += 1;
                protocol_event!(
                    Level::Warn,
                    "Unreliable datagram dropped - queue full";
                    "queue_size" => self.outgoing_queue.len(),
                    "max_queue_size" => self.config.max_queued_datagrams,
                    "source_id" => source_id
                );
                return UnreliableResult::QueueFull;
            }
        }

        // Queue the datagram
        let queued_datagram = QueuedDatagram::new(data.clone(), priority, source_id);
        
        // Insert in priority order (lower priority value = higher priority)
        let insert_pos = self.outgoing_queue
            .iter()
            .position(|d| d.priority > priority)
            .unwrap_or(self.outgoing_queue.len());
        
        self.outgoing_queue.insert(insert_pos, queued_datagram);

        // Update statistics
        self.stats.current_queue_size = self.outgoing_queue.len();
        self.stats.peak_queue_size = self.stats.peak_queue_size.max(self.stats.current_queue_size);

        protocol_event!(
            Level::Debug,
            "Unreliable datagram queued";
            "size" => data.len(),
            "priority" => priority,
            "queue_size" => self.outgoing_queue.len(),
            "queue_position" => insert_pos,
            "source_id" => source_id
        );

        UnreliableResult::Queued
    }

    /// Get the next datagram to transmit
    pub fn next_datagram(&mut self) -> Option<Bytes> {
        if !self.config.enabled || !self.connection_ready {
            return None;
        }

        // Check burst limits
        if !self.can_send_in_burst() {
            return None;
        }

        if let Some(queued) = self.outgoing_queue.pop_front() {
            let data = queued.data.clone();
            let size = data.len();

            // Update statistics
            self.stats.datagrams_sent += 1;
            self.stats.bytes_sent += size as u64;
            self.stats.current_queue_size = self.outgoing_queue.len();
            
            // Update average datagram size
            let total_datagrams = self.stats.datagrams_sent;
            self.stats.avg_datagram_size = 
                ((self.stats.avg_datagram_size * (total_datagrams - 1) as f64) + size as f64) / total_datagrams as f64;

            // Update burst tracking
            self.update_burst_tracking();

            protocol_event!(
                Level::Debug,
                "Sending unreliable datagram";
                "size" => size,
                "queue_latency_ms" => queued.age().as_millis(),
                "priority" => queued.priority,
                "remaining_queue_size" => self.outgoing_queue.len(),
                "source_id" => queued.source_id
            );

            Some(data)
        } else {
            None
        }
    }

    /// Process a received unreliable datagram
    pub fn on_datagram_received(&mut self, connection_id: &ConnectionId, data: Bytes) -> Result<()> {
        if !self.config.enabled {
            return Err("Unreliable delivery not enabled".to_connection_error(ConnectionErrorCode::InternalError));
        }

        let received = ReceivedDatagram {
            connection_id: connection_id.clone(),
            data: data.clone(),
            received_at: Instant::now(),
            size: data.len(),
        };

        // Store for application processing
        self.received_datagrams.push_back(received);
        
        // Limit received datagram buffer size
        while self.received_datagrams.len() > 1000 {
            self.received_datagrams.pop_front();
        }

        // Update statistics
        self.stats.datagrams_received += 1;
        self.stats.bytes_received += data.len() as u64;

        protocol_event!(
            Level::Debug,
            "Unreliable datagram received";
            "connection_id" => format!("{:?}", connection_id),
            "size" => data.len(),
            "total_received" => self.stats.datagrams_received
        );

        Ok(())
    }

    /// Get the next received datagram
    pub fn next_received_datagram(&mut self) -> Option<ReceivedDatagram> {
        self.received_datagrams.pop_front()
    }

    /// Check if there are pending datagrams to send
    pub fn has_pending_datagrams(&self) -> bool {
        !self.outgoing_queue.is_empty()
    }

    /// Get the number of pending datagrams
    pub fn pending_datagram_count(&self) -> usize {
        self.outgoing_queue.len()
    }

    /// Get current statistics
    pub fn stats(&self) -> UnreliableStats {
        let mut stats = self.stats.clone();
        stats.current_queue_size = self.outgoing_queue.len();
        stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = UnreliableStats::default();
        self.stats.current_queue_size = self.outgoing_queue.len();
    }

    /// Update configuration
    pub fn update_config(&mut self, config: UnreliableConfig) {
        let was_enabled = self.config.enabled;
        self.config = config;
        
        // If disabled, clear queues
        if was_enabled && !self.config.enabled {
            let dropped_count = self.outgoing_queue.len();
            self.outgoing_queue.clear();
            self.received_datagrams.clear();
            
            if dropped_count > 0 {
                protocol_event!(
                    Level::Info,
                    "Unreliable delivery disabled - clearing queues";
                    "dropped_outgoing" => dropped_count
                );
            }
        }
        
        // Enforce new queue size limit
        while self.outgoing_queue.len() > self.config.max_queued_datagrams {
            if let Some(pos) = self.find_droppable_datagram() {
                self.outgoing_queue.remove(pos);
            } else {
                break;
            }
        }
    }

    /// Get configuration
    pub fn config(&self) -> &UnreliableConfig {
        &self.config
    }

    /// Clear all pending datagrams
    pub fn clear_pending(&mut self) {
        let dropped_count = self.outgoing_queue.len();
        self.outgoing_queue.clear();
        self.stats.current_queue_size = 0;
        
        if dropped_count > 0 {
            protocol_event!(
                Level::Info,
                "Cleared all pending unreliable datagrams";
                "dropped_count" => dropped_count
            );
        }
    }

    // Private helper methods

    /// Find a datagram that can be dropped (oldest, lowest priority)
    fn find_droppable_datagram(&self) -> Option<usize> {
        if self.outgoing_queue.is_empty() {
            return None;
        }

        // Find the oldest datagram with the lowest priority
        let mut oldest_pos = 0;
        let mut oldest_time = self.outgoing_queue[0].queued_at;
        let mut lowest_priority = self.outgoing_queue[0].priority;

        for (i, datagram) in self.outgoing_queue.iter().enumerate().skip(1) {
            if datagram.priority > lowest_priority || 
               (datagram.priority == lowest_priority && datagram.queued_at < oldest_time) {
                oldest_pos = i;
                oldest_time = datagram.queued_at;
                lowest_priority = datagram.priority;
            }
        }

        Some(oldest_pos)
    }

    /// Check if we can send another datagram in the current burst
    fn can_send_in_burst(&self) -> bool {
        let now = Instant::now();
        
        // Check if we're in a new burst window (1 second)
        if let Some(window_start) = self.burst_window_start {
            if now.duration_since(window_start).as_secs() >= 1 {
                return true; // New window, reset burst counter
            }
        } else {
            return true; // No burst tracking yet
        }

        // Check if we've exceeded burst limit
        self.current_burst_count < self.config.max_burst_size
    }

    /// Update burst tracking after sending a datagram
    fn update_burst_tracking(&mut self) {
        let now = Instant::now();
        
        // Check if we need to start a new burst window
        if let Some(window_start) = self.burst_window_start {
            if now.duration_since(window_start).as_secs() >= 1 {
                // New window
                self.burst_window_start = Some(now);
                self.current_burst_count = 1;
            } else {
                // Same window
                self.current_burst_count += 1;
            }
        } else {
            // First transmission
            self.burst_window_start = Some(now);
            self.current_burst_count = 1;
        }
        
        self.last_transmission = Some(now);
    }
}

impl Default for UnreliableDeliveryManager {
    fn default() -> Self {
        Self::new(UnreliableConfig::default(), ConnectionRole::Client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::congestion::CongestionController;

    #[test]
    fn test_unreliable_manager_creation() {
        let manager = UnreliableDeliveryManager::default_for_role(ConnectionRole::Client);
        assert!(manager.is_enabled());
        assert_eq!(manager.pending_datagram_count(), 0);
        assert!(!manager.has_pending_datagrams());
    }

    #[test]
    fn test_datagram_queuing() {
        let mut manager = UnreliableDeliveryManager::default_for_role(ConnectionRole::Client);
        manager.set_connection_ready(true);
        
        let data = Bytes::from_static(b"test datagram");
        let result = manager.send_datagram(data.clone(), 1, Some(42), None);
        assert_eq!(result, UnreliableResult::Queued);
        assert_eq!(manager.pending_datagram_count(), 1);
        assert!(manager.has_pending_datagrams());

        // Get the datagram back
        let sent_data = manager.next_datagram().unwrap();
        assert_eq!(sent_data, data);
        assert_eq!(manager.pending_datagram_count(), 0);
    }

    #[test]
    fn test_priority_ordering() {
        let mut manager = UnreliableDeliveryManager::default_for_role(ConnectionRole::Client);
        manager.set_connection_ready(true);
        
        // Send datagrams with different priorities (lower number = higher priority)
        manager.send_datagram(Bytes::from_static(b"low priority"), 5, None, None);
        manager.send_datagram(Bytes::from_static(b"high priority"), 1, None, None);
        manager.send_datagram(Bytes::from_static(b"medium priority"), 3, None, None);
        
        // Should get high priority first
        assert_eq!(manager.next_datagram().unwrap(), Bytes::from_static(b"high priority"));
        assert_eq!(manager.next_datagram().unwrap(), Bytes::from_static(b"medium priority"));
        assert_eq!(manager.next_datagram().unwrap(), Bytes::from_static(b"low priority"));
    }

    #[test]
    fn test_size_limits() {
        let config = UnreliableConfig {
            max_datagram_size: 10,
            ..Default::default()
        };
        let mut manager = UnreliableDeliveryManager::new(config, ConnectionRole::Client);
        manager.set_connection_ready(true);
        
        // Small datagram should work
        let small_data = Bytes::from(vec![0u8; 5]);
        assert_eq!(manager.send_datagram(small_data, 1, None, None), UnreliableResult::Queued);
        
        // Large datagram should be rejected
        let large_data = Bytes::from(vec![0u8; 20]);
        assert_eq!(manager.send_datagram(large_data, 1, None, None), UnreliableResult::TooLarge);
        
        let stats = manager.stats();
        assert_eq!(stats.dropped_too_large, 1);
    }

    #[test]
    fn test_queue_limits() {
        let config = UnreliableConfig {
            max_queued_datagrams: 2,
            ..Default::default()
        };
        let mut manager = UnreliableDeliveryManager::new(config, ConnectionRole::Client);
        manager.set_connection_ready(true);
        
        let data = Bytes::from_static(b"test");
        
        // Fill the queue
        assert_eq!(manager.send_datagram(data.clone(), 1, None, None), UnreliableResult::Queued);
        assert_eq!(manager.send_datagram(data.clone(), 2, None, None), UnreliableResult::Queued);
        
        // Next one should cause oldest to be dropped (since it has lower priority)
        assert_eq!(manager.send_datagram(data.clone(), 0, None, None), UnreliableResult::Queued);
        assert_eq!(manager.pending_datagram_count(), 2);
        
        // Should get the highest priority datagrams
        assert_eq!(manager.next_datagram().unwrap(), data);  // priority 0
        assert_eq!(manager.next_datagram().unwrap(), data);  // priority 2 (priority 1 was dropped)
    }

    #[test]
    fn test_congestion_control_integration() {
        let mut manager = UnreliableDeliveryManager::default_for_role(ConnectionRole::Client);
        manager.set_connection_ready(true);
        
        let mut cc = CongestionController::new();
        // Simulate high congestion
        cc.on_packet_sent(1000);
        
        let data = Bytes::from_static(b"test");
        let result = manager.send_datagram(data, 1, None, Some(&cc));
        
        // Should be dropped due to congestion
        assert_eq!(result, UnreliableResult::CongestionDropped);
        
        let stats = manager.stats();
        assert_eq!(stats.dropped_congestion, 1);
    }

    #[test]
    fn test_received_datagram_processing() {
        let mut manager = UnreliableDeliveryManager::default_for_role(ConnectionRole::Server);
        let connection_id = ConnectionId::from(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let data = Bytes::from_static(b"received test data");
        
        manager.on_datagram_received(&connection_id, data.clone()).unwrap();
        
        let received = manager.next_received_datagram().unwrap();
        assert_eq!(received.connection_id, connection_id);
        assert_eq!(received.data, data);
        assert_eq!(received.size, data.len());
        
        let stats = manager.stats();
        assert_eq!(stats.datagrams_received, 1);
        assert_eq!(stats.bytes_received, data.len() as u64);
    }

    #[test]
    fn test_connection_readiness() {
        let mut manager = UnreliableDeliveryManager::default_for_role(ConnectionRole::Client);
        
        // Initially not ready
        let data = Bytes::from_static(b"test");
        assert_eq!(manager.send_datagram(data.clone(), 1, None, None), UnreliableResult::NotReady);
        
        // Make ready
        manager.set_connection_ready(true);
        assert_eq!(manager.send_datagram(data.clone(), 1, None, None), UnreliableResult::Queued);
        
        // Make not ready again - should clear queue
        manager.set_connection_ready(false);
        assert_eq!(manager.pending_datagram_count(), 0);
        assert_eq!(manager.send_datagram(data, 1, None, None), UnreliableResult::NotReady);
    }

    #[test]
    fn test_statistics_tracking() {
        let mut manager = UnreliableDeliveryManager::default_for_role(ConnectionRole::Client);
        manager.set_connection_ready(true);
        
        let data1 = Bytes::from(vec![1u8; 100]);
        let data2 = Bytes::from(vec![2u8; 200]);
        
        // Send some datagrams
        manager.send_datagram(data1.clone(), 1, None, None);
        manager.send_datagram(data2.clone(), 1, None, None);
        
        // Transmit them
        manager.next_datagram();
        manager.next_datagram();
        
        let stats = manager.stats();
        assert_eq!(stats.datagrams_sent, 2);
        assert_eq!(stats.bytes_sent, 300);
        assert_eq!(stats.avg_datagram_size, 150.0);
        assert_eq!(stats.peak_queue_size, 2);
        assert_eq!(stats.current_queue_size, 0);
    }
}