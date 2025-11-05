//! HTTP/3 Datagram Support (RFC 9297)
//!
//! This module implements HTTP datagrams as specified in RFC 9297:
//! "HTTP Datagrams and the Capsule Protocol"
//!
//! HTTP datagrams provide an unreliable data transmission mechanism
//! that can be used for applications requiring low-latency communication
//! where reliability is less important than speed.

use crate::{
    error::{Result, Http3ErrorCode},
    error_context::ErrorConversion,
    http3::frame::{DatagramFrame, Http3Frame},
    quic::stream::StreamId,
    util::time::Instant,
    whathappened::Level,
    protocol_event,
};
use bytes::Bytes;
use std::collections::{HashMap, VecDeque};

/// Maximum datagram queue size per endpoint
const MAX_DATAGRAM_QUEUE_SIZE: usize = 1000;

/// Maximum datagram size (should be smaller than path MTU)
const MAX_DATAGRAM_SIZE: usize = 1200;

/// Datagram transmission result
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DatagramResult {
    /// Datagram was sent successfully
    Sent,
    /// Datagram was queued for later transmission
    Queued,
    /// Datagram was dropped due to size constraints
    TooLarge,
    /// Datagram was dropped due to queue full
    QueueFull,
    /// Datagram support not enabled
    NotSupported,
}

/// Datagram receive event
#[derive(Debug, Clone)]
pub struct DatagramReceived {
    /// Stream ID the datagram was received on
    pub stream_id: StreamId,
    /// Datagram data
    pub data: Bytes,
    /// Time when datagram was received
    pub received_at: Instant,
}

/// Configuration for datagram support
#[derive(Debug, Clone)]
pub struct DatagramConfig {
    /// Enable datagram support
    pub enabled: bool,
    /// Maximum datagram size
    pub max_datagram_size: usize,
    /// Maximum number of datagrams to queue per endpoint
    pub max_queue_size: usize,
    /// Enable datagram statistics collection
    pub collect_stats: bool,
}

impl Default for DatagramConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_datagram_size: MAX_DATAGRAM_SIZE,
            max_queue_size: MAX_DATAGRAM_QUEUE_SIZE,
            collect_stats: true,
        }
    }
}

/// Datagram statistics
#[derive(Debug, Clone, Default)]
pub struct DatagramStats {
    /// Total datagrams sent
    pub datagrams_sent: u64,
    /// Total datagrams received
    pub datagrams_received: u64,
    /// Total bytes sent via datagrams
    pub bytes_sent: u64,
    /// Total bytes received via datagrams
    pub bytes_received: u64,
    /// Datagrams dropped due to size
    pub dropped_too_large: u64,
    /// Datagrams dropped due to queue full
    pub dropped_queue_full: u64,
    /// Current queue size
    pub queue_size: usize,
}

/// Pending datagram for transmission
#[derive(Debug, Clone)]
struct PendingDatagram {
    /// Datagram data
    data: Bytes,
    /// Stream ID to send on
    stream_id: StreamId,
    /// Time when datagram was queued
    queued_at: Instant,
}

/// HTTP/3 Datagram Manager
///
/// Manages unreliable datagram transmission and reception according to RFC 9297
#[derive(Debug)]
pub struct DatagramManager {
    /// Configuration
    config: DatagramConfig,
    /// Pending outgoing datagrams per stream
    outgoing_queue: HashMap<StreamId, VecDeque<PendingDatagram>>,
    /// Statistics
    stats: DatagramStats,
    /// Recent received datagrams for debugging
    recent_received: VecDeque<DatagramReceived>,
}

impl DatagramManager {
    /// Create a new datagram manager
    pub fn new(config: DatagramConfig) -> Self {
        Self {
            config,
            outgoing_queue: HashMap::new(),
            stats: DatagramStats::default(),
            recent_received: VecDeque::with_capacity(100),
        }
    }

    /// Create datagram manager with default configuration
    pub fn default() -> Self {
        Self::new(DatagramConfig::default())
    }

    /// Check if datagram support is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Send a datagram on a specific stream
    pub fn send_datagram(&mut self, stream_id: StreamId, data: Bytes) -> DatagramResult {
        if !self.config.enabled {
            return DatagramResult::NotSupported;
        }

        // Check size limit
        if data.len() > self.config.max_datagram_size {
            self.stats.dropped_too_large += 1;
            protocol_event!(
                Level::Warn,
                "Datagram dropped - too large";
                "size" => data.len(),
                "max_size" => self.config.max_datagram_size,
                "stream_id" => stream_id.into_inner()
            );
            return DatagramResult::TooLarge;
        }

        // Get or create queue for this stream
        let queue = self.outgoing_queue.entry(stream_id).or_default();

        // Check queue limit
        if queue.len() >= self.config.max_queue_size {
            self.stats.dropped_queue_full += 1;
            protocol_event!(
                Level::Warn,
                "Datagram dropped - queue full";
                "queue_size" => queue.len(),
                "max_queue_size" => self.config.max_queue_size,
                "stream_id" => stream_id.into_inner()
            );
            return DatagramResult::QueueFull;
        }

        // Queue the datagram
        let pending = PendingDatagram {
            data,
            stream_id,
            queued_at: Instant::now(),
        };

        let data_len = pending.data.len();
        queue.push_back(pending);
        let queue_len = queue.len();
        self.stats.queue_size = self.total_queue_size();

        protocol_event!(
            Level::Debug,
            "Datagram queued for transmission";
            "size" => data_len,
            "stream_id" => stream_id.into_inner(),
            "queue_size" => queue_len
        );

        DatagramResult::Queued
    }

    /// Get the next datagram frame to send
    pub fn next_datagram_frame(&mut self, stream_id: StreamId) -> Option<Http3Frame> {
        if !self.config.enabled {
            return None;
        }

        if let Some(queue) = self.outgoing_queue.get_mut(&stream_id) {
            if let Some(pending) = queue.pop_front() {
                let frame = DatagramFrame::new(pending.data.clone());
                
                // Update statistics
                if self.config.collect_stats {
                    self.stats.datagrams_sent += 1;
                    self.stats.bytes_sent += pending.data.len() as u64;
                    self.stats.queue_size = self.total_queue_size();
                }

                protocol_event!(
                    Level::Debug,
                    "Sending datagram frame";
                    "size" => pending.data.len(),
                    "stream_id" => stream_id.into_inner(),
                    "queue_latency_ms" => pending.queued_at.elapsed().as_millis()
                );

                return Some(Http3Frame::Datagram(frame));
            }
        }

        None
    }

    /// Process received datagram frame
    pub fn on_datagram_received(&mut self, stream_id: StreamId, frame: DatagramFrame) -> Result<()> {
        if !self.config.enabled {
            return Err("Datagram support not enabled".to_http3_error(Http3ErrorCode::InternalError));
        }

        let received = DatagramReceived {
            stream_id,
            data: frame.data.clone(),
            received_at: Instant::now(),
        };

        // Update statistics
        if self.config.collect_stats {
            self.stats.datagrams_received += 1;
            self.stats.bytes_received += frame.data.len() as u64;
        }

        // Store recent received datagrams (for debugging/testing)
        self.recent_received.push_back(received);
        while self.recent_received.len() > 100 {
            self.recent_received.pop_front();
        }

        protocol_event!(
            Level::Debug,
            "Datagram received";
            "size" => frame.data.len(),
            "stream_id" => stream_id.into_inner()
        );

        Ok(())
    }

    /// Get the next received datagram
    pub fn next_received_datagram(&mut self) -> Option<DatagramReceived> {
        self.recent_received.pop_front()
    }

    /// Check if there are pending datagrams for a stream
    pub fn has_pending_datagrams(&self, stream_id: StreamId) -> bool {
        self.outgoing_queue
            .get(&stream_id)
            .map(|queue| !queue.is_empty())
            .unwrap_or(false)
    }

    /// Get number of pending datagrams for a stream
    pub fn pending_datagram_count(&self, stream_id: StreamId) -> usize {
        self.outgoing_queue
            .get(&stream_id)
            .map(|queue| queue.len())
            .unwrap_or(0)
    }

    /// Get total number of pending datagrams across all streams
    pub fn total_pending_datagrams(&self) -> usize {
        self.outgoing_queue.values().map(|queue| queue.len()).sum()
    }

    /// Clear all pending datagrams for a stream
    pub fn clear_pending_datagrams(&mut self, stream_id: StreamId) {
        if let Some(queue) = self.outgoing_queue.remove(&stream_id) {
            let dropped_count = queue.len();
            self.stats.queue_size = self.total_queue_size();
            
            if dropped_count > 0 {
                protocol_event!(
                    Level::Info,
                    "Cleared pending datagrams";
                    "stream_id" => stream_id.into_inner(),
                    "dropped_count" => dropped_count
                );
            }
        }
    }

    /// Get current statistics
    pub fn stats(&self) -> DatagramStats {
        let mut stats = self.stats.clone();
        stats.queue_size = self.total_queue_size();
        stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = DatagramStats::default();
        self.stats.queue_size = self.total_queue_size();
    }

    /// Update configuration
    pub fn update_config(&mut self, config: DatagramConfig) {
        let was_enabled = self.config.enabled;
        self.config = config;
        
        // If disabling, clear all queues
        if was_enabled && !self.config.enabled {
            let total_dropped = self.total_pending_datagrams();
            self.outgoing_queue.clear();
            
            if total_dropped > 0 {
                protocol_event!(
                    Level::Info,
                    "Datagram support disabled - clearing queues";
                    "dropped_count" => total_dropped
                );
            }
        }
    }

    /// Get configuration
    pub fn config(&self) -> &DatagramConfig {
        &self.config
    }

    // Private helper methods

    fn total_queue_size(&self) -> usize {
        self.outgoing_queue.values().map(|queue| queue.len()).sum()
    }
}

impl Default for DatagramManager {
    fn default() -> Self {
        Self::new(DatagramConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::stream::StreamId;

    // Test stream ID for datagram tests
    fn stream_id() -> StreamId {
        StreamId::from(0u64)
    }

    #[test]
    fn test_datagram_manager_creation() {
        let manager = DatagramManager::default();
        assert!(manager.is_enabled());
        assert_eq!(manager.total_pending_datagrams(), 0);
    }

    #[test]
    fn test_send_datagram() {
        let mut manager = DatagramManager::default();
        let data = Bytes::from_static(b"Hello, World!");

        let result = manager.send_datagram(stream_id(), data);
        assert_eq!(result, DatagramResult::Queued);
        assert_eq!(manager.pending_datagram_count(stream_id()), 1);
        assert!(manager.has_pending_datagrams(stream_id()));
    }

    #[test]
    fn test_datagram_too_large() {
        let config = DatagramConfig {
            max_datagram_size: 10,
            ..Default::default()
        };
        let mut manager = DatagramManager::new(config);
        let large_data = Bytes::from(vec![0u8; 20]);

        let result = manager.send_datagram(stream_id(), large_data);
        assert_eq!(result, DatagramResult::TooLarge);
        assert_eq!(manager.pending_datagram_count(stream_id()), 0);
        
        let stats = manager.stats();
        assert_eq!(stats.dropped_too_large, 1);
    }

    #[test]
    fn test_queue_full() {
        let config = DatagramConfig {
            max_queue_size: 2,
            ..Default::default()
        };
        let mut manager = DatagramManager::new(config);
        let data = Bytes::from_static(b"test");

        // Fill queue
        assert_eq!(manager.send_datagram(stream_id(), data.clone()), DatagramResult::Queued);
        assert_eq!(manager.send_datagram(stream_id(), data.clone()), DatagramResult::Queued);
        
        // Should be full now
        assert_eq!(manager.send_datagram(stream_id(), data), DatagramResult::QueueFull);
        
        let stats = manager.stats();
        assert_eq!(stats.dropped_queue_full, 1);
    }

    #[test]
    fn test_next_datagram_frame() {
        let mut manager = DatagramManager::default();
        let data = Bytes::from_static(b"Hello, World!");

        // Queue a datagram
        assert_eq!(manager.send_datagram(stream_id(), data.clone()), DatagramResult::Queued);

        // Get the frame
        let frame = manager.next_datagram_frame(stream_id()).unwrap();
        match frame {
            Http3Frame::Datagram(datagram_frame) => {
                assert_eq!(datagram_frame.data, data);
            }
            _ => panic!("Expected datagram frame"),
        }

        // Queue should be empty now
        assert_eq!(manager.pending_datagram_count(stream_id()), 0);
        
        // No more frames
        assert!(manager.next_datagram_frame(stream_id()).is_none());
    }

    #[test]
    fn test_datagram_disabled() {
        let config = DatagramConfig {
            enabled: false,
            ..Default::default()
        };
        let mut manager = DatagramManager::new(config);
        let data = Bytes::from_static(b"test");

        assert!(!manager.is_enabled());
        assert_eq!(manager.send_datagram(stream_id(), data), DatagramResult::NotSupported);
        assert!(manager.next_datagram_frame(stream_id()).is_none());
    }

    #[test]
    fn test_receive_datagram() {
        let mut manager = DatagramManager::default();
        let data = Bytes::from_static(b"Received data");
        let frame = DatagramFrame::new(data.clone());

        // Process received datagram
        manager.on_datagram_received(stream_id(), frame).unwrap();

        // Check statistics
        let stats = manager.stats();
        assert_eq!(stats.datagrams_received, 1);
        assert_eq!(stats.bytes_received, data.len() as u64);

        // Get received datagram
        let received = manager.next_received_datagram().unwrap();
        assert_eq!(received.stream_id, stream_id());
        assert_eq!(received.data, data);
    }

    #[test]
    fn test_clear_pending_datagrams() {
        let mut manager = DatagramManager::default();
        let data = Bytes::from_static(b"test");

        // Queue some datagrams
        assert_eq!(manager.send_datagram(stream_id(), data.clone()), DatagramResult::Queued);
        assert_eq!(manager.send_datagram(stream_id(), data.clone()), DatagramResult::Queued);
        assert_eq!(manager.pending_datagram_count(stream_id()), 2);

        // Clear them
        manager.clear_pending_datagrams(stream_id());
        assert_eq!(manager.pending_datagram_count(stream_id()), 0);
        assert!(!manager.has_pending_datagrams(stream_id()));
    }

    #[test]
    fn test_statistics() {
        let mut manager = DatagramManager::default();
        let data = Bytes::from_static(b"test data");

        // Send some datagrams
        assert_eq!(manager.send_datagram(stream_id(), data.clone()), DatagramResult::Queued);
        let _frame = manager.next_datagram_frame(stream_id()).unwrap();

        // Receive some datagrams
        let frame = DatagramFrame::new(data.clone());
        manager.on_datagram_received(stream_id(), frame).unwrap();

        let stats = manager.stats();
        assert_eq!(stats.datagrams_sent, 1);
        assert_eq!(stats.datagrams_received, 1);
        assert_eq!(stats.bytes_sent, data.len() as u64);
        assert_eq!(stats.bytes_received, data.len() as u64);
    }
}