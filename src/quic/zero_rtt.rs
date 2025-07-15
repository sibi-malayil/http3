//! 0-RTT early data support per RFC 9000 Section 2.3 and RFC 9001 Section 4.6
//!
//! Implements 0-RTT early data for QUIC connections, allowing clients to send
//! application data immediately without waiting for the handshake to complete.

use crate::{
    error::{Error, Result},
    quic::{
        packet::{PacketType, PacketHeader, LongHeader, ConnectionId, TypeSpecificData},
        frame_types::Frame,
        crypto_impl::CryptoManager,
    },
    util::varint::VarInt,
    whathappened::Level,
    protocol_event,
};
use bytes::{Bytes, BytesMut};
use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

/// 0-RTT state for a connection
#[derive(Debug, Clone, PartialEq)]
pub enum ZeroRttState {
    /// 0-RTT not available
    Disabled,
    /// 0-RTT available but not yet used
    Available {
        /// Maximum data that can be sent in 0-RTT
        max_early_data: u64,
        /// Ticket age for anti-replay
        ticket_age: Duration,
    },
    /// 0-RTT data being sent
    Sending {
        /// Bytes sent so far
        bytes_sent: u64,
        /// Maximum allowed
        max_early_data: u64,
    },
    /// 0-RTT accepted by server
    Accepted,
    /// 0-RTT rejected by server
    Rejected {
        /// Reason for rejection
        reason: String,
    },
}

/// 0-RTT configuration
#[derive(Debug, Clone)]
pub struct ZeroRttConfig {
    /// Enable 0-RTT
    pub enabled: bool,
    /// Maximum early data size per connection
    pub max_early_data_size: u64,
    /// Anti-replay window duration
    pub anti_replay_window: Duration,
    /// Allow early data on idempotent requests only
    pub idempotent_only: bool,
}

impl Default for ZeroRttConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_early_data_size: 16384, // 16KB default
            anti_replay_window: Duration::from_secs(10),
            idempotent_only: true,
        }
    }
}

/// 0-RTT early data manager
pub struct ZeroRttManager {
    /// Configuration
    config: ZeroRttConfig,
    /// Current state
    state: Arc<Mutex<ZeroRttState>>,
    /// Buffered 0-RTT data waiting to be sent
    send_buffer: Arc<Mutex<VecDeque<ZeroRttData>>>,
    /// Received 0-RTT data
    recv_buffer: Arc<Mutex<VecDeque<Bytes>>>,
    /// Crypto manager reference
    crypto: Arc<Mutex<CryptoManager>>,
    /// Session ticket
    session_ticket: Option<Vec<u8>>,
    /// Time when 0-RTT started
    start_time: Option<Instant>,
}

/// Data queued for 0-RTT transmission
#[derive(Debug, Clone)]
struct ZeroRttData {
    /// Stream ID
    stream_id: u64,
    /// Data to send
    data: Bytes,
    /// Whether this is idempotent
    idempotent: bool,
    /// Time queued
    queued_at: Instant,
}

impl ZeroRttManager {
    /// Create a new 0-RTT manager
    pub fn new(config: ZeroRttConfig, crypto: Arc<Mutex<CryptoManager>>) -> Self {
        Self {
            config,
            state: Arc::new(Mutex::new(ZeroRttState::Disabled)),
            send_buffer: Arc::new(Mutex::new(VecDeque::new())),
            recv_buffer: Arc::new(Mutex::new(VecDeque::new())),
            crypto,
            session_ticket: None,
            start_time: None,
        }
    }

    /// Check if 0-RTT is available
    pub async fn is_available(&self) -> bool {
        if !self.config.enabled {
            return false;
        }

        let state = self.state.lock().await;
        matches!(*state, ZeroRttState::Available { .. })
    }

    /// Enable 0-RTT with a session ticket
    pub async fn enable_with_ticket(
        &mut self,
        ticket: Vec<u8>,
        max_early_data: u64,
        ticket_age: Duration,
    ) -> Result<()> {
        if !self.config.enabled {
            return Err(Error::Internal("0-RTT is disabled".to_string()));
        }

        // Validate ticket age for anti-replay
        if ticket_age > self.config.anti_replay_window {
            return Err(Error::Internal("Session ticket too old".to_string()));
        }

        self.session_ticket = Some(ticket);
        
        let mut state = self.state.lock().await;
        *state = ZeroRttState::Available {
            max_early_data: max_early_data.min(self.config.max_early_data_size),
            ticket_age,
        };

        protocol_event!(
            Level::Info,
            "0-RTT enabled";
            "max_early_data" => max_early_data,
            "ticket_age_ms" => ticket_age.as_millis()
        );

        Ok(())
    }

    /// Queue data for 0-RTT transmission
    pub async fn queue_early_data(
        &self,
        stream_id: u64,
        data: Bytes,
        idempotent: bool,
    ) -> Result<()> {
        // Check if we can send 0-RTT data
        let mut state = self.state.lock().await;
        
        match &*state {
            ZeroRttState::Available { max_early_data, .. } => {
                // Check idempotent requirement
                if self.config.idempotent_only && !idempotent {
                    return Err(Error::Internal(
                        "Non-idempotent data not allowed in 0-RTT".to_string()
                    ));
                }

                // Transition to sending state
                *state = ZeroRttState::Sending {
                    bytes_sent: 0,
                    max_early_data: *max_early_data,
                };

                // Start time tracking handled separately
            }
            ZeroRttState::Sending { bytes_sent, max_early_data } => {
                // Check size limit
                if bytes_sent + data.len() as u64 > *max_early_data {
                    return Err(Error::Internal(
                        "Exceeds 0-RTT data limit".to_string()
                    ));
                }
            }
            _ => {
                return Err(Error::Internal(
                    "0-RTT not available or already completed".to_string()
                ));
            }
        }
        drop(state);

        // Queue the data
        let zero_rtt_data = ZeroRttData {
            stream_id,
            data: data.clone(),
            idempotent,
            queued_at: Instant::now(),
        };

        let mut buffer = self.send_buffer.lock().await;
        buffer.push_back(zero_rtt_data);

        // Update bytes sent
        let mut state = self.state.lock().await;
        if let ZeroRttState::Sending { bytes_sent, .. } = &mut *state {
            *bytes_sent += data.len() as u64;
        }

        protocol_event!(
            Level::Debug,
            "0-RTT data queued";
            "stream_id" => stream_id,
            "data_len" => data.len(),
            "idempotent" => idempotent
        );

        Ok(())
    }

    /// Get the next 0-RTT packet to send
    pub async fn get_next_packet(
        &self,
        dcid: &ConnectionId,
        scid: &ConnectionId,
        packet_number: u32,
    ) -> Result<Option<Bytes>> {
        let state = self.state.lock().await;
        if !matches!(*state, ZeroRttState::Sending { .. }) {
            return Ok(None);
        }
        drop(state);

        let mut buffer = self.send_buffer.lock().await;
        if buffer.is_empty() {
            return Ok(None);
        }

        // Build 0-RTT packet
        let mut packet = BytesMut::new();
        let mut frames = Vec::new();
        let mut total_size = 0;
        const MAX_PACKET_SIZE: usize = 1200; // Conservative MTU

        // Collect frames up to packet size
        while let Some(data) = buffer.front() {
            let frame_size = 1 + 8 + 8 + data.data.len(); // Approx STREAM frame size
            if total_size + frame_size > MAX_PACKET_SIZE {
                break;
            }

            let data = buffer.pop_front().unwrap();
            frames.push(Frame::Stream {
                stream_id: crate::quic::stream::StreamId::from(data.stream_id),
                offset: 0, // TODO: Track stream offsets
                length: Some(data.data.len() as u64),
                fin: false,
                data: data.data,
            });
            total_size += frame_size;
        }

        if frames.is_empty() {
            return Ok(None);
        }

        // Create 0-RTT packet header
        let header = PacketHeader::Long(LongHeader {
            packet_type: PacketType::ZeroRtt,
            version: 0x00000001, // QUIC v1
            dst_cid: dcid.clone(),
            src_cid: scid.clone(),
            type_specific: TypeSpecificData::ZeroRtt {
                length: VarInt(total_size as u64),
                packet_number,
            },
        });

        // Encode header
        header.encode(&mut packet)?;

        // Encode frames
        for frame in frames {
            frame.encode(&mut packet)?;
        }

        // Apply 0-RTT protection
        let crypto = self.crypto.lock().await;
        let protected = crypto.protect_zero_rtt_packet(packet.freeze())?;

        protocol_event!(
            Level::Debug,
            "0-RTT packet created";
            "packet_number" => packet_number,
            "packet_size" => protected.len()
        );

        Ok(Some(protected))
    }

    /// Handle 0-RTT acceptance
    pub async fn handle_acceptance(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        
        match &*state {
            ZeroRttState::Sending { .. } => {
                *state = ZeroRttState::Accepted;

                let duration = self.start_time
                    .map(|t| t.elapsed())
                    .unwrap_or(Duration::ZERO);

                protocol_event!(
                    Level::Info,
                    "0-RTT accepted";
                    "duration_ms" => duration.as_millis()
                );

                Ok(())
            }
            _ => Err(Error::Internal("Invalid 0-RTT state for acceptance".to_string())),
        }
    }

    /// Handle 0-RTT rejection
    pub async fn handle_rejection(&self, reason: String) -> Result<Vec<ZeroRttData>> {
        let mut state = self.state.lock().await;
        
        match &*state {
            ZeroRttState::Sending { .. } => {
                *state = ZeroRttState::Rejected {
                    reason: reason.clone(),
                };

                protocol_event!(
                    Level::Warn,
                    "0-RTT rejected";
                    "reason" => &reason
                );

                // Return buffered data for retransmission
                let mut buffer = self.send_buffer.lock().await;
                let data: Vec<_> = buffer.drain(..).collect();
                
                Ok(data)
            }
            _ => Err(Error::Internal("Invalid 0-RTT state for rejection".to_string())),
        }
    }

    /// Process received 0-RTT data (server side)
    pub async fn process_zero_rtt_data(&self, data: Bytes) -> Result<()> {
        // Verify we're in a state to receive 0-RTT
        let state = self.state.lock().await;
        if !matches!(*state, ZeroRttState::Available { .. } | ZeroRttState::Sending { .. }) {
            return Err(Error::Internal("Not expecting 0-RTT data".to_string()));
        }
        drop(state);

        // Buffer the data
        let data_len = data.len();
        let mut buffer = self.recv_buffer.lock().await;
        buffer.push_back(data);

        protocol_event!(
            Level::Debug,
            "0-RTT data received";
            "data_len" => data_len
        );

        Ok(())
    }

    /// Get received 0-RTT data
    pub async fn get_received_data(&self) -> Vec<Bytes> {
        let mut buffer = self.recv_buffer.lock().await;
        buffer.drain(..).collect()
    }

    /// Get current 0-RTT state
    pub async fn get_state(&self) -> ZeroRttState {
        self.state.lock().await.clone()
    }

    /// Check if we should retry after rejection
    pub fn should_retry_after_rejection(&self) -> bool {
        // Could implement more sophisticated retry logic
        true
    }

    /// Get statistics about 0-RTT usage
    pub async fn get_stats(&self) -> ZeroRttStats {
        let state = self.state.lock().await;
        let send_buffer = self.send_buffer.lock().await;
        let recv_buffer = self.recv_buffer.lock().await;

        let (bytes_sent, bytes_pending) = match &*state {
            ZeroRttState::Sending { bytes_sent, .. } => (*bytes_sent, send_buffer.len() as u64),
            ZeroRttState::Accepted => {
                // All data was sent
                (0, 0)
            }
            _ => (0, send_buffer.len() as u64),
        };

        ZeroRttStats {
            state: state.clone(),
            bytes_sent,
            bytes_pending,
            bytes_received: recv_buffer.iter().map(|b| b.len() as u64).sum(),
            duration: self.start_time.map(|t| t.elapsed()),
        }
    }
}

/// 0-RTT statistics
#[derive(Debug, Clone)]
pub struct ZeroRttStats {
    /// Current state
    pub state: ZeroRttState,
    /// Bytes sent in 0-RTT
    pub bytes_sent: u64,
    /// Bytes pending to send
    pub bytes_pending: u64,
    /// Bytes received (server)
    pub bytes_received: u64,
    /// Duration of 0-RTT phase
    pub duration: Option<Duration>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::crypto_impl::CryptoManager;

    #[tokio::test]
    async fn test_zero_rtt_lifecycle() {
        let crypto = Arc::new(Mutex::new(CryptoManager::new_client("test.example.com").unwrap()));
        let mut manager = ZeroRttManager::new(ZeroRttConfig::default(), crypto);

        // Initially disabled
        assert!(!manager.is_available().await);

        // Enable with ticket
        manager.enable_with_ticket(
            vec![1, 2, 3, 4], // Mock ticket
            8192,
            Duration::from_secs(1),
        ).await.unwrap();

        assert!(manager.is_available().await);

        // Queue some data
        manager.queue_early_data(
            0,
            Bytes::from("GET / HTTP/1.1\r\n\r\n"),
            true, // idempotent
        ).await.unwrap();

        // State should be sending
        let state = manager.get_state().await;
        assert!(matches!(state, ZeroRttState::Sending { .. }));

        // Accept 0-RTT
        manager.handle_acceptance().await.unwrap();
        let state = manager.get_state().await;
        assert_eq!(state, ZeroRttState::Accepted);
    }

    #[tokio::test]
    async fn test_zero_rtt_rejection() {
        let crypto = Arc::new(Mutex::new(CryptoManager::new_client("test.example.com").unwrap()));
        let mut manager = ZeroRttManager::new(ZeroRttConfig::default(), crypto);

        manager.enable_with_ticket(
            vec![1, 2, 3, 4],
            8192,
            Duration::from_secs(1),
        ).await.unwrap();

        // Queue data
        let data = Bytes::from("GET / HTTP/1.1\r\n\r\n");
        manager.queue_early_data(0, data.clone(), true).await.unwrap();

        // Reject 0-RTT
        let rejected_data = manager.handle_rejection("Version mismatch".to_string()).await.unwrap();
        
        assert_eq!(rejected_data.len(), 1);
        assert_eq!(rejected_data[0].data, data);

        let state = manager.get_state().await;
        assert!(matches!(state, ZeroRttState::Rejected { .. }));
    }

    #[tokio::test]
    async fn test_zero_rtt_size_limit() {
        let crypto = Arc::new(Mutex::new(CryptoManager::new_client("test.example.com").unwrap()));
        let mut manager = ZeroRttManager::new(ZeroRttConfig {
            enabled: true,
            max_early_data_size: 100, // Small limit
            ..Default::default()
        }, crypto);

        manager.enable_with_ticket(
            vec![1, 2, 3, 4],
            1000, // Server allows more, but we limit to 100
            Duration::from_secs(1),
        ).await.unwrap();

        // Queue data up to limit
        manager.queue_early_data(0, Bytes::from(vec![0u8; 50]), true).await.unwrap();
        manager.queue_early_data(1, Bytes::from(vec![0u8; 50]), true).await.unwrap();

        // This should fail - exceeds limit
        let result = manager.queue_early_data(2, Bytes::from(vec![0u8; 1]), true).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_zero_rtt_idempotent_only() {
        let crypto = Arc::new(Mutex::new(CryptoManager::new_client("test.example.com").unwrap()));
        let mut manager = ZeroRttManager::new(ZeroRttConfig {
            enabled: true,
            idempotent_only: true,
            ..Default::default()
        }, crypto);

        manager.enable_with_ticket(
            vec![1, 2, 3, 4],
            8192,
            Duration::from_secs(1),
        ).await.unwrap();

        // Non-idempotent request should fail
        let result = manager.queue_early_data(
            0,
            Bytes::from("POST /api HTTP/1.1\r\n\r\n"),
            false, // non-idempotent
        ).await;
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Non-idempotent"));
    }
}