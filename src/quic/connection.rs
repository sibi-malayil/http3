//! QUIC connection management implementation
//!
//! Implements QUIC connection state machine and lifecycle management
//! according to RFC 9000 Section 4.

use crate::{
    error::{Error, Result, ConnectionErrorCode},
    quic::{
        packet::{ConnectionId, PacketHeader, PacketType, Packet},
        frame_types::Frame,
        transport::TransportParameters,
        stream::{StreamId, StreamType},
        stream_manager::{StreamManager, StreamParameters, StreamPriority, StreamEvent},
        recovery::RecoveryManager,
        congestion::CongestionController,
        crypto_impl::CryptoManager,
        zero_rtt::{ZeroRttManager, ZeroRttConfig},
        version::{VersionNegotiator, VersionConfig, VersionNegotiationPacket},
    },
    util::{varint::VarInt, time::{Instant, Duration}},
    whathappened::Level,
    {debug, protocol_event, span},
};
use bytes::Bytes;
use std::{
    collections::VecDeque,
    net::SocketAddr,
};
use tokio::sync::mpsc;

/// QUIC connection state according to RFC 9000 Section 4
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConnectionState {
    /// Initial state before handshake begins
    Initial,
    /// Handshake in progress
    Handshaking,
    /// Early data can be sent (0-RTT)
    EarlyData,
    /// Connection fully established (1-RTT)
    Established,
    /// Connection is closing (draining period)
    Closing {
        /// Error code for the close
        error_code: ConnectionErrorCode,
        /// Close reason
        reason: String,
        /// When the draining period ends
        drain_timeout: Instant,
    },
    /// Connection is closed
    Closed,
}

impl ConnectionState {
    /// Returns true if the connection can send application data
    pub fn can_send_app_data(self) -> bool {
        matches!(self, Self::EarlyData | Self::Established)
    }

    /// Returns true if the connection can accept new streams
    pub fn can_accept_streams(self) -> bool {
        matches!(self, Self::Established)
    }

    /// Returns true if the connection is effectively closed
    pub fn is_closed(self) -> bool {
        matches!(self, Self::Closing { .. } | Self::Closed)
    }

    /// Returns true if the connection is in handshake phase
    pub fn is_handshaking(self) -> bool {
        matches!(self, Self::Initial | Self::Handshaking)
    }
}

/// QUIC connection role
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionRole {
    /// Client role in QUIC connection
    Client,
    /// Server role in QUIC connection
    Server,
}

/// Flow control limits for a connection
#[derive(Debug, Clone)]
pub struct FlowControlLimits {
    /// Maximum data that can be sent on the connection
    pub max_data: u64,
    /// Current data sent on the connection
    pub data_sent: u64,
    /// Maximum data that can be received on the connection
    pub max_data_recv: u64,
    /// Current data received on the connection
    pub data_recv: u64,
    /// Maximum number of bidirectional streams
    pub max_streams_bidi: u64,
    /// Maximum number of unidirectional streams
    pub max_streams_uni: u64,
    /// Current number of bidirectional streams
    pub streams_bidi_count: u64,
    /// Current number of unidirectional streams
    pub streams_uni_count: u64,
}

impl FlowControlLimits {
    /// Create new flow control limits from transport parameters
    pub fn new(transport_params: &TransportParameters) -> Self {
        Self {
            max_data: transport_params.initial_max_data.map(|v| v.into_inner()).unwrap_or(0),
            data_sent: 0,
            max_data_recv: transport_params.initial_max_data.map(|v| v.into_inner()).unwrap_or(0),
            data_recv: 0,
            max_streams_bidi: transport_params.initial_max_streams_bidi.map(|v| v.into_inner()).unwrap_or(0),
            max_streams_uni: transport_params.initial_max_streams_uni.map(|v| v.into_inner()).unwrap_or(0),
            streams_bidi_count: 0,
            streams_uni_count: 0,
        }
    }

    /// Check if we can send the specified amount of data
    pub fn can_send_data(&self, amount: u64) -> bool {
        self.data_sent + amount <= self.max_data
    }

    /// Record data sent on the connection
    pub fn record_data_sent(&mut self, amount: u64) {
        self.data_sent += amount;
    }

    /// Record data received on the connection
    pub fn record_data_recv(&mut self, amount: u64) {
        self.data_recv += amount;
    }

    /// Check if we can open a new stream of the specified type
    pub fn can_open_stream(&self, stream_type: crate::quic::stream::StreamType) -> bool {
        match stream_type {
            crate::quic::stream::StreamType::Bidirectional => {
                self.streams_bidi_count < self.max_streams_bidi
            }
            crate::quic::stream::StreamType::Unidirectional => {
                self.streams_uni_count < self.max_streams_uni
            }
        }
    }

    /// Record a new stream being opened
    pub fn record_stream_opened(&mut self, stream_type: crate::quic::stream::StreamType) {
        match stream_type {
            crate::quic::stream::StreamType::Bidirectional => {
                self.streams_bidi_count += 1;
            }
            crate::quic::stream::StreamType::Unidirectional => {
                self.streams_uni_count += 1;
            }
        }
    }

    /// Update maximum data limit
    pub fn update_max_data(&mut self, new_limit: u64) {
        if new_limit > self.max_data {
            self.max_data = new_limit;
        }
    }

    /// Update maximum streams limit
    pub fn update_max_streams(&mut self, stream_type: crate::quic::stream::StreamType, new_limit: u64) {
        match stream_type {
            crate::quic::stream::StreamType::Bidirectional => {
                if new_limit > self.max_streams_bidi {
                    self.max_streams_bidi = new_limit;
                }
            }
            crate::quic::stream::StreamType::Unidirectional => {
                if new_limit > self.max_streams_uni {
                    self.max_streams_uni = new_limit;
                }
            }
        }
    }

    /// Check if we should send a MAX_DATA frame
    pub fn should_send_max_data(&self) -> bool {
        // Send MAX_DATA when we've consumed more than half of our receive window
        let consumed_ratio = self.data_recv as f64 / self.max_data_recv as f64;
        consumed_ratio > 0.5
    }

    /// Get available send window
    pub fn available_send_window(&self) -> u64 {
        self.max_data.saturating_sub(self.data_sent)
    }

    /// Get available receive window
    pub fn available_recv_window(&self) -> u64 {
        self.max_data_recv.saturating_sub(self.data_recv)
    }

}

/// QUIC connection implementation
pub struct Connection {
    /// Connection state
    state: ConnectionState,
    /// Connection role (client or server)
    role: ConnectionRole,
    /// Local connection ID
    local_cid: ConnectionId,
    /// Remote connection ID
    remote_cid: ConnectionId,
    /// Remote peer address
    remote_addr: SocketAddr,
    /// Local address
    local_addr: Option<SocketAddr>,
    /// Transport parameters
    transport_params: TransportParameters,
    /// Peer transport parameters (received during handshake)
    peer_transport_params: Option<TransportParameters>,
    /// Flow control limits
    flow_control: FlowControlLimits,
    /// Stream manager
    stream_manager: StreamManager,
    /// Packet number for each packet number space
    packet_numbers: [u64; 3], // Initial, Handshake, Application
    /// Loss recovery manager
    recovery: RecoveryManager,
    /// Congestion controller
    congestion: CongestionController,
    /// Crypto manager for TLS integration
    crypto: CryptoManager,
    /// Pending frames to send
    pending_frames: VecDeque<Frame>,
    /// Last activity time for idle timeout
    last_activity: Instant,
    /// Channel for sending packets to the network
    packet_tx: Option<mpsc::UnboundedSender<(Bytes, SocketAddr)>>,
    /// Connection close information
    close_info: Option<(ConnectionErrorCode, String)>,
    /// Bytes in flight (sent but not acknowledged)
    bytes_in_flight: u64,
    /// Tracking for pacing and burst control
    pacing_rate: Option<u64>,
    /// Address validation token for 0-RTT
    address_validation_token: Option<Bytes>,
    /// Available connection IDs for migration
    available_connection_ids: Vec<(u64, ConnectionId, [u8; 16])>,
    /// Crypto stream send offset
    crypto_send_offset: u64,
    /// Retired connection ID sequence numbers
    retired_connection_ids: Vec<u64>,
    /// Path challenge data for validation
    path_challenge_data: Option<[u8; 8]>,
    /// Whether the path has been validated
    path_validated: bool,
    /// Version negotiator
    version_negotiator: VersionNegotiator,
    /// Current QUIC version in use
    quic_version: u32,
    /// 0-RTT early data manager
    zero_rtt_manager: Option<ZeroRttManager>,
}

impl Connection {
    /// Create a new QUIC connection
    pub fn new(
        role: ConnectionRole,
        local_cid: ConnectionId,
        remote_cid: ConnectionId,
        remote_addr: SocketAddr,
        transport_params: TransportParameters,
    ) -> Result<Self> {
        let _span = span!(Level::Info, "Connection::new", role = role, local_cid = local_cid, remote_cid = remote_cid);
        
        protocol_event!(
            Level::Info,
            "Creating new QUIC connection";
            "role" => role,
            "local_cid" => local_cid,
            "remote_cid" => remote_cid,
            "remote_addr" => remote_addr
        );
        
        let flow_control = FlowControlLimits::new(&transport_params);
        let stream_manager = StreamManager::new(role, &transport_params);
        let recovery = RecoveryManager::new();
        let congestion = CongestionController::new();
        let mut crypto = CryptoManager::new(role)?;
        
        // Initialize version negotiator
        let version_config = VersionConfig::default();
        let version_negotiator = VersionNegotiator::new(version_config.clone());
        let quic_version = version_config.preferred_version;
        
        // Set connection IDs
        crypto.set_connection_ids(local_cid.clone(), remote_cid.clone());
        
        // Initialize initial keys for QUIC connection
        // RFC 9001: Initial keys are derived from the client's initial destination connection ID
        // For client: use server's CID (remote_cid)
        // For server: ALSO use server's CID (local_cid) - not client's!
        let initial_dcid = match role {
            ConnectionRole::Client => remote_cid.as_bytes(),
            ConnectionRole::Server => local_cid.as_bytes(),
        };
        crypto.init_initial_keys(initial_dcid)?;
        
        // Set transport parameters for TLS extension
        crypto.set_transport_params(transport_params.clone());

        // Stream IDs are now managed by StreamManager

        Ok(Self {
            state: ConnectionState::Initial,
            role,
            local_cid,
            remote_cid,
            remote_addr,
            local_addr: None,
            transport_params,
            peer_transport_params: None,
            flow_control,
            stream_manager,
            packet_numbers: [0; 3],
            recovery,
            congestion,
            crypto,
            pending_frames: VecDeque::new(),
            last_activity: Instant::now(),
            packet_tx: None,
            close_info: None,
            bytes_in_flight: 0,
            pacing_rate: None,
            address_validation_token: None,
            available_connection_ids: Vec::new(),
            crypto_send_offset: 0,
            retired_connection_ids: Vec::new(),
            path_challenge_data: None,
            path_validated: false,
            version_negotiator,
            quic_version,
            zero_rtt_manager: None, // Will be initialized after crypto setup
        })
    }

    /// Set the packet sender for network output
    pub fn set_packet_sender(&mut self, tx: mpsc::UnboundedSender<(Bytes, SocketAddr)>) {
        self.packet_tx = Some(tx);
    }

    /// Enable 0-RTT early data
    pub fn enable_zero_rtt(&mut self, session_ticket: Vec<u8>, max_early_data: u64) -> Result<()> {
        if self.role != ConnectionRole::Client {
            return Err(Error::Internal("0-RTT is only supported for clients".to_string()));
        }

        // Create 0-RTT manager if not already created
        if self.zero_rtt_manager.is_none() {
            // For now, create a new crypto manager for 0-RTT
            // In production, this would share the crypto state properly
            let crypto = match self.role {
                ConnectionRole::Client => {
                    let cm = CryptoManager::new_client("example.com")?;
                    std::sync::Arc::new(tokio::sync::Mutex::new(cm))
                },
                ConnectionRole::Server => {
                    return Err(Error::Internal("0-RTT not supported for servers yet".to_string()));
                }
            };
            let manager = ZeroRttManager::new(ZeroRttConfig::default(), crypto);
            self.zero_rtt_manager = Some(manager);
        }

        // Enable 0-RTT with the session ticket
        if let Some(ref mut manager) = self.zero_rtt_manager {
            // Use a simple ticket age calculation (in production, this would be more sophisticated)
            let ticket_age = std::time::Duration::from_secs(1);
            
            // Block to enable ticket - in real code, this would be async
            let rt = tokio::runtime::Handle::current();
            rt.block_on(async {
                manager.enable_with_ticket(session_ticket, max_early_data, ticket_age).await
            })?;
        }

        protocol_event!(
            Level::Info,
            "0-RTT enabled for connection";
            "max_early_data" => max_early_data
        );

        Ok(())
    }

    /// Send data in 0-RTT
    pub fn send_zero_rtt_data(&mut self, stream_id: StreamId, data: Bytes) -> Result<()> {
        if let Some(ref manager) = self.zero_rtt_manager {
            let rt = tokio::runtime::Handle::current();
            let data_len = data.len();
            rt.block_on(async {
                manager.queue_early_data(stream_id.into_inner(), data, true).await
            })?;

            protocol_event!(
                Level::Debug,
                "0-RTT data queued";
                "stream_id" => stream_id.into_inner(),
                "data_len" => data_len
            );
        } else {
            return Err(Error::Internal("0-RTT not enabled".to_string()));
        }

        Ok(())
    }

    /// Get the current connection state
    pub fn state(&self) -> ConnectionState {
        self.state.clone()
    }
    
    /// Check if the connection is established
    pub fn is_established(&self) -> bool {
        self.state == ConnectionState::Established
    }

    /// Get the connection role
    pub fn role(&self) -> ConnectionRole {
        self.role
    }

    /// Get the local connection ID
    pub fn local_cid(&self) -> &ConnectionId {
        &self.local_cid
    }

    /// Get the remote connection ID
    pub fn remote_cid(&self) -> &ConnectionId {
        &self.remote_cid
    }

    /// Get the remote address
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Start the connection handshake
    pub async fn start_handshake(&mut self) -> Result<()> {
        let _span = span!(Level::Info, "start_handshake", role = self.role, local_cid = self.local_cid);
        
        if self.state != ConnectionState::Initial {
            return Err(Error::ProtocolViolation("Connection not in initial state".to_string()));
        }

        protocol_event!(
            Level::Info,
            "Starting QUIC handshake";
            "role" => self.role,
            "local_cid" => self.local_cid,
            "remote_cid" => self.remote_cid
        );
        
        self.state = ConnectionState::Handshaking;
        
        // Get initial handshake data
        let handshake_data = self.crypto.start_handshake().await?;
        
        // If we have handshake data (client sends first), queue it
        if !handshake_data.is_empty() {
            let offset = self.crypto_send_offset;
            self.crypto_send_offset += handshake_data.len() as u64;
            self.pending_frames.push_back(Frame::Crypto {
                offset,
                data: handshake_data.into(),
            });
        }
        
        // Send initial packet
        self.send_pending_frames().await?;
        
        Ok(())
    }

    /// Process an incoming packet
    pub async fn process_packet(&mut self, packet_data: &[u8]) -> Result<()> {
        let _span = span!(Level::Debug, "process_packet", state = self.state, packet_len = packet_data.len());
        
        self.last_activity = Instant::now();

        // RFC 9002 Section 8.1: Track bytes received for anti-amplification
        self.recovery.update_bytes_received(packet_data.len());
        
        protocol_event!(
            Level::Debug,
            "Processing incoming packet";
            "state" => self.state,
            "packet_len" => packet_data.len(),
            "role" => self.role
        );

        // Check for version negotiation packet first
        if packet_data.len() >= 5 && packet_data[1..5] == [0, 0, 0, 0] {
            // This is a version negotiation packet
            if self.role == ConnectionRole::Client {
                let vn_packet = VersionNegotiationPacket::decode(packet_data)?;
                self.handle_version_negotiation(&vn_packet).await?;
                return Ok(());
            } else {
                return Err(Error::InvalidPacket("Server received version negotiation packet".to_string()));
            }
        }
        
        // For server, check if we need to send version negotiation
        if self.role == ConnectionRole::Server && packet_data.len() >= 5 {
            let version = u32::from_be_bytes([packet_data[1], packet_data[2], packet_data[3], packet_data[4]]);
            if self.needs_version_negotiation(version) {
                // Create and send version negotiation packet
                let src_cid = self.parse_connection_ids_from_packet(packet_data)?;
                let vn_packet = self.create_version_negotiation_packet(src_cid.1, src_cid.0);
                
                let mut buf = bytes::BytesMut::new();
                vn_packet.encode(&mut buf)?;
                
                if let Some(ref tx) = self.packet_tx {
                    let _ = tx.send((buf.freeze(), self.remote_addr));
                }
                
                protocol_event!(
                    Level::Info,
                    "Sent version negotiation packet";
                    "client_version" => format!("0x{:08x}", version)
                );
                
                return Ok(());
            }
        }

        // Decrypt the packet using crypto manager
        eprintln!("DEBUG: About to decrypt packet, role={:?}", self.role);
        let decrypted_packet = self.crypto.decrypt_packet(packet_data).await?;
        eprintln!("DEBUG: Decrypted packet with {} frames", decrypted_packet.frames.len());
        
        // If server receives Initial packet while in Initial state, transition to Handshaking
        if self.role == ConnectionRole::Server && 
           self.state == ConnectionState::Initial &&
           packet_data.len() > 0 && (packet_data[0] & 0xf0) == 0xc0 {
            eprintln!("Server transitioning to Handshaking state after receiving Initial packet");
            self.state = ConnectionState::Handshaking;
        }
        
        // Update recovery with received packet
        let packet_type = self.crypto.determine_packet_type();
        
        // Check if any frames are ack-eliciting
        let ack_eliciting = decrypted_packet.frames.iter().any(|frame| {
            !matches!(frame, 
                Frame::Ack { .. } | 
                Frame::Padding | 
                Frame::ConnectionClose { .. }
            )
        });
        
        self.recovery.on_packet_received(
            decrypted_packet.packet_number,
            packet_type,
            ack_eliciting,
            Instant::now(),
        );
        
        // Process each frame in the decrypted packet
        for frame in decrypted_packet.frames {
            self.process_frame(frame).await?;
        }

        // Send any pending frames
        eprintln!("DEBUG: After processing packet, pending_frames.len() = {}", self.pending_frames.len());
        self.send_pending_frames().await?;

        Ok(())
    }

    /// Process a single frame
    async fn process_frame(&mut self, frame: Frame) -> Result<()> {
        match frame {
            Frame::Padding => {
                // Padding frames have no semantic meaning
            }
            Frame::Ping => {
                // Ping frames require no response but acknowledge connectivity
            }
            Frame::Ack { largest_acknowledged, ack_delay, ack_ranges, .. } => {
                // Convert AckRange to tuple format for congestion control
                // AckRange contains gap and length, need to compute actual ranges
                let mut ranges: Vec<(u64, u64)> = Vec::new();
                let mut current = largest_acknowledged;
                
                // First range is implicit: from largest_acknowledged down
                ranges.push((current, current));
                
                // Process additional ranges
                for range in ack_ranges {
                    current = current.saturating_sub(range.gap + 1);
                    let start = current.saturating_sub(range.ack_range_length);
                    ranges.push((start, current));
                    current = start;
                }
                
                // Handle acknowledgments for congestion control with RTT measurement
                // In production, RTT would be calculated from packet send time to ack receive time
                let rtt = Duration::from_millis(100); // TODO: Calculate actual RTT from packet timing
                self.congestion.on_ack_received_with_rtt(&ranges, rtt);
                
                // Update bytes in flight (simplified)
                let acked_bytes: u64 = ranges.iter()
                    .map(|(start, end)| (end - start + 1) * 1200) // Estimate packet size
                    .sum();
                self.bytes_in_flight = self.bytes_in_flight.saturating_sub(acked_bytes);
                
                // Update recovery manager with acknowledgment
                // Note: We need packet type context to determine packet number space
                // For now, assume ApplicationData space for established connections
                let pn_space = if self.state == ConnectionState::Established {
                    crate::quic::recovery::PacketNumberSpace::ApplicationData
                } else if self.state == ConnectionState::Handshaking {
                    crate::quic::recovery::PacketNumberSpace::Handshake
                } else {
                    crate::quic::recovery::PacketNumberSpace::Initial
                };
                
                // Process ACK and get frames that need retransmission
                let lost_frames = self.recovery.on_ack_received(
                    pn_space,
                    largest_acknowledged,
                    &ranges,
                    Duration::from_micros(ack_delay)
                )?;
                
                // RFC 9002 Section 8.1: Valid ACK validates peer address
                self.recovery.validate_address();
                
                // Queue lost frames for retransmission
                for frame in lost_frames {
                    self.pending_frames.push_back(frame);
                }
            }
            Frame::ResetStream { stream_id, application_error_code, final_size } => {
                // Handle stream reset through stream manager
                self.stream_manager.handle_reset_stream(stream_id, application_error_code, final_size)?;
                
                // Update flow control
                if let Some(stats) = self.stream_manager.stream_stats(stream_id) {
                    self.flow_control.data_recv += final_size.saturating_sub(stats.data_recv);
                }
            }
            Frame::StopSending { stream_id, application_error_code } => {
                // Handle stop sending through stream manager
                self.stream_manager.handle_stop_sending(stream_id, application_error_code)?;
                
                // Get final size from stream stats
                if let Some(stats) = self.stream_manager.stream_stats(stream_id) {
                    // Queue a RESET_STREAM frame
                    self.pending_frames.push_back(Frame::ResetStream {
                        stream_id,
                        application_error_code,
                        final_size: stats.data_sent,
                    });
                }
            }
            Frame::Crypto { offset, data } => {
                eprintln!("DEBUG: Processing CRYPTO frame, offset={}, len={}, role={:?}", 
                    offset, data.len(), self.role);
                self.crypto.process_crypto_frame(offset, data).await?;
                
                // After processing CRYPTO frame, check if we have handshake data to send
                if let Some(handshake_data) = self.crypto.get_handshake_data() {
                    if !handshake_data.is_empty() {
                        eprintln!("Queueing handshake response data: {} bytes at offset {}", handshake_data.len(), self.crypto_send_offset);
                        let offset = self.crypto_send_offset;
                        self.crypto_send_offset += handshake_data.len() as u64;
                        self.pending_frames.push_back(Frame::Crypto {
                            offset,
                            data: handshake_data.into(),
                        });
                    }
                }
                
                // Check if handshake is complete and update state
                let handshake_done = self.crypto.handshake_complete().await?;
                eprintln!("DEBUG: Checking handshake completion: role={:?}, complete={}, state={:?}", 
                    self.role, handshake_done, self.state);
                if handshake_done {
                    match self.state {
                        ConnectionState::Handshaking => {
                            protocol_event!(
                                Level::Info,
                                "Handshake complete, transitioning to Established";
                                "role" => self.role,
                                "local_cid" => self.local_cid,
                                "remote_cid" => self.remote_cid
                            );
                            
                            // Extract and process peer transport parameters
                            if let Some(peer_params) = self.crypto.get_peer_transport_params() {
                                self.process_peer_transport_params(peer_params.clone())?;
                            }
                            
                            self.state = ConnectionState::Established;
                            
                            // RFC 9002 Section 6.2.2: Confirm handshake completion
                            self.recovery.confirm_handshake();
                            
                            // Send HANDSHAKE_DONE frame for server
                            if self.role == ConnectionRole::Server {
                                self.pending_frames.push_back(Frame::HandshakeDone);
                            }
                        }
                        ConnectionState::EarlyData => {
                            protocol_event!(
                                Level::Info,
                                "EarlyData to Established transition";
                                "role" => self.role,
                                "local_cid" => self.local_cid
                            );
                            self.state = ConnectionState::Established;
                        }
                        _ => {}
                    }
                }
                
                // Get any pending crypto frames to send
                for frame in self.crypto.take_crypto_frames() {
                    self.pending_frames.push_back(frame);
                }
            }
            Frame::NewToken { token } => {
                // Store token for future connections per RFC 9000 Section 8.1
                if self.role == ConnectionRole::Client {
                    self.address_validation_token = Some(token);
                }
            }
            Frame::Stream { stream_id, offset, data, fin, length: _ } => {
                self.process_stream_frame(stream_id, offset, data, fin).await?;
            }
            Frame::MaxData { maximum_data } => {
                // Update max data through stream manager for proper unblocking
                self.stream_manager.update_max_data(maximum_data)?;
            }
            Frame::MaxStreamData { stream_id, maximum_stream_data } => {
                // Update max stream data through stream manager
                self.stream_manager.update_max_stream_data(stream_id, maximum_stream_data)?;
            }
            Frame::MaxStreams { maximum_streams, stream_type } => {
                match stream_type {
                    crate::quic::frame_types::StreamType::Bidirectional => {
                        self.flow_control.update_max_streams(crate::quic::stream::StreamType::Bidirectional, maximum_streams);
                    }
                    crate::quic::frame_types::StreamType::Unidirectional => {
                        self.flow_control.update_max_streams(crate::quic::stream::StreamType::Unidirectional, maximum_streams);
                    }
                }
            }
            Frame::DataBlocked { maximum_data: _ } => {
                // Peer is blocked by connection-level flow control
                self.consider_sending_max_data();
            }
            Frame::StreamDataBlocked { stream_id, maximum_stream_data: _ } => {
                // Peer is blocked by stream-level flow control per RFC 9000 Section 4.1
                if let Some(stats) = self.stream_manager.stream_stats(stream_id) {
                    // Check if we should send a MAX_STREAM_DATA frame
                    let consumed = stats.data_recv;
                    let current_max = stats.max_data_recv;
                    if consumed > current_max / 2 {
                        // Send MAX_STREAM_DATA with increased limit
                        let new_max = current_max + 65536; // Add 64KB
                        self.pending_frames.push_back(Frame::MaxStreamData {
                            stream_id,
                            maximum_stream_data: new_max,
                        });
                        // Update through stream manager
                        let _ = self.stream_manager.update_max_stream_data(stream_id, new_max);
                    }
                }
            }
            Frame::StreamsBlocked { maximum_streams, stream_type } => {
                // Peer is blocked by stream limit
                self.stream_manager.handle_streams_blocked(stream_type, maximum_streams)?;
                self.consider_sending_max_streams(stream_type);
            }
            Frame::NewConnectionId { sequence_number, retire_prior_to, connection_id, stateless_reset_token } => {
                // Handle new connection ID per RFC 9000 Section 5.1
                if self.role == ConnectionRole::Client {
                    // Store the new connection ID for migration
                    self.available_connection_ids.push((sequence_number, connection_id, stateless_reset_token));
                    
                    // Retire old connection IDs
                    self.available_connection_ids.retain(|(seq, _, _)| *seq >= retire_prior_to);
                    
                    // Send RETIRE_CONNECTION_ID for retired IDs
                    for seq in 0..retire_prior_to {
                        self.pending_frames.push_back(Frame::RetireConnectionId { 
                            sequence_number: seq 
                        });
                    }
                }
            }
            Frame::RetireConnectionId { sequence_number } => {
                // Handle connection ID retirement per RFC 9000 Section 5.1.2
                if self.role == ConnectionRole::Server {
                    self.retired_connection_ids.push(sequence_number);
                }
            }
            Frame::PathChallenge { data } => {
                // Respond with PATH_RESPONSE per RFC 9000 Section 8.2.2
                self.pending_frames.push_back(Frame::PathResponse { data });
            }
            Frame::PathResponse { data } => {
                // Handle path validation response per RFC 9000 Section 8.2.3
                if let Some(challenge_data) = self.path_challenge_data.take() {
                    if challenge_data == data {
                        // Path validation successful
                        self.path_validated = true;
                    }
                }
            }
            Frame::ConnectionClose { error_code, frame_type: _, reason_phrase } => {
                self.state = ConnectionState::Closing {
                    error_code: ConnectionErrorCode::try_from(error_code as u64)?,
                    reason: String::from_utf8_lossy(&reason_phrase).to_string(),
                    drain_timeout: Instant::now() + Duration::from_secs(3),
                };
            }
            Frame::HandshakeDone => {
                // Handshake confirmation (server to client)
                if self.role == ConnectionRole::Client && self.state == ConnectionState::Handshaking {
                    self.state = ConnectionState::Established;
                }
            }
        }

        Ok(())
    }

    /// Process a STREAM frame
    async fn process_stream_frame(
        &mut self,
        stream_id: StreamId,
        offset: u64,
        data: Bytes,
        fin: bool,
    ) -> Result<()> {
        // Record data length before moving
        let data_len = data.len() as u64;
        
        // Receive data through stream manager
        self.stream_manager.receive_data(stream_id, offset, data, fin)?;

        // Check flow control
        self.flow_control.record_data_recv(data_len);
        if self.flow_control.data_recv > self.flow_control.max_data_recv {
            return Err(Error::FlowControl);
        }

        // Process stream events from manager
        while let Some(event) = self.stream_manager.poll_event() {
            match event {
                StreamEvent::DataAvailable { stream_id } => {
                    protocol_event!(
                        Level::Debug,
                        "Stream has data available";
                        "stream_id" => stream_id.into_inner()
                    );
                }
                StreamEvent::StreamBlocked { stream_id, is_connection_blocked } => {
                    if is_connection_blocked {
                        self.pending_frames.push_back(Frame::DataBlocked {
                            maximum_data: self.flow_control.max_data,
                        });
                    } else {
                        if let Some(stats) = self.stream_manager.stream_stats(stream_id) {
                            self.pending_frames.push_back(Frame::StreamDataBlocked {
                                stream_id,
                                maximum_stream_data: stats.max_data_send,
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        // Send flow control updates if needed
        if self.flow_control.should_send_max_data() {
            self.pending_frames.push_back(Frame::MaxData {
                maximum_data: self.flow_control.max_data_recv,
            });
        }

        // Generate frames through stream manager
        if let Ok(frames) = self.stream_manager.generate_stream_frames(stream_id, 1000) {
            for frame in frames {
                self.pending_frames.push_back(frame);
            }
        }

        Ok(())
    }

    /// Open a new stream
    pub fn open_stream(&mut self, stream_type: StreamType) -> Result<StreamId> {
        if !self.state.clone().can_accept_streams() {
            return Err(Error::ProtocolViolation("Cannot open streams in current state".to_string()));
        }

        // Create stream through stream manager
        let params = StreamParameters {
            stream_type,
            priority: StreamPriority::Normal,
            initial_recv_window: None,
        };
        let stream_id = self.stream_manager.create_stream(params)?;
        
        self.flow_control.record_stream_opened(stream_type);

        Ok(stream_id)
    }

    /// Create a new stream
    pub fn create_stream(&mut self, stream_type: StreamType) -> Result<StreamId> {
        self.open_stream(stream_type)
    }

    /// Send data on a stream  
    pub async fn stream_send(
        &mut self,
        stream_id: StreamId,
        data: Bytes,
        fin: bool,
    ) -> Result<()> {
        self.send_stream_data(stream_id, data, fin).await
    }

    /// Send data on a stream
    pub async fn send_stream_data(
        &mut self,
        stream_id: StreamId,
        data: Bytes,
        fin: bool,
    ) -> Result<()> {
        // Check congestion control constraints first
        let packet_size = data.len() as u64 + 50; // Estimate header overhead
        if !self.congestion.can_send(self.bytes_in_flight + packet_size) {
            return Err(Error::Internal("Congestion control limit reached".to_string()));
        }
        
        // Check available sending window considering pacing
        let available_window = self.congestion.sending_window(self.bytes_in_flight);
        if packet_size > available_window {
            return Err(Error::Internal("Pacing limit reached".to_string()));
        }

        // Get current stream offset before sending
        let offset = if let Some(stats) = self.stream_manager.stream_stats(stream_id) {
            stats.data_sent
        } else {
            0
        };

        // Send data through stream manager
        self.stream_manager.send_data(stream_id, data.clone(), fin)?;
        
        // Update connection flow control
        self.flow_control.record_data_sent(data.len() as u64);

        // Queue STREAM frame
        self.pending_frames.push_back(Frame::Stream {
            stream_id,
            offset,
            data,
            fin,
            length: None, // Optional length field
        });

        self.send_pending_frames().await?;
        Ok(())
    }

    /// Close a stream gracefully
    pub async fn close_stream(&mut self, stream_id: StreamId, error_code: u64) -> Result<()> {
        // Get stream stats to determine final size
        let stats = self.stream_manager.stream_stats(stream_id)
            .ok_or_else(|| Error::ProtocolViolation("Stream not found".to_string()))?;
        
        // Send RESET_STREAM frame to close the stream
        let final_size = stats.data_sent;
        self.pending_frames.push_back(Frame::ResetStream {
            stream_id,
            application_error_code: error_code,
            final_size,
        });
        
        // Stream removal is handled by stream manager
        
        // Send pending frames
        self.send_pending_frames().await?;
        
        Ok(())
    }

    /// Close the connection
    pub async fn close(&mut self, error_code: ConnectionErrorCode, reason: String) -> Result<()> {
        let _span = span!(Level::Info, "close", error_code = error_code, reason = reason);
        
        if self.state.clone().is_closed() {
            return Ok(());
        }

        protocol_event!(
            Level::Info,
            "Closing QUIC connection";
            "error_code" => error_code,
            "reason" => reason.clone(),
            "role" => self.role,
            "local_cid" => self.local_cid
        );
        
        self.state = ConnectionState::Closing {
            error_code,
            reason: reason.clone(),
            drain_timeout: Instant::now() + Duration::from_secs(3),
        };

        // Send CONNECTION_CLOSE frame
        self.pending_frames.push_back(Frame::ConnectionClose {
            error_code: error_code.into(),
            frame_type: None,
            reason_phrase: reason.into_bytes().into(),
        });

        self.send_pending_frames().await?;
        Ok(())
    }

    /// Send all pending frames
    async fn send_pending_frames(&mut self) -> Result<()> {
        // Get flow control frames from stream manager
        let flow_control_frames = self.stream_manager.get_pending_flow_control_frames();
        
        // Add flow control frames to pending frames (high priority)
        for frame in flow_control_frames {
            self.pending_frames.push_front(frame);
        }
        
        if self.pending_frames.is_empty() {
            return Ok(());
        }

        let frames: Vec<_> = self.pending_frames.drain(..).collect();
        
        eprintln!("DEBUG: send_pending_frames: role={:?}, frames.len()={}, state={:?}", 
            self.role, frames.len(), self.state);
        
        // Get the next packet number
        let packet_number = self.next_packet_number();
        
        // Encrypt the packet using crypto manager
        let encrypted_packet = self.crypto.encrypt_packet(packet_number, frames.clone()).await?;
        let packet_size = encrypted_packet.len();
        
        // Send the encrypted packet
        if let Some(tx) = &self.packet_tx {
            tx.send((encrypted_packet.clone(), self.remote_addr))
                .map_err(|_| Error::Transport("Failed to send packet".to_string()))?;
        }
        
        // Track sent packet for recovery
        let packet_type = match self.state {
            ConnectionState::Initial => PacketType::Initial,
            ConnectionState::Handshaking => PacketType::Handshake,
            ConnectionState::Established => PacketType::OneRtt,
            ConnectionState::EarlyData => PacketType::ZeroRtt,
            _ => PacketType::OneRtt,
        };
        
        eprintln!("Sending packet: role={:?}, state={:?}, packet_type={:?}, packet_number={}, size={} bytes", 
            self.role, self.state, packet_type, packet_number, encrypted_packet.len());
        
        // Create a packet for recovery tracking
        // Note: This is a placeholder packet for recovery purposes
        let header = match packet_type {
            PacketType::OneRtt => {
                use crate::quic::packet::ShortHeader;
                PacketHeader::Short(ShortHeader::new(
                    false, // spin bit
                    false, // key phase
                    self.local_cid.clone(),
                    packet_number as u32,
                ))
            }
            _ => {
                use crate::quic::packet::{LongHeader, TypeSpecificData};
                let type_specific = match packet_type {
                    PacketType::Initial => TypeSpecificData::Initial {
                        token: bytes::Bytes::new(),
                        length: VarInt::from_u32(packet_size as u32),
                        packet_number: packet_number as u32,
                    },
                    PacketType::Handshake => TypeSpecificData::Handshake {
                        length: VarInt::from_u32(packet_size as u32),
                        packet_number: packet_number as u32,
                    },
                    PacketType::ZeroRtt => TypeSpecificData::ZeroRtt {
                        length: VarInt::from_u32(packet_size as u32),
                        packet_number: packet_number as u32,
                    },
                    _ => unreachable!(),
                };
                
                PacketHeader::Long(LongHeader::new(
                    packet_type,
                    0x00000001, // QUIC version 1
                    self.remote_cid.clone(),
                    self.local_cid.clone(),
                    type_specific,
                ))
            }
        };
        
        let packet = Packet::new(
            header,
            encrypted_packet,
            self.local_addr.unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0))),
            self.remote_addr,
        );
        
        self.recovery.on_packet_sent(&packet, frames);
        
        self.bytes_in_flight += packet_size as u64;

        Ok(())
    }

    /// Get packet number space index from packet type
    fn space_index_from_type(packet_type: PacketType) -> usize {
        match packet_type {
            PacketType::Initial | PacketType::Retry => 0,
            PacketType::Handshake => 1,
            PacketType::ZeroRtt | PacketType::OneRtt => 2,
        }
    }
    
    /// Get the next packet number
    fn next_packet_number(&mut self) -> u64 {
        let space = match self.state {
            ConnectionState::Initial => 0,
            ConnectionState::Handshaking => 1,
            _ => 2,
        };
        
        let pn = self.packet_numbers[space];
        self.packet_numbers[space] += 1;
        eprintln!("DEBUG: next_packet_number called, role={:?}, space={}, returning {}, new value={}", 
            self.role, space, pn, self.packet_numbers[space]);
        pn
    }

    /// Consider sending MAX_DATA frame
    fn consider_sending_max_data(&mut self) {
        if self.flow_control.should_send_max_data() {
            self.pending_frames.push_back(Frame::MaxData {
                maximum_data: self.flow_control.max_data_recv,
            });
        }
    }

    /// Consider sending MAX_STREAMS frame
    fn consider_sending_max_streams(&mut self, stream_type: crate::quic::frame_types::StreamType) {
        let should_send = match stream_type {
            crate::quic::frame_types::StreamType::Bidirectional => {
                self.flow_control.streams_bidi_count as f64 / self.flow_control.max_streams_bidi as f64 > 0.5
            }
            crate::quic::frame_types::StreamType::Unidirectional => {
                self.flow_control.streams_uni_count as f64 / self.flow_control.max_streams_uni as f64 > 0.5
            }
        };

        if should_send {
            let maximum_streams = match stream_type {
                crate::quic::frame_types::StreamType::Bidirectional => self.flow_control.max_streams_bidi,
                crate::quic::frame_types::StreamType::Unidirectional => self.flow_control.max_streams_uni,
            };

            self.pending_frames.push_back(Frame::MaxStreams {
                maximum_streams,
                stream_type,
            });
        }
    }

    /// Check if the connection has timed out
    pub fn is_idle_timeout(&self) -> bool {
        let idle_timeout = Duration::from_millis(
            self.transport_params.max_idle_timeout
                .map(|v| v.into_inner())
                .unwrap_or(30000) // Default 30 seconds
        );
        self.last_activity.elapsed() > idle_timeout
    }

    /// Perform periodic maintenance
    pub async fn maintain(&mut self) -> Result<()> {
        let _span = span!(Level::Debug, "maintain", state = self.state, role = self.role);
        
        // Check for idle timeout
        if self.is_idle_timeout() {
            protocol_event!(
                Level::Warn,
                "Connection idle timeout";
                "role" => self.role,
                "local_cid" => self.local_cid
            );
            self.close(ConnectionErrorCode::NoError, "Idle timeout".to_string()).await?;
            return Ok(());
        }

        // Check for loss recovery
        if let Some(frames_to_retransmit) = self.recovery.check_loss_detection() {
            if !frames_to_retransmit.is_empty() {
                // Queue frames for retransmission
                for frame in frames_to_retransmit {
                    self.pending_frames.push_back(frame);
                }
                // Send the queued frames
                self.send_pending_frames().await?;
            }
        }

        // Update congestion controller
        self.congestion.update();

        // Check draining period
        if let ConnectionState::Closing { drain_timeout, .. } = self.state {
            if Instant::now() >= drain_timeout {
                protocol_event!(
                    Level::Info,
                    "Connection draining period complete, closing";
                    "role" => self.role,
                    "local_cid" => self.local_cid
                );
                self.state = ConnectionState::Closed;
            }
        }

        Ok(())
    }

    /// Process peer transport parameters received during handshake
    pub fn process_peer_transport_params(&mut self, peer_params: TransportParameters) -> Result<()> {
        // Validate peer parameters
        peer_params.validate()?;
        
        // Store peer parameters
        self.peer_transport_params = Some(peer_params.clone());
        
        // Apply peer parameters to flow control
        self.apply_peer_transport_params(&peer_params)?;
        
        Ok(())
    }
    
    /// Apply peer transport parameters to connection state
    fn apply_peer_transport_params(&mut self, peer_params: &TransportParameters) -> Result<()> {
        // Update stream manager with peer parameters
        self.stream_manager.update_peer_params(peer_params);
        
        // Update flow control limits based on peer's advertised values
        if let Some(max_data) = peer_params.initial_max_data {
            self.flow_control.max_data = max_data.into_inner();
        }
        
        if let Some(max_streams_bidi) = peer_params.initial_max_streams_bidi {
            self.flow_control.max_streams_bidi = max_streams_bidi.into_inner();
        }
        
        if let Some(max_streams_uni) = peer_params.initial_max_streams_uni {
            self.flow_control.max_streams_uni = max_streams_uni.into_inner();
        }
        
        // Apply connection-level parameters
        if let Some(max_idle_timeout) = peer_params.max_idle_timeout {
            // Use the minimum of local and peer idle timeout
            let local_timeout = self.transport_params.max_idle_timeout
                .map(|v| v.into_inner())
                .unwrap_or(u64::MAX);
            let peer_timeout = max_idle_timeout.into_inner();
            let min_timeout = local_timeout.min(peer_timeout);
            self.transport_params.max_idle_timeout = Some(VarInt::from_u64(min_timeout)?);
        }
        
        // Update ACK delay parameters for recovery
        if let Some(ack_delay_exponent) = peer_params.ack_delay_exponent {
            self.recovery.set_ack_delay_exponent(ack_delay_exponent.into_inner() as u8);
        }
        
        if let Some(max_ack_delay) = peer_params.max_ack_delay {
            self.recovery.set_max_ack_delay(Duration::from_millis(max_ack_delay.into_inner()));
        }
        
        // Store active connection ID limit
        if let Some(active_cid_limit) = peer_params.active_connection_id_limit {
            let limit = active_cid_limit.into_inner();
            if limit < 2 {
                return Err(Error::ProtocolViolation("Peer active_connection_id_limit too small".to_string()));
            }
            // TODO: Use this limit when managing connection IDs
        }
        
        // Handle preferred address if provided
        if let Some(ref preferred_addr) = peer_params.preferred_address {
            // TODO: Implement connection migration to preferred address
            debug!("Peer provided preferred address: {:?}", preferred_addr);
        }
        
        // Check for disable_active_migration
        if peer_params.disable_active_migration {
            // TODO: Disable connection migration
            debug!("Peer disabled active migration");
        }
        
        Ok(())
    }
    
    /// Get local transport parameters to send to peer
    pub fn get_transport_params(&self) -> &TransportParameters {
        &self.transport_params
    }
    
    /// Get peer transport parameters if available
    pub fn get_peer_transport_params(&self) -> Option<&TransportParameters> {
        self.peer_transport_params.as_ref()
    }
    
    /// Get statistics about the connection
    pub fn stats(&self) -> ConnectionStats {
        ConnectionStats {
            state: self.state.clone(),
            streams_count: self.stream_manager.active_streams().len(),
            data_sent: self.flow_control.data_sent,
            data_recv: self.flow_control.data_recv,
            packets_sent: self.recovery.packets_sent(),
            packets_recv: self.recovery.packets_recv(),
            rtt: self.recovery.rtt(),
            cwnd: self.congestion.congestion_window(),
            bytes_in_flight: self.bytes_in_flight,
            available_send_window: self.flow_control.available_send_window(),
            available_recv_window: self.flow_control.available_recv_window(),
            congestion_limited: !self.congestion.can_send(self.bytes_in_flight),
            flow_control_limited: !self.flow_control.can_send_data(1),
        }
    }
    
    /// Handle version negotiation packet (client side)
    pub async fn handle_version_negotiation(&mut self, packet: &VersionNegotiationPacket) -> Result<()> {
        if self.role != ConnectionRole::Client {
            return Err(Error::Internal("Version negotiation is only for clients".to_string()));
        }
        
        protocol_event!(
            Level::Info,
            "Received version negotiation packet";
            "supported_versions" => packet.supported_versions.iter()
                .map(|v| format!("0x{:08x}", v))
                .collect::<Vec<_>>()
                .join(", ")
        );
        
        // Select a mutually supported version
        let new_version = self.version_negotiator.handle_version_negotiation(packet)?;
        
        if new_version != self.quic_version {
            // Update to new version
            self.quic_version = new_version;
            
            // Reset connection state for new version
            self.state = ConnectionState::Initial;
            self.packet_numbers = [0; 3];
            
            // Re-initialize crypto with new version
            self.crypto = CryptoManager::new(self.role)?;
            self.crypto.set_connection_ids(self.local_cid.clone(), self.remote_cid.clone());
            
            let initial_dcid = self.remote_cid.as_bytes();
            self.crypto.init_initial_keys(initial_dcid)?;
            self.crypto.set_transport_params(self.transport_params.clone());
            
            protocol_event!(
                Level::Info,
                "Switched to negotiated version";
                "version" => format!("0x{:08x}", new_version)
            );
        }
        
        Ok(())
    }
    
    /// Check if version negotiation is needed for incoming packet
    pub fn needs_version_negotiation(&self, packet_version: u32) -> bool {
        self.role == ConnectionRole::Server && 
        self.version_negotiator.needs_negotiation(packet_version)
    }
    
    /// Create version negotiation packet
    pub fn create_version_negotiation_packet(
        &self, 
        src_cid: ConnectionId,
        dst_cid: ConnectionId,
    ) -> VersionNegotiationPacket {
        self.version_negotiator.create_version_negotiation(dst_cid, src_cid)
    }
    
    /// Get current QUIC version
    pub fn quic_version(&self) -> u32 {
        self.quic_version
    }
    
    /// Get supported versions
    pub fn supported_versions(&self) -> &[u32] {
        self.version_negotiator.supported_versions()
    }
    
    /// Parse connection IDs from packet header (for version negotiation)
    fn parse_connection_ids_from_packet(&self, packet_data: &[u8]) -> Result<(ConnectionId, ConnectionId)> {
        if packet_data.len() < 6 {
            return Err(Error::PacketTooShort);
        }
        
        let mut offset = 5; // Skip first byte and version
        
        // Parse destination connection ID
        if packet_data.len() <= offset {
            return Err(Error::PacketTooShort);
        }
        let dcid_len = packet_data[offset] as usize;
        offset += 1;
        
        if packet_data.len() < offset + dcid_len {
            return Err(Error::PacketTooShort);
        }
        let dst_cid = ConnectionId::from_slice(&packet_data[offset..offset + dcid_len]);
        offset += dcid_len;
        
        // Parse source connection ID
        if packet_data.len() <= offset {
            return Err(Error::PacketTooShort);
        }
        let scid_len = packet_data[offset] as usize;
        offset += 1;
        
        if packet_data.len() < offset + scid_len {
            return Err(Error::PacketTooShort);
        }
        let src_cid = ConnectionId::from_slice(&packet_data[offset..offset + scid_len]);
        
        Ok((dst_cid, src_cid))
    }
    
    /// Determine packet type from header
    fn determine_packet_type(&self, header: &PacketHeader) -> Result<PacketType> {
        match header {
            PacketHeader::Long(long_header) => {
                Ok(long_header.packet_type)
            }
            PacketHeader::Short(_) => {
                Ok(PacketType::OneRtt)
            }
        }
    }
    
    /// Set crypto manager (for testing with custom TLS config)
    pub fn set_crypto_manager(&mut self, crypto: CryptoManager) {
        self.crypto = crypto;
    }
}

/// Connection statistics
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    /// Current connection state
    pub state: ConnectionState,
    /// Number of active streams
    pub streams_count: usize,
    /// Total bytes sent
    pub data_sent: u64,
    /// Total bytes received
    pub data_recv: u64,
    /// Total packets sent
    pub packets_sent: u64,
    /// Total packets received
    pub packets_recv: u64,
    /// Current round-trip time
    pub rtt: Duration,
    /// Current congestion window
    pub cwnd: u64,
    /// Bytes in flight (unacknowledged)
    pub bytes_in_flight: u64,
    /// Available send window
    pub available_send_window: u64,
    /// Available receive window
    pub available_recv_window: u64,
    /// Whether sending is limited by congestion control
    pub congestion_limited: bool,
    /// Whether sending is limited by flow control
    pub flow_control_limited: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn connection_state_transitions() {
        assert!(ConnectionState::Initial.is_handshaking());
        assert!(ConnectionState::Handshaking.is_handshaking());
        assert!(!ConnectionState::Established.is_handshaking());
        
        assert!(ConnectionState::Established.can_send_app_data());
        assert!(ConnectionState::EarlyData.can_send_app_data());
        assert!(!ConnectionState::Initial.can_send_app_data());
    }

    #[tokio::test]
    async fn connection_creation() -> Result<()> {
        let local_cid = ConnectionId::random(8)?;
        let remote_cid = ConnectionId::random(8)?;
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        let transport_params = TransportParameters::default();

        let conn = Connection::new(
            ConnectionRole::Client,
            local_cid,
            remote_cid,
            remote_addr,
            transport_params,
        ).unwrap();

        assert_eq!(conn.state(), ConnectionState::Initial);
        assert_eq!(conn.role(), ConnectionRole::Client);
        Ok(())
    }

    #[tokio::test]
    async fn stream_management() -> Result<()> {
        let local_cid = ConnectionId::random(8)?;
        let remote_cid = ConnectionId::random(8)?;
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        let transport_params = TransportParameters::default();

        let mut conn = Connection::new(
            ConnectionRole::Client,
            local_cid,
            remote_cid,
            remote_addr,
            transport_params,
        ).unwrap();

        // Should not be able to open streams in initial state
        assert!(conn.open_stream(StreamType::Bidirectional).is_err());

        // Change state to established
        conn.state = ConnectionState::Established;

        // Should be able to open streams now
        let stream_id = conn.open_stream(StreamType::Bidirectional).unwrap();
        // Stream should be created in stream manager
        assert!(conn.stream_manager.stream_stats(stream_id).is_some());
        Ok(())
    }
}