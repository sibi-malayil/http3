//! WebTransport Implementation (RFC 9114 Section 7.4)
//!
//! WebTransport provides a framework for multiplexing bidirectional streams 
//! and unreliable datagrams over HTTP/3. This implementation supports:
//! - WebTransport session establishment
//! - Bidirectional stream management
//! - Unreliable datagram transmission
//! - Session lifecycle management
//! - Capsule protocol support

use crate::{
    error::{Result, Http3ErrorCode},
    error_context::ErrorConversion,
    http3::{
        datagram::{DatagramManager, DatagramResult},
        frame::Http3Frame,
        ConnectionRole,
    },
    quic::{
        stream::StreamId,
        unreliable::{UnreliableDeliveryManager},
        connection::ConnectionRole as QuicConnectionRole,
    },
    util::time::Instant,
    whathappened::Level,
    protocol_event,
};
use bytes::Bytes;
use std::collections::{HashMap, VecDeque};

/// WebTransport protocol identifier
pub const WEBTRANSPORT_PROTOCOL: &str = "webtransport";

/// Simple header field for WebTransport  
#[derive(Debug, Clone)]
pub struct HeaderField {
    /// Header name
    pub name: Vec<u8>,
    /// Header value  
    pub value: Vec<u8>,
}

/// WebTransport session ID type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(u64);

impl SessionId {
    /// Create a new session ID
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Get the raw session ID value
    pub fn value(&self) -> u64 {
        self.0
    }
}

impl From<u64> for SessionId {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

impl From<SessionId> for u64 {
    fn from(session: SessionId) -> u64 {
        session.0
    }
}

/// WebTransport session state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// Session is being established
    Establishing,
    /// Session is active and ready for use
    Active,
    /// Session is being closed
    Closing,
    /// Session is closed
    Closed,
    /// Session failed to establish
    Failed,
}

/// WebTransport stream type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebTransportStreamType {
    /// Bidirectional stream
    Bidirectional,
    /// Unidirectional outgoing stream
    UnidirectionalOutgoing,
    /// Unidirectional incoming stream
    UnidirectionalIncoming,
}

/// WebTransport session configuration
#[derive(Debug, Clone)]
pub struct WebTransportConfig {
    /// Maximum number of concurrent sessions
    pub max_sessions: usize,
    /// Maximum number of streams per session
    pub max_streams_per_session: usize,
    /// Maximum datagram size
    pub max_datagram_size: usize,
    /// Enable unreliable datagram support
    pub enable_datagrams: bool,
    /// Session idle timeout in seconds
    pub session_idle_timeout: u64,
    /// Enable statistics collection
    pub collect_stats: bool,
}

impl Default for WebTransportConfig {
    fn default() -> Self {
        Self {
            max_sessions: 100,
            max_streams_per_session: 1000,
            max_datagram_size: 1200,
            enable_datagrams: true,
            session_idle_timeout: 300, // 5 minutes
            collect_stats: true,
        }
    }
}

/// WebTransport statistics
#[derive(Debug, Clone, Default)]
pub struct WebTransportStats {
    /// Total sessions established
    pub sessions_established: u64,
    /// Total sessions closed
    pub sessions_closed: u64,
    /// Active sessions count
    pub active_sessions: usize,
    /// Total streams created
    pub streams_created: u64,
    /// Total datagrams sent
    pub datagrams_sent: u64,
    /// Total datagrams received
    pub datagrams_received: u64,
    /// Total bytes sent via datagrams
    pub datagram_bytes_sent: u64,
    /// Total bytes received via datagrams
    pub datagram_bytes_received: u64,
    /// Sessions failed to establish
    pub sessions_failed: u64,
}

/// WebTransport session information
#[derive(Debug, Clone)]
pub struct WebTransportSession {
    /// Session ID
    pub session_id: SessionId,
    /// Associated HTTP/3 stream ID
    pub stream_id: StreamId,
    /// Session state
    pub state: SessionState,
    /// Session origin
    pub origin: String,
    /// Session path
    pub path: String,
    /// Active streams in this session
    pub streams: HashMap<StreamId, WebTransportStreamType>,
    /// Session creation time
    pub created_at: Instant,
    /// Last activity time
    pub last_activity: Instant,
    /// Session statistics
    pub stats: SessionStats,
}

/// Per-session statistics
#[derive(Debug, Clone, Default)]
pub struct SessionStats {
    /// Streams created in this session
    pub streams_created: u64,
    /// Datagrams sent in this session
    pub datagrams_sent: u64,
    /// Datagrams received in this session
    pub datagrams_received: u64,
    /// Bytes sent via datagrams
    pub datagram_bytes_sent: u64,
    /// Bytes received via datagrams
    pub datagram_bytes_received: u64,
}

impl WebTransportSession {
    /// Create a new WebTransport session
    pub fn new(session_id: SessionId, stream_id: StreamId, origin: String, path: String) -> Self {
        let now = Instant::now();
        Self {
            session_id,
            stream_id,
            state: SessionState::Establishing,
            origin,
            path,
            streams: HashMap::new(),
            created_at: now,
            last_activity: now,
            stats: SessionStats::default(),
        }
    }

    /// Mark session as active
    pub fn mark_active(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Add a stream to this session
    pub fn add_stream(&mut self, stream_id: StreamId, stream_type: WebTransportStreamType) {
        self.streams.insert(stream_id, stream_type);
        self.stats.streams_created += 1;
        let _ = self.mark_active();
    }

    /// Remove a stream from this session
    pub fn remove_stream(&mut self, stream_id: StreamId) {
        self.streams.remove(&stream_id);
        let _ = self.mark_active();
    }

    /// Check if session is active
    pub fn is_active(&self) -> bool {
        self.state == SessionState::Active
    }

    /// Check if session has expired
    pub fn is_expired(&self, timeout_seconds: u64) -> bool {
        self.last_activity.elapsed().as_secs() > timeout_seconds
    }
}

/// WebTransport stream event
#[derive(Debug, Clone)]
pub enum WebTransportStreamEvent {
    /// New stream created
    StreamCreated {
        session_id: SessionId,
        stream_id: StreamId,
    },
    /// Stream closed
    StreamClosed {
        session_id: SessionId,
        stream_id: StreamId,
    },
    /// Data received on stream
    StreamData {
        session_id: SessionId,
        stream_id: StreamId,
        data: Bytes,
        fin: bool,
    },
}

/// WebTransport datagram event
#[derive(Debug, Clone)]
pub struct WebTransportDatagram {
    /// Session ID
    pub session_id: SessionId,
    /// Datagram data
    pub data: Bytes,
    /// Time when datagram was received
    pub received_at: Instant,
}

/// WebTransport Manager
///
/// Manages WebTransport sessions, streams, and datagrams over HTTP/3
#[derive(Debug)]
pub struct WebTransportManager {
    /// Configuration
    config: WebTransportConfig,
    /// Active sessions by session ID
    sessions: HashMap<SessionId, WebTransportSession>,
    /// Session lookup by stream ID
    stream_to_session: HashMap<StreamId, SessionId>,
    /// Next session ID
    next_session_id: u64,
    /// Connection role
    connection_role: ConnectionRole,
    /// Datagram manager
    datagram_manager: DatagramManager,
    /// Unreliable delivery manager
    unreliable_manager: UnreliableDeliveryManager,
    /// Pending stream events
    stream_events: VecDeque<WebTransportStreamEvent>,
    /// Received datagrams
    received_datagrams: VecDeque<WebTransportDatagram>,
    /// Statistics
    stats: WebTransportStats,
}

impl WebTransportManager {
    /// Create a new WebTransport manager
    pub fn new(config: WebTransportConfig, connection_role: ConnectionRole) -> Self {
        let quic_role = match connection_role {
            ConnectionRole::Client => QuicConnectionRole::Client,
            ConnectionRole::Server => QuicConnectionRole::Server,
        };

        Self {
            config: config.clone(),
            sessions: HashMap::new(),
            stream_to_session: HashMap::new(),
            next_session_id: 1,
            connection_role,
            datagram_manager: DatagramManager::default(),
            unreliable_manager: UnreliableDeliveryManager::default_for_role(quic_role),
            stream_events: VecDeque::new(),
            received_datagrams: VecDeque::new(),
            stats: WebTransportStats::default(),
        }
    }

    /// Create manager with default configuration
    pub fn default_for_role(connection_role: ConnectionRole) -> Self {
        Self::new(WebTransportConfig::default(), connection_role)
    }

    /// Establish a new WebTransport session
    pub fn establish_session(
        &mut self,
        stream_id: StreamId,
        headers: &[HeaderField],
    ) -> Result<SessionId> {
        // Validate session establishment request
        if self.sessions.len() >= self.config.max_sessions {
            return Err("Maximum number of sessions reached".to_http3_error(Http3ErrorCode::ExcessiveLoad));
        }

        // Extract origin and path from headers
        let mut origin = None;
        let mut path = None;
        let mut protocol = None;

        for header in headers {
            let name_str = String::from_utf8_lossy(&header.name);
            match name_str.as_ref() {
                ":authority" | "origin" => {
                    origin = Some(String::from_utf8_lossy(&header.value).to_string());
                }
                ":path" => {
                    path = Some(String::from_utf8_lossy(&header.value).to_string());
                }
                ":protocol" => {
                    protocol = Some(String::from_utf8_lossy(&header.value).to_string());
                }
                _ => {}
            }
        }

        // Validate protocol
        if protocol.as_deref() != Some(WEBTRANSPORT_PROTOCOL) {
            return Err("Invalid WebTransport protocol".to_http3_error(Http3ErrorCode::GeneralProtocolError));
        }

        let origin = origin.unwrap_or_else(|| "unknown".to_string());
        let path = path.unwrap_or_else(|| "/".to_string());

        // Create new session
        let session_id = SessionId::new(self.next_session_id);
        self.next_session_id += 1;

        let mut session = WebTransportSession::new(session_id, stream_id, origin.clone(), path.clone());
        session.state = SessionState::Active;

        // Register session
        self.sessions.insert(session_id, session);
        self.stream_to_session.insert(stream_id, session_id);

        // Update statistics
        self.stats.sessions_established += 1;
        self.stats.active_sessions = self.sessions.len();

        protocol_event!(
            Level::Info,
            "WebTransport session established";
            "session_id" => session_id.value(),
            "stream_id" => stream_id.into_inner(),
            "origin" => origin,
            "path" => path
        );

        Ok(session_id)
    }

    /// Close a WebTransport session
    pub fn close_session(&mut self, session_id: SessionId) -> Result<()> {
        if let Some(mut session) = self.sessions.remove(&session_id) {
            session.state = SessionState::Closed;
            
            // Remove stream mappings
            let stream_ids: Vec<StreamId> = session.streams.keys().cloned().collect();
            for stream_id in stream_ids {
                self.stream_to_session.remove(&stream_id);
                
                // Generate stream closed events
                self.stream_events.push_back(WebTransportStreamEvent::StreamClosed {
                    session_id,
                    stream_id,
                });
            }

            // Remove main session stream mapping
            self.stream_to_session.remove(&session.stream_id);

            // Update statistics
            self.stats.sessions_closed += 1;
            self.stats.active_sessions = self.sessions.len();

            protocol_event!(
                Level::Info,
                "WebTransport session closed";
                "session_id" => session_id.value(),
                "streams_closed" => session.streams.len()
            );

            Ok(())
        } else {
            Err("Session not found".to_http3_error(Http3ErrorCode::IdError))
        }
    }

    /// Add a stream to a WebTransport session
    pub fn add_stream(
        &mut self,
        session_id: SessionId,
        stream_id: StreamId,
        stream_type: WebTransportStreamType,
    ) -> Result<()> {
        if let Some(session) = self.sessions.get_mut(&session_id) {
            if !session.is_active() {
                return Err("Session not active".to_http3_error(Http3ErrorCode::ClosedCriticalStream));
            }

            if session.streams.len() >= self.config.max_streams_per_session {
                return Err("Maximum streams per session reached".to_http3_error(Http3ErrorCode::ExcessiveLoad));
            }

            session.add_stream(stream_id, stream_type);
            self.stream_to_session.insert(stream_id, session_id);

            // Update statistics
            self.stats.streams_created += 1;

            // Generate stream event
            self.stream_events.push_back(WebTransportStreamEvent::StreamCreated {
                session_id,
                stream_id,
            });

            protocol_event!(
                Level::Debug,
                "WebTransport stream added";
                "session_id" => session_id.value(),
                "stream_id" => stream_id.into_inner(),
                "stream_type" => format!("{:?}", stream_type)
            );

            Ok(())
        } else {
            Err("Session not found".to_http3_error(Http3ErrorCode::IdError))
        }
    }

    /// Remove a stream from a WebTransport session
    pub fn remove_stream(&mut self, stream_id: StreamId) -> Result<()> {
        if let Some(session_id) = self.stream_to_session.remove(&stream_id) {
            if let Some(session) = self.sessions.get_mut(&session_id) {
                session.remove_stream(stream_id);

                // Generate stream event
                self.stream_events.push_back(WebTransportStreamEvent::StreamClosed {
                    session_id,
                    stream_id,
                });

                protocol_event!(
                    Level::Debug,
                    "WebTransport stream removed";
                    "session_id" => session_id.value(),
                    "stream_id" => stream_id.into_inner()
                );
            }
            Ok(())
        } else {
            Err("Stream not found in any session".to_http3_error(Http3ErrorCode::IdError))
        }
    }

    /// Send a WebTransport datagram
    pub fn send_datagram(&mut self, session_id: SessionId, data: Bytes) -> Result<DatagramResult> {
        if !self.config.enable_datagrams {
            return Err("Datagrams not enabled".to_http3_error(Http3ErrorCode::FrameUnexpected));
        }

        if let Some(session) = self.sessions.get_mut(&session_id) {
            if !session.is_active() {
                return Err("Session not active".to_http3_error(Http3ErrorCode::ClosedCriticalStream));
            }

            if data.len() > self.config.max_datagram_size {
                return Ok(DatagramResult::TooLarge);
            }

            // Send via datagram manager
            let result = self.datagram_manager.send_datagram(session.stream_id, data.clone());

            if result == DatagramResult::Queued || result == DatagramResult::Sent {
                // Update session statistics
                session.stats.datagrams_sent += 1;
                session.stats.datagram_bytes_sent += data.len() as u64;
                session.mark_active();

                // Update global statistics
                self.stats.datagrams_sent += 1;
                self.stats.datagram_bytes_sent += data.len() as u64;

                protocol_event!(
                    Level::Debug,
                    "WebTransport datagram sent";
                    "session_id" => session_id.value(),
                    "size" => data.len()
                );
            }

            Ok(result)
        } else {
            Err("Session not found".to_http3_error(Http3ErrorCode::IdError))
        }
    }

    /// Process a received WebTransport datagram
    pub fn on_datagram_received(&mut self, stream_id: StreamId, data: Bytes) -> Result<()> {
        if let Some(session_id) = self.stream_to_session.get(&stream_id).cloned() {
            if let Some(session) = self.sessions.get_mut(&session_id) {
                if session.is_active() {
                    // Update session statistics
                    session.stats.datagrams_received += 1;
                    session.stats.datagram_bytes_received += data.len() as u64;
                    session.mark_active();

                    // Update global statistics
                    self.stats.datagrams_received += 1;
                    self.stats.datagram_bytes_received += data.len() as u64;

                    let data_len = data.len();
                    
                    // Queue for application processing
                    let datagram = WebTransportDatagram {
                        session_id,
                        data,
                        received_at: Instant::now(),
                    };
                    self.received_datagrams.push_back(datagram);

                    protocol_event!(
                        Level::Debug,
                        "WebTransport datagram received";
                        "session_id" => session_id.value(),
                        "size" => data_len
                    );

                    Ok(())
                } else {
                    Err("Session not active".to_http3_error(Http3ErrorCode::ClosedCriticalStream))
                }
            } else {
                Err("Session not found".to_http3_error(Http3ErrorCode::IdError))
            }
        } else {
            Err("Stream not associated with any session".to_http3_error(Http3ErrorCode::IdError))
        }
    }

    /// Process stream data for WebTransport
    pub fn on_stream_data(
        &mut self,
        stream_id: StreamId,
        data: Bytes,
        fin: bool,
    ) -> Result<()> {
        if let Some(session_id) = self.stream_to_session.get(&stream_id).cloned() {
            if let Some(session) = self.sessions.get_mut(&session_id) {
                session.mark_active();

                // Generate stream data event
                self.stream_events.push_back(WebTransportStreamEvent::StreamData {
                    session_id,
                    stream_id,
                    data,
                    fin,
                });

                Ok(())
            } else {
                Err("Session not found".to_http3_error(Http3ErrorCode::IdError))
            }
        } else {
            Err("Stream not associated with any session".to_http3_error(Http3ErrorCode::IdError))
        }
    }

    /// Get the next datagram frame to transmit
    pub fn next_datagram_frame(&mut self, stream_id: StreamId) -> Option<Http3Frame> {
        self.datagram_manager.next_datagram_frame(stream_id)
    }

    /// Get the next stream event
    pub fn next_stream_event(&mut self) -> Option<WebTransportStreamEvent> {
        self.stream_events.pop_front()
    }

    /// Get the next received datagram
    pub fn next_received_datagram(&mut self) -> Option<WebTransportDatagram> {
        self.received_datagrams.pop_front()
    }

    /// Get session information
    pub fn get_session(&self, session_id: SessionId) -> Option<&WebTransportSession> {
        self.sessions.get(&session_id)
    }

    /// List all active sessions
    pub fn list_sessions(&self) -> Vec<&WebTransportSession> {
        self.sessions.values().collect()
    }

    /// Get session ID for a stream
    pub fn get_session_for_stream(&self, stream_id: StreamId) -> Option<SessionId> {
        self.stream_to_session.get(&stream_id).cloned()
    }

    /// Get current statistics
    pub fn stats(&self) -> WebTransportStats {
        let mut stats = self.stats.clone();
        stats.active_sessions = self.sessions.len();
        stats
    }

    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = WebTransportStats::default();
        self.stats.active_sessions = self.sessions.len();
        
        // Reset session statistics
        for session in self.sessions.values_mut() {
            session.stats = SessionStats::default();
        }
    }

    /// Cleanup expired sessions
    pub fn cleanup_expired_sessions(&mut self) -> usize {
        let mut expired_sessions = Vec::new();
        
        for (session_id, session) in &self.sessions {
            if session.is_expired(self.config.session_idle_timeout) {
                expired_sessions.push(*session_id);
            }
        }

        let cleanup_count = expired_sessions.len();
        for session_id in expired_sessions {
            if let Err(e) = self.close_session(session_id) {
                protocol_event!(
                    Level::Warn,
                    "Failed to close expired session";
                    "session_id" => session_id.value(),
                    "error" => format!("{}", e)
                );
            }
        }

        if cleanup_count > 0 {
            protocol_event!(
                Level::Info,
                "Cleaned up expired WebTransport sessions";
                "count" => cleanup_count
            );
        }

        cleanup_count
    }

    /// Update configuration
    pub fn update_config(&mut self, config: WebTransportConfig) {
        self.config = config;
    }

    /// Get configuration
    pub fn config(&self) -> &WebTransportConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webtransport_session_creation() {
        let session_id = SessionId::new(1);
        let session = WebTransportSession::new(
            session_id,
            stream_id,
            "example.com".to_string(),
            "/webtransport".to_string(),
        );

        assert_eq!(session.session_id, session_id);
        assert_eq!(session.stream_id, stream_id);
        assert_eq!(session.state, SessionState::Establishing);
        assert_eq!(session.origin, "example.com");
        assert_eq!(session.path, "/webtransport");
        assert!(session.streams.is_empty());
    }

    #[test]
    fn test_webtransport_manager_creation() {
        let manager = WebTransportManager::default_for_role(ConnectionRole::Client);
        assert_eq!(manager.sessions.len(), 0);
        assert_eq!(manager.next_session_id, 1);
        assert!(manager.config.enable_datagrams);
    }

    #[test]
    fn test_session_establishment() {
        let mut manager = WebTransportManager::default_for_role(ConnectionRole::Server);
        
        let headers = vec![
            HeaderField::new(HeaderName::from(":protocol"), HeaderValue::from("webtransport")),
            HeaderField::new(HeaderName::from(":authority"), HeaderValue::from("example.com")),
            HeaderField::new(HeaderName::from(":path"), HeaderValue::from("/chat")),
        ];

        let session_id = manager.establish_session(stream_id, &headers).unwrap();
        assert_eq!(session_id.value(), 1);
        assert_eq!(manager.sessions.len(), 1);
        assert!(manager.stream_to_session.contains_key(&stream_id));

        let session = manager.get_session(session_id).unwrap();
        assert_eq!(session.state, SessionState::Active);
        assert_eq!(session.origin, "example.com");
        assert_eq!(session.path, "/chat");
    }

    #[test]
    fn test_stream_management() {
        let mut manager = WebTransportManager::default_for_role(ConnectionRole::Server);
        
        let headers = vec![
            HeaderField::new(HeaderName::from(":protocol"), HeaderValue::from("webtransport")),
            HeaderField::new(HeaderName::from(":authority"), HeaderValue::from("example.com")),
            HeaderField::new(HeaderName::from(":path"), HeaderValue::from("/test")),
        ];

        let session_id = manager.establish_session(main_stream, &headers).unwrap();
        
        // Add a stream
        
        let session = manager.get_session(session_id).unwrap();
        assert!(session.streams.contains_key(&data_stream));
        assert_eq!(session.stats.streams_created, 1);

        // Check stream events
        let event = manager.next_stream_event().unwrap();
        match event {
            WebTransportStreamEvent::StreamCreated { session_id: sid, stream_id: sid2, .. } => {
                assert_eq!(sid, session_id);
                assert_eq!(sid2, data_stream);
            }
            _ => panic!("Expected StreamCreated event"),
        }

        // Remove the stream
        manager.remove_stream(data_stream).unwrap();
        assert!(!manager.stream_to_session.contains_key(&data_stream));
    }

    #[test]
    fn test_datagram_transmission() {
        let mut manager = WebTransportManager::default_for_role(ConnectionRole::Client);
        
        let headers = vec![
            HeaderField::new(HeaderName::from(":protocol"), HeaderValue::from("webtransport")),
            HeaderField::new(HeaderName::from(":authority"), HeaderValue::from("example.com")),
            HeaderField::new(HeaderName::from(":path"), HeaderValue::from("/test")),
        ];

        let session_id = manager.establish_session(stream_id, &headers).unwrap();
        let data = Bytes::from_static(b"Hello WebTransport!");

        // Send datagram
        let result = manager.send_datagram(session_id, data.clone()).unwrap();
        assert_eq!(result, DatagramResult::Queued);

        let session = manager.get_session(session_id).unwrap();
        assert_eq!(session.stats.datagrams_sent, 1);
        assert_eq!(session.stats.datagram_bytes_sent, data.len() as u64);

        // Simulate receiving datagram
        manager.on_datagram_received(stream_id, data.clone()).unwrap();
        
        let received = manager.next_received_datagram().unwrap();
        assert_eq!(received.session_id, session_id);
        assert_eq!(received.data, data);

        let stats = manager.stats();
        assert_eq!(stats.datagrams_sent, 1);
        assert_eq!(stats.datagrams_received, 1);
    }

    #[test]
    fn test_session_cleanup() {
        let mut manager = WebTransportManager::default_for_role(ConnectionRole::Server);
        
        let headers = vec![
            HeaderField::new(HeaderName::from(":protocol"), HeaderValue::from("webtransport")),
            HeaderField::new(HeaderName::from(":authority"), HeaderValue::from("example.com")),
            HeaderField::new(HeaderName::from(":path"), HeaderValue::from("/test")),
        ];

        let session_id = manager.establish_session(stream_id, &headers).unwrap();
        assert_eq!(manager.sessions.len(), 1);

        // Close session
        manager.close_session(session_id).unwrap();
        assert_eq!(manager.sessions.len(), 0);
        assert!(!manager.stream_to_session.contains_key(&stream_id));

        let stats = manager.stats();
        assert_eq!(stats.sessions_established, 1);
        assert_eq!(stats.sessions_closed, 1);
        assert_eq!(stats.active_sessions, 0);
    }

    #[test]
    fn test_invalid_protocol() {
        let mut manager = WebTransportManager::default_for_role(ConnectionRole::Server);
        
        let headers = vec![
            HeaderField::new(HeaderName::from(":protocol"), HeaderValue::from("invalid-protocol")),
            HeaderField::new(HeaderName::from(":authority"), HeaderValue::from("example.com")),
            HeaderField::new(HeaderName::from(":path"), HeaderValue::from("/test")),
        ];

        let result = manager.establish_session(stream_id, &headers);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_limits() {
        let config = WebTransportConfig {
            max_sessions: 1,
            ..Default::default()
        };
        let mut manager = WebTransportManager::new(config, ConnectionRole::Server);
        
        
        let headers = vec![
            HeaderField::new(HeaderName::from(":protocol"), HeaderValue::from("webtransport")),
            HeaderField::new(HeaderName::from(":authority"), HeaderValue::from("example.com")),
            HeaderField::new(HeaderName::from(":path"), HeaderValue::from("/test")),
        ];

        // First session should succeed
        manager.establish_session(stream1, &headers).unwrap();
        
        // Second session should fail due to limit
        let result = manager.establish_session(stream2, &headers);
        assert!(result.is_err());
    }
}