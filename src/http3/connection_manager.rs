//! HTTP/3 Connection Manager with integrated Server Push support
//!
//! Manages HTTP/3 connections including stream multiplexing, frame routing,
//! server push coordination, and protocol compliance.

use crate::{
    error::{Error, Result, Http3ErrorCode},
    error_context::ErrorConversion,
    http3::{
        settings::Settings,
        priority::PriorityUpdateFrame,
        frame::{Http3Frame, PushPromiseFrame, CancelPushFrame, MaxPushIdFrame},
        server_push::{ServerPushManager, ServerPushConfig, PushPromise},
        webtransport::HeaderField,
        ConnectionRole, StreamType,
    },
    util::varint::VarInt,
    whathappened::Level,
    protocol_event,
};
use bytes::Bytes;
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{RwLock, Mutex};

/// Stream state in HTTP/3 connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Stream is idle
    Idle,
    /// Stream is open for sending/receiving
    Open,
    /// Stream is half-closed (local)
    HalfClosedLocal,
    /// Stream is half-closed (remote)
    HalfClosedRemote,
    /// Stream is fully closed
    Closed,
    /// Stream was reset
    Reset,
}

/// HTTP/3 stream information
#[derive(Debug, Clone)]
pub struct StreamInfo {
    /// Stream ID
    pub stream_id: u64,
    /// Stream state
    pub state: StreamState,
    /// Stream type (for unidirectional streams)
    pub stream_type: Option<StreamType>,
    /// Whether this is a push stream
    pub is_push_stream: bool,
    /// Associated push ID (for push streams)
    pub push_id: Option<u64>,
    /// Headers received/sent
    pub headers: Vec<HeaderField>,
    /// Data bytes transferred
    pub bytes_transferred: u64,
    /// Stream creation time
    pub created_at: Instant,
    /// Last activity time
    pub last_activity: Instant,
}

impl StreamInfo {
    /// Create new stream info
    pub fn new(stream_id: u64) -> Self {
        let now = Instant::now();
        Self {
            stream_id,
            state: StreamState::Idle,
            stream_type: None,
            is_push_stream: false,
            push_id: None,
            headers: Vec::new(),
            bytes_transferred: 0,
            created_at: now,
            last_activity: now,
        }
    }

    /// Mark stream as active
    pub fn mark_active(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Check if stream can receive frames
    pub fn can_receive(&self) -> bool {
        matches!(self.state, StreamState::Open | StreamState::HalfClosedLocal)
    }

    /// Check if stream can send frames
    pub fn can_send(&self) -> bool {
        matches!(self.state, StreamState::Open | StreamState::HalfClosedRemote)
    }
}

/// HTTP/3 Connection Manager
pub struct ConnectionManager {
    /// Connection role (client or server)
    role: ConnectionRole,
    /// Connection settings
    settings: Arc<RwLock<Settings>>,
    /// Peer settings
    peer_settings: Arc<RwLock<Settings>>,
    /// Stream information by stream ID
    streams: Arc<RwLock<HashMap<u64, StreamInfo>>>,
    /// Server push manager (server only)
    push_manager: Option<Arc<ServerPushManager>>,
    /// Control stream ID
    control_stream_id: Arc<RwLock<Option<u64>>>,
    /// QPACK encoder stream ID
    qpack_encoder_stream_id: Arc<RwLock<Option<u64>>>,
    /// QPACK decoder stream ID
    qpack_decoder_stream_id: Arc<RwLock<Option<u64>>>,
    /// Next client-initiated stream ID
    next_client_stream_id: Arc<RwLock<u64>>,
    /// Next server-initiated stream ID
    next_server_stream_id: Arc<RwLock<u64>>,
    /// Frame processing queue
    frame_queue: Arc<Mutex<VecDeque<(u64, Http3Frame)>>>,
    /// Connection statistics
    stats: Arc<RwLock<ConnectionStats>>,
}

/// Connection statistics
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    /// Total streams created
    pub streams_created: u64,
    /// Active streams count
    pub active_streams: usize,
    /// Total frames processed
    pub frames_processed: u64,
    /// Total bytes transferred
    pub bytes_transferred: u64,
    /// Push promises made (server only)
    pub push_promises_made: u64,
    /// Push promises completed
    pub push_promises_completed: u64,
    /// Push promises cancelled
    pub push_promises_cancelled: u64,
}

impl ConnectionManager {
    /// Create a new connection manager
    pub fn new(role: ConnectionRole, push_config: Option<ServerPushConfig>) -> Self {
        let push_manager = if role == ConnectionRole::Server {
            push_config.map(|config| Arc::new(ServerPushManager::new(config)))
        } else {
            None
        };

        // Initialize stream IDs based on role
        let (next_client_stream_id, next_server_stream_id) = match role {
            ConnectionRole::Client => (0, 1), // Client: 0, 4, 8... Server: 1, 5, 9...
            ConnectionRole::Server => (1, 0), // Server: 1, 5, 9... Client: 0, 4, 8...
        };

        Self {
            role,
            settings: Arc::new(RwLock::new(Settings::new())),
            peer_settings: Arc::new(RwLock::new(Settings::new())),
            streams: Arc::new(RwLock::new(HashMap::new())),
            push_manager,
            control_stream_id: Arc::new(RwLock::new(None)),
            qpack_encoder_stream_id: Arc::new(RwLock::new(None)),
            qpack_decoder_stream_id: Arc::new(RwLock::new(None)),
            next_client_stream_id: Arc::new(RwLock::new(next_client_stream_id)),
            next_server_stream_id: Arc::new(RwLock::new(next_server_stream_id)),
            frame_queue: Arc::new(Mutex::new(VecDeque::new())),
            stats: Arc::new(RwLock::new(ConnectionStats::default())),
        }
    }

    /// Process an incoming frame on a stream
    pub async fn process_frame(&self, stream_id: u64, frame: Http3Frame) -> Result<Vec<Http3Frame>> {
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.frames_processed += 1;
        }

        // Ensure stream exists
        self.ensure_stream_exists(stream_id).await?;

        // Mark stream as active
        {
            let mut streams = self.streams.write().await;
            if let Some(stream) = streams.get_mut(&stream_id) {
                stream.mark_active();
            }
        }

        // Process frame based on type
        match frame {
            Http3Frame::Data(data_frame) => {
                self.process_data_frame(stream_id, data_frame).await
            }
            Http3Frame::Headers(headers_frame) => {
                self.process_headers_frame(stream_id, headers_frame)
            }
            Http3Frame::Settings(settings_frame) => {
                self.process_settings_frame(stream_id, settings_frame).await
            }
            Http3Frame::PushPromise(push_promise_frame) => {
                self.process_push_promise_frame(stream_id, push_promise_frame)
            }
            Http3Frame::CancelPush(cancel_push_frame) => {
                self.process_cancel_push_frame(stream_id, cancel_push_frame).await
            }
            Http3Frame::MaxPushId(max_push_id_frame) => {
                self.process_max_push_id_frame(stream_id, max_push_id_frame).await
            }
            Http3Frame::PriorityUpdate(priority_frame) => {
                self.process_priority_update_frame(stream_id, priority_frame)
            }
            Http3Frame::Goaway(goaway_frame) => {
                self.process_goaway_frame(stream_id, goaway_frame)
            }
            Http3Frame::MaxStreams(max_streams_frame) => {
                self.process_max_streams_frame(stream_id, max_streams_frame).await
            }
            Http3Frame::StreamsBlocked(streams_blocked_frame) => {
                self.process_streams_blocked_frame(stream_id, streams_blocked_frame).await
            }
            Http3Frame::Datagram(datagram_frame) => {
                self.process_datagram_frame(stream_id, datagram_frame).await
            }
            Http3Frame::Unknown { frame_type, payload } => {
                self.process_unknown_frame(stream_id, frame_type, payload)
            }
        }
    }

    /// Create a push promise for a resource
    pub async fn create_push_promise(
        &self,
        request_stream_id: u64,
        headers: Vec<HeaderField>,
    ) -> Result<Option<Http3Frame>> {
        if self.role != ConnectionRole::Server {
            return Err("Only servers can create push promises"
                .to_http3_error(Http3ErrorCode::FrameUnexpected));
        }

        let push_manager = self.push_manager.as_ref()
            .ok_or_else(|| Error::Http3Error {
                code: Http3ErrorCode::InternalError,
                reason: "Push manager not available".to_string(),
            })?;

        if let Some(push_promise_frame) = push_manager
            .create_push_promise(request_stream_id, headers)
            .await?
        {
            // Update statistics
            {
                let mut stats = self.stats.write().await;
                stats.push_promises_made += 1;
            }

            protocol_event!(
                Level::Info,
                "Created push promise";
                "request_stream_id" => request_stream_id,
                "push_id" => push_promise_frame.push_id.0
            );

            Ok(Some(Http3Frame::PushPromise(push_promise_frame)))
        } else {
            Ok(None)
        }
    }

    /// Start a push stream
    pub async fn start_push_stream(
        &self,
        push_id: u64,
        response_headers: Vec<HeaderField>,
    ) -> Result<u64> {
        if self.role != ConnectionRole::Server {
            return Err("Only servers can start push streams"
                .to_http3_error(Http3ErrorCode::FrameUnexpected));
        }

        let push_manager = self.push_manager.as_ref()
            .ok_or_else(|| Error::Http3Error {
                code: Http3ErrorCode::InternalError,
                reason: "Push manager not available".to_string(),
            })?;

        // Allocate a new server-initiated stream ID
        let push_stream_id = {
            let mut next_id = self.next_server_stream_id.write().await;
            let id = *next_id;
            *next_id += 4; // Server streams: 1, 5, 9, 13...
            id
        };

        // Create stream info
        let mut stream_info = StreamInfo::new(push_stream_id);
        stream_info.state = StreamState::Open;
        stream_info.stream_type = Some(StreamType::Push);
        stream_info.is_push_stream = true;
        stream_info.push_id = Some(push_id);
        stream_info.headers = response_headers.clone();

        // Add to streams
        {
            let mut streams = self.streams.write().await;
            streams.insert(push_stream_id, stream_info);
        }

        // Start the push stream
        push_manager.start_push_stream(push_id, push_stream_id, response_headers).await?;

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.streams_created += 1;
            stats.active_streams += 1;
        }

        protocol_event!(
            Level::Info,
            "Started push stream";
            "push_id" => push_id,
            "push_stream_id" => push_stream_id
        );

        Ok(push_stream_id)
    }

    /// Get push promise information
    pub async fn get_push_promise(&self, push_id: u64) -> Option<PushPromise> {
        if let Some(push_manager) = &self.push_manager {
            push_manager.get_push_promise(push_id).await
        } else {
            None
        }
    }

    /// Get all push promises for a request stream
    pub async fn get_pushes_for_stream(&self, stream_id: u64) -> Vec<PushPromise> {
        if let Some(push_manager) = &self.push_manager {
            push_manager.get_pushes_for_stream(stream_id).await
        } else {
            Vec::new()
        }
    }

    /// Get connection statistics
    pub async fn get_stats(&self) -> ConnectionStats {
        self.stats.read().await.clone()
    }

    /// Get stream information
    pub async fn get_stream_info(&self, stream_id: u64) -> Option<StreamInfo> {
        self.streams.read().await.get(&stream_id).cloned()
    }

    /// List all active streams
    pub async fn list_active_streams(&self) -> Vec<StreamInfo> {
        self.streams.read().await
            .values()
            .filter(|s| matches!(s.state, StreamState::Open | StreamState::HalfClosedLocal | StreamState::HalfClosedRemote))
            .cloned()
            .collect()
    }

    /// Cleanup old and completed resources
    pub async fn cleanup(&self) -> usize {
        let mut cleaned_up = 0;

        // Cleanup old push promises
        if let Some(push_manager) = &self.push_manager {
            cleaned_up += push_manager.cleanup_old_pushes().await;
        }

        // Cleanup closed streams older than 5 minutes
        let retention_duration = Duration::from_secs(300);
        let now = Instant::now();

        {
            let mut streams = self.streams.write().await;
            let mut to_remove = Vec::new();

            for (stream_id, stream) in streams.iter() {
                if matches!(stream.state, StreamState::Closed | StreamState::Reset) {
                    if now.duration_since(stream.last_activity) > retention_duration {
                        to_remove.push(*stream_id);
                    }
                }
            }

            for stream_id in &to_remove {
                streams.remove(stream_id);
                cleaned_up += 1;
            }

            // Update active streams count
            let mut stats = self.stats.write().await;
            stats.active_streams = streams.values()
                .filter(|s| !matches!(s.state, StreamState::Closed | StreamState::Reset))
                .count();
        }

        if cleaned_up > 0 {
            protocol_event!(
                Level::Debug,
                "Cleaned up connection resources";
                "cleaned_up" => cleaned_up
            );
        }

        cleaned_up
    }

    // Private helper methods
    
    async fn ensure_stream_exists(&self, stream_id: u64) -> Result<()> {
        let mut streams = self.streams.write().await;
        if !streams.contains_key(&stream_id) {
            let stream_info = StreamInfo::new(stream_id);
            streams.insert(stream_id, stream_info);

            let mut stats = self.stats.write().await;
            stats.streams_created += 1;
            stats.active_streams += 1;
        }
        Ok(())
    }

    async fn process_data_frame(&self, stream_id: u64, data_frame: crate::http3::frame::DataFrame) -> Result<Vec<Http3Frame>> {
        // Update stream state and statistics
        {
            let mut streams = self.streams.write().await;
            if let Some(stream) = streams.get_mut(&stream_id) {
                stream.bytes_transferred += data_frame.data.len() as u64;
            }
        }

        {
            let mut stats = self.stats.write().await;
            stats.bytes_transferred += data_frame.data.len() as u64;
        }

        protocol_event!(
            Level::Debug,
            "Processed DATA frame";
            "stream_id" => stream_id,
            "data_length" => data_frame.data.len()
        );

        Ok(Vec::new()) // No response frames
    }

    fn process_headers_frame(&self, stream_id: u64, headers_frame: crate::http3::frame::HeadersFrame) -> Result<Vec<Http3Frame>> {
        // This is a placeholder - in practice, would decode QPACK headers
        protocol_event!(
            Level::Debug,
            "Processed HEADERS frame";
            "stream_id" => stream_id,
            "field_section_length" => headers_frame.field_section.len()
        );

        Ok(Vec::new()) // No response frames
    }

    async fn process_settings_frame(&self, stream_id: u64, settings_frame: crate::http3::frame::SettingsFrame) -> Result<Vec<Http3Frame>> {
        // Update peer settings
        {
            let mut peer_settings = self.peer_settings.write().await;
            *peer_settings = settings_frame.settings;
        }

        protocol_event!(
            Level::Info,
            "Processed SETTINGS frame";
            "stream_id" => stream_id
        );

        Ok(Vec::new()) // No response frames
    }

    fn process_push_promise_frame(&self, stream_id: u64, push_promise_frame: PushPromiseFrame) -> Result<Vec<Http3Frame>> {
        if self.role != ConnectionRole::Client {
            return Err("Only clients can receive push promises"
                .to_http3_error(Http3ErrorCode::FrameUnexpected));
        }

        protocol_event!(
            Level::Info,
            "Received PUSH_PROMISE frame";
            "stream_id" => stream_id,
            "push_id" => push_promise_frame.push_id.0
        );

        // Client would validate and potentially send CANCEL_PUSH
        Ok(Vec::new())
    }

    async fn process_cancel_push_frame(&self, _stream_id: u64, cancel_push_frame: CancelPushFrame) -> Result<Vec<Http3Frame>> {
        if let Some(push_manager) = &self.push_manager {
            push_manager.handle_cancel_push(&cancel_push_frame).await?;

            let mut stats = self.stats.write().await;
            stats.push_promises_cancelled += 1;
        }

        Ok(Vec::new())
    }

    async fn process_max_push_id_frame(&self, _stream_id: u64, max_push_id_frame: MaxPushIdFrame) -> Result<Vec<Http3Frame>> {
        if let Some(push_manager) = &self.push_manager {
            push_manager.handle_max_push_id(&max_push_id_frame).await?;
        }

        Ok(Vec::new())
    }

    fn process_priority_update_frame(&self, stream_id: u64, _priority_frame: PriorityUpdateFrame) -> Result<Vec<Http3Frame>> {
        protocol_event!(
            Level::Debug,
            "Processed PRIORITY_UPDATE frame";
            "stream_id" => stream_id
        );

        Ok(Vec::new())
    }

    fn process_goaway_frame(&self, stream_id: u64, goaway_frame: crate::http3::frame::GoawayFrame) -> Result<Vec<Http3Frame>> {
        protocol_event!(
            Level::Warn,
            "Received GOAWAY frame";
            "stream_id" => stream_id,
            "last_stream_id" => goaway_frame.stream_id.0
        );

        Ok(Vec::new())
    }

    fn process_unknown_frame(&self, stream_id: u64, frame_type: VarInt, payload: Bytes) -> Result<Vec<Http3Frame>> {
        protocol_event!(
            Level::Debug,
            "Processed unknown frame";
            "stream_id" => stream_id,
            "frame_type" => frame_type.0,
            "payload_length" => payload.len()
        );

        Ok(Vec::new()) // Unknown frames are ignored
    }

    async fn process_max_streams_frame(&self, _stream_id: u64, max_streams_frame: crate::http3::frame::MaxStreamsFrame) -> Result<Vec<Http3Frame>> {
        protocol_event!(
            Level::Info,
            "Processed MAX_STREAMS frame";
            "stream_type" => if max_streams_frame.stream_type == 0 { "bidirectional" } else { "unidirectional" },
            "max_streams" => max_streams_frame.maximum_streams.0
        );

        // Update stream limits - this would typically be handled by the stream multiplexer
        // For now, just acknowledge receipt
        {
            let mut stats = self.stats.write().await;
            stats.frames_processed += 1;
        }

        Ok(vec![])
    }

    async fn process_streams_blocked_frame(&self, _stream_id: u64, streams_blocked_frame: crate::http3::frame::StreamsBlockedFrame) -> Result<Vec<Http3Frame>> {
        protocol_event!(
            Level::Info,
            "Processed STREAMS_BLOCKED frame";
            "stream_type" => if streams_blocked_frame.stream_type == 0 { "bidirectional" } else { "unidirectional" },
            "max_streams" => streams_blocked_frame.maximum_streams.0
        );

        // Handle streams blocked notification - typically would trigger MAX_STREAMS response
        {
            let mut stats = self.stats.write().await;
            stats.frames_processed += 1;
        }

        Ok(vec![])
    }

    async fn process_datagram_frame(&self, stream_id: u64, datagram_frame: crate::http3::frame::DatagramFrame) -> Result<Vec<Http3Frame>> {
        protocol_event!(
            Level::Debug,
            "Processed DATAGRAM frame";
            "stream_id" => stream_id,
            "data_length" => datagram_frame.data.len()
        );

        // Update statistics for datagrams
        {
            let mut stats = self.stats.write().await;
            stats.frames_processed += 1;
            stats.bytes_transferred += datagram_frame.data.len() as u64;
        }

        // Datagrams are fire-and-forget, no response frames
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http3::frame::{DataFrame, HeadersFrame};
    use crate::qpack::field::{HeaderName, HeaderValue, HeaderField};

    #[tokio::test]
    async fn test_connection_manager_creation() {
        let push_config = ServerPushConfig::default();
        let manager = ConnectionManager::new(ConnectionRole::Server, Some(push_config));
        
        assert_eq!(manager.role, ConnectionRole::Server);
        assert!(manager.push_manager.is_some());
        
        let stats = manager.get_stats().await;
        assert_eq!(stats.streams_created, 0);
        assert_eq!(stats.frames_processed, 0);
    }

    #[tokio::test]
    async fn test_push_promise_creation() {
        let push_config = ServerPushConfig::default();
        let manager = ConnectionManager::new(ConnectionRole::Server, Some(push_config));
        
        let headers = vec![
            HeaderField::new(HeaderName::from(":method"), HeaderValue::from("GET")),
            HeaderField::new(HeaderName::from(":scheme"), HeaderValue::from("https")),
            HeaderField::new(HeaderName::from(":authority"), HeaderValue::from("example.com")),
            HeaderField::new(HeaderName::from(":path"), HeaderValue::from("/style.css")),
        ];
        
        let result = manager.create_push_promise(1, headers).await.unwrap();
        assert!(result.is_some());
        
        let stats = manager.get_stats().await;
        assert_eq!(stats.push_promises_made, 1);
    }

    #[tokio::test]
    async fn test_frame_processing() {
        let manager = ConnectionManager::new(ConnectionRole::Client, None);
        
        let data_frame = DataFrame::new(Bytes::from("test data"));
        let frame = Http3Frame::Data(data_frame);
        
        let responses = manager.process_frame(1, frame).await.unwrap();
        assert!(responses.is_empty());
        
        let stats = manager.get_stats().await;
        assert_eq!(stats.frames_processed, 1);
        assert_eq!(stats.bytes_transferred, 9); // "test data" length
    }

    #[tokio::test]
    async fn test_stream_lifecycle() {
        let manager = ConnectionManager::new(ConnectionRole::Server, None);
        
        // Process frame to create stream
        let headers_frame = HeadersFrame::new(Bytes::from("headers"));
        let frame = Http3Frame::Headers(headers_frame);
        
        manager.process_frame(1, frame).await.unwrap();
        
        let stream_info = manager.get_stream_info(1).await.unwrap();
        assert_eq!(stream_info.stream_id, 1);
        assert_eq!(stream_info.state, StreamState::Idle);
        
        let active_streams = manager.list_active_streams().await;
        assert_eq!(active_streams.len(), 1);
    }

    #[tokio::test]
    async fn test_cleanup() {
        let push_config = ServerPushConfig::default();
        let manager = ConnectionManager::new(ConnectionRole::Server, Some(push_config));
        
        // Create some activity
        let headers = vec![
            HeaderField::new(HeaderName::from(":method"), HeaderValue::from("GET")),
            HeaderField::new(HeaderName::from(":scheme"), HeaderValue::from("https")),
            HeaderField::new(HeaderName::from(":authority"), HeaderValue::from("example.com")),
            HeaderField::new(HeaderName::from(":path"), HeaderValue::from("/test")),
        ];
        
        manager.create_push_promise(1, headers).await.unwrap();
        
        // Cleanup should run without errors
        let cleaned_up = manager.cleanup().await;
        assert_eq!(cleaned_up, 0); // Nothing old enough to clean up yet
    }
}