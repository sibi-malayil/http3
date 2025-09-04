//! HTTP/3 Server Push implementation per RFC 9114 Section 4.6
//!
//! Implements server push functionality including PUSH_PROMISE frames,
//! push stream management, and client validation.

use crate::{
    error::{Result, Http3ErrorCode},
    error_context::ErrorConversion,
    http3::{
        frame::{PushPromiseFrame, CancelPushFrame, MaxPushIdFrame},
        webtransport::HeaderField,
    },
    util::varint::VarInt,
    whathappened::Level,
    protocol_event,
};
use bytes::{Bytes, BytesMut};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

/// Push stream state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushStreamState {
    /// Push promised but not yet sent
    Promised,
    /// Headers sent, body being transmitted
    Active,
    /// Push completed successfully
    Completed,
    /// Push cancelled by client or server
    Cancelled,
    /// Push failed due to error
    Failed,
}

/// Reason for push cancellation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushCancellationReason {
    /// Cancelled by client (CANCEL_PUSH frame)
    ClientCancellation,
    /// Resource no longer needed
    ResourceUnavailable,
    /// Connection closing
    ConnectionClosing,
    /// Push ID limit exceeded
    PushIdLimitExceeded,
    /// Internal server error
    InternalError(String),
}

/// Information about a push promise
#[derive(Debug, Clone)]
pub struct PushPromise {
    /// Unique push ID
    pub push_id: u64,
    /// Stream ID where promise was made
    pub request_stream_id: u64,
    /// Push stream ID (if allocated)
    pub push_stream_id: Option<u64>,
    /// Promise headers (authority, method, path, etc.)
    pub headers: Vec<HeaderField>,
    /// Current state of the push
    pub state: PushStreamState,
    /// When the promise was created
    pub created_at: Instant,
    /// When headers were sent (if any)
    pub headers_sent_at: Option<Instant>,
    /// When push completed (if completed)
    pub completed_at: Option<Instant>,
    /// Cancellation reason (if cancelled)
    pub cancellation_reason: Option<PushCancellationReason>,
    /// Response headers (when push stream starts)
    pub response_headers: Option<Vec<HeaderField>>,
    /// Total bytes sent
    pub bytes_sent: u64,
}

impl PushPromise {
    /// Create a new push promise
    pub fn new(
        push_id: u64,
        request_stream_id: u64,
        headers: Vec<HeaderField>,
    ) -> Self {
        Self {
            push_id,
            request_stream_id,
            push_stream_id: None,
            headers,
            state: PushStreamState::Promised,
            created_at: Instant::now(),
            headers_sent_at: None,
            completed_at: None,
            cancellation_reason: None,
            response_headers: None,
            bytes_sent: 0,
        }
    }

    /// Get the promised authority
    pub fn authority(&self) -> Option<String> {
        self.headers.iter()
            .find(|h| String::from_utf8_lossy(&h.name) == ":authority")
            .map(|h| String::from_utf8_lossy(&h.value).to_string())
    }

    /// Get the promised method
    pub fn method(&self) -> Option<String> {
        self.headers.iter()
            .find(|h| String::from_utf8_lossy(&h.name) == ":method")
            .map(|h| String::from_utf8_lossy(&h.value).to_string())
    }

    /// Get the promised path
    pub fn path(&self) -> Option<String> {
        self.headers.iter()
            .find(|h| String::from_utf8_lossy(&h.name) == ":path")
            .map(|h| String::from_utf8_lossy(&h.value).to_string())
    }

    /// Get the promised scheme
    pub fn scheme(&self) -> Option<String> {
        self.headers.iter()
            .find(|h| String::from_utf8_lossy(&h.name) == ":scheme")
            .map(|h| String::from_utf8_lossy(&h.value).to_string())
    }

    /// Check if this push is still active
    pub fn is_active(&self) -> bool {
        matches!(self.state, PushStreamState::Promised | PushStreamState::Active)
    }

    /// Check if this push is completed (success or failure)
    pub fn is_completed(&self) -> bool {
        matches!(
            self.state,
            PushStreamState::Completed | PushStreamState::Cancelled | PushStreamState::Failed
        )
    }

    /// Get the duration since promise was created
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
}

/// Server push manager configuration
#[derive(Debug, Clone)]
pub struct ServerPushConfig {
    /// Maximum number of concurrent push promises
    pub max_concurrent_pushes: usize,
    /// Maximum push ID value
    pub max_push_id: u64,
    /// Enable server push (can be disabled by settings)
    pub enable_push: bool,
    /// Timeout for push promises (after which they're cancelled)
    pub push_timeout: Duration,
    /// Maximum time to keep completed push state
    pub completed_push_retention: Duration,
}

impl Default for ServerPushConfig {
    fn default() -> Self {
        Self {
            max_concurrent_pushes: 100,
            max_push_id: 1000,
            enable_push: true,
            push_timeout: Duration::from_secs(30),
            completed_push_retention: Duration::from_secs(300), // 5 minutes
        }
    }
}

/// HTTP/3 Server Push Manager
pub struct ServerPushManager {
    /// Configuration
    config: ServerPushConfig,
    /// Active push promises by push ID
    pushes: Arc<RwLock<HashMap<u64, PushPromise>>>,
    /// Next available push ID
    next_push_id: Arc<RwLock<u64>>,
    /// Client's maximum push ID (from MAX_PUSH_ID frame)
    client_max_push_id: Arc<RwLock<Option<u64>>>,
    /// Push promises by request stream ID
    pushes_by_stream: Arc<RwLock<HashMap<u64, Vec<u64>>>>,
    /// Cancelled push IDs (to track client cancellations)
    cancelled_pushes: Arc<RwLock<HashMap<u64, PushCancellationReason>>>,
    /// Push statistics
    stats: Arc<RwLock<ServerPushStats>>,
}

/// Server push statistics
#[derive(Debug, Clone, Default)]
pub struct ServerPushStats {
    /// Total promises made
    pub promises_made: u64,
    /// Total promises completed successfully
    pub promises_completed: u64,
    /// Total promises cancelled
    pub promises_cancelled: u64,
    /// Total promises failed
    pub promises_failed: u64,
    /// Total bytes pushed
    pub bytes_pushed: u64,
    /// Current active pushes
    pub active_pushes: usize,
}

impl ServerPushManager {
    /// Create a new server push manager
    pub fn new(config: ServerPushConfig) -> Self {
        Self {
            config,
            pushes: Arc::new(RwLock::new(HashMap::new())),
            next_push_id: Arc::new(RwLock::new(0)),
            client_max_push_id: Arc::new(RwLock::new(None)),
            pushes_by_stream: Arc::new(RwLock::new(HashMap::new())),
            cancelled_pushes: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(ServerPushStats::default())),
        }
    }

    /// Create a push promise for a resource
    pub async fn create_push_promise(
        &self,
        request_stream_id: u64,
        headers: Vec<HeaderField>,
    ) -> Result<Option<PushPromiseFrame>> {
        if !self.config.enable_push {
            return Ok(None);
        }

        // Validate headers
        self.validate_push_headers(&headers)?;

        // Check if we can create more pushes
        let current_pushes = self.pushes.read().await.len();
        if current_pushes >= self.config.max_concurrent_pushes {
            protocol_event!(
                Level::Warn,
                "Cannot create push promise - too many concurrent pushes";
                "current_pushes" => current_pushes,
                "max_concurrent" => self.config.max_concurrent_pushes
            );
            return Ok(None);
        }

        // Get next push ID
        let push_id = {
            let mut next_id = self.next_push_id.write().await;
            let id = *next_id;
            *next_id += 4; // Server-initiated streams are multiples of 4
            id
        };

        // Check against client's max push ID
        let client_max = *self.client_max_push_id.read().await;
        if let Some(max_id) = client_max {
            if push_id > max_id {
                protocol_event!(
                    Level::Warn,
                    "Push ID exceeds client maximum";
                    "push_id" => push_id,
                    "client_max" => max_id
                );
                return Err("Push ID exceeds client maximum"
                    .to_http3_error(Http3ErrorCode::IdError));
            }
        }

        // Check against our config limit
        if push_id > self.config.max_push_id {
            return Err("Push ID exceeds server maximum"
                .to_http3_error(Http3ErrorCode::IdError));
        }

        // Create the promise
        let promise = PushPromise::new(push_id, request_stream_id, headers);

        // Encode headers for PUSH_PROMISE frame
        let encoded_headers = self.encode_headers(&promise.headers)?;

        // Get values for logging before moving the promise
        let authority = promise.authority().unwrap_or_else(|| "unknown".to_string());
        let path = promise.path().unwrap_or_else(|| "unknown".to_string());

        // Store the promise
        {
            let mut pushes = self.pushes.write().await;
            pushes.insert(push_id, promise);
        }

        // Track by stream ID
        {
            let mut by_stream = self.pushes_by_stream.write().await;
            by_stream.entry(request_stream_id).or_default().push(push_id);
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.promises_made += 1;
            stats.active_pushes += 1;
        }

        let frame = PushPromiseFrame::new(
            VarInt::try_from(push_id)?,
            encoded_headers,
        );

        protocol_event!(
            Level::Info,
            "Created push promise";
            "push_id" => push_id,
            "request_stream_id" => request_stream_id,
            "authority" => authority,
            "path" => path
        );

        Ok(Some(frame))
    }

    /// Handle a CANCEL_PUSH frame from the client
    pub async fn handle_cancel_push(&self, cancel_frame: &CancelPushFrame) -> Result<()> {
        let push_id = cancel_frame.push_id.0;

        protocol_event!(
            Level::Info,
            "Received CANCEL_PUSH frame";
            "push_id" => push_id
        );

        // Mark as cancelled
        {
            let mut cancelled = self.cancelled_pushes.write().await;
            cancelled.insert(push_id, PushCancellationReason::ClientCancellation);
        }

        // Update promise state if it exists
        {
            let mut pushes = self.pushes.write().await;
            if let Some(promise) = pushes.get_mut(&push_id) {
                if promise.is_active() {
                    promise.state = PushStreamState::Cancelled;
                    promise.cancellation_reason = Some(PushCancellationReason::ClientCancellation);
                    promise.completed_at = Some(Instant::now());

                    // Update stats
                    let mut stats = self.stats.write().await;
                    stats.promises_cancelled += 1;
                    if promise.state == PushStreamState::Promised || promise.state == PushStreamState::Active {
                        stats.active_pushes = stats.active_pushes.saturating_sub(1);
                    }
                }
            }
        }

        Ok(())
    }

    /// Handle a MAX_PUSH_ID frame from the client
    pub async fn handle_max_push_id(&self, max_push_frame: &MaxPushIdFrame) -> Result<()> {
        let max_push_id = max_push_frame.push_id.0;

        protocol_event!(
            Level::Info,
            "Received MAX_PUSH_ID frame";
            "max_push_id" => max_push_id
        );

        // Update client's max push ID
        {
            let mut client_max = self.client_max_push_id.write().await;
            *client_max = Some(max_push_id);
        }

        // Cancel any pushes that exceed the new limit
        {
            let mut pushes = self.pushes.write().await;
            let mut cancelled_count = 0;

            for (push_id, promise) in pushes.iter_mut() {
                if *push_id > max_push_id && promise.is_active() {
                    promise.state = PushStreamState::Cancelled;
                    promise.cancellation_reason = Some(PushCancellationReason::PushIdLimitExceeded);
                    promise.completed_at = Some(Instant::now());
                    cancelled_count += 1;
                }
            }

            if cancelled_count > 0 {
                protocol_event!(
                    Level::Warn,
                    "Cancelled pushes due to MAX_PUSH_ID limit";
                    "cancelled_count" => cancelled_count,
                    "max_push_id" => max_push_id
                );

                // Update stats
                let mut stats = self.stats.write().await;
                stats.promises_cancelled += cancelled_count;
                stats.active_pushes = stats.active_pushes.saturating_sub(cancelled_count as usize);
            }
        }

        Ok(())
    }

    /// Start a push stream for a promised resource
    pub async fn start_push_stream(
        &self,
        push_id: u64,
        push_stream_id: u64,
        response_headers: Vec<HeaderField>,
    ) -> Result<()> {
        // Check if push was cancelled
        {
            let cancelled = self.cancelled_pushes.read().await;
            if cancelled.contains_key(&push_id) {
                return Err("Push was cancelled by client"
                    .to_http3_error(Http3ErrorCode::RequestCancelled));
            }
        }

        // Update promise state
        {
            let mut pushes = self.pushes.write().await;
            if let Some(promise) = pushes.get_mut(&push_id) {
                if promise.state != PushStreamState::Promised {
                    return Err("Push stream already started or completed"
                        .to_http3_error(Http3ErrorCode::IdError));
                }

                promise.state = PushStreamState::Active;
                promise.push_stream_id = Some(push_stream_id);
                promise.response_headers = Some(response_headers);
                promise.headers_sent_at = Some(Instant::now());

                protocol_event!(
                    Level::Info,
                    "Started push stream";
                    "push_id" => push_id,
                    "push_stream_id" => push_stream_id,
                    "authority" => promise.authority().unwrap_or_else(|| "unknown".to_string()),
                    "path" => promise.path().unwrap_or_else(|| "unknown".to_string())
                );
            } else {
                return Err("Push promise not found"
                    .to_http3_error(Http3ErrorCode::IdError));
            }
        }

        Ok(())
    }

    /// Complete a push stream
    pub async fn complete_push_stream(&self, push_id: u64, bytes_sent: u64) -> Result<()> {
        {
            let mut pushes = self.pushes.write().await;
            if let Some(promise) = pushes.get_mut(&push_id) {
                if promise.state != PushStreamState::Active {
                    return Err("Push stream not active"
                        .to_http3_error(Http3ErrorCode::IdError));
                }

                promise.state = PushStreamState::Completed;
                promise.completed_at = Some(Instant::now());
                promise.bytes_sent = bytes_sent;

                protocol_event!(
                    Level::Info,
                    "Completed push stream";
                    "push_id" => push_id,
                    "bytes_sent" => bytes_sent,
                    "duration_ms" => promise.age().as_millis()
                );

                // Update stats
                let mut stats = self.stats.write().await;
                stats.promises_completed += 1;
                stats.bytes_pushed += bytes_sent;
                stats.active_pushes = stats.active_pushes.saturating_sub(1);
            } else {
                return Err("Push promise not found"
                    .to_http3_error(Http3ErrorCode::IdError));
            }
        }

        Ok(())
    }

    /// Get push promise information
    pub async fn get_push_promise(&self, push_id: u64) -> Option<PushPromise> {
        self.pushes.read().await.get(&push_id).cloned()
    }

    /// Get all push promises for a request stream
    pub async fn get_pushes_for_stream(&self, stream_id: u64) -> Vec<PushPromise> {
        let by_stream = self.pushes_by_stream.read().await;
        let pushes = self.pushes.read().await;

        if let Some(push_ids) = by_stream.get(&stream_id) {
            push_ids.iter()
                .filter_map(|&push_id| pushes.get(&push_id).cloned())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> ServerPushStats {
        self.stats.read().await.clone()
    }

    /// Cleanup completed and old push promises
    pub async fn cleanup_old_pushes(&self) -> usize {
        let now = Instant::now();
        let retention_duration = self.config.completed_push_retention;
        let timeout_duration = self.config.push_timeout;

        let mut removed_count = 0;

        // Clean up completed pushes
        {
            let mut pushes = self.pushes.write().await;
            let mut to_remove = Vec::new();

            for (push_id, promise) in pushes.iter_mut() {
                let should_remove = match promise.state {
                    PushStreamState::Completed | PushStreamState::Cancelled | PushStreamState::Failed => {
                        if let Some(completed_at) = promise.completed_at {
                            now.duration_since(completed_at) > retention_duration
                        } else {
                            promise.age() > retention_duration
                        }
                    }
                    PushStreamState::Promised | PushStreamState::Active => {
                        // Timeout old promises
                        if promise.age() > timeout_duration {
                            promise.state = PushStreamState::Failed;
                            promise.cancellation_reason = Some(PushCancellationReason::InternalError("Timeout".to_string()));
                            promise.completed_at = Some(now);
                            false // Will be cleaned up next time
                        } else {
                            false
                        }
                    }
                };

                if should_remove {
                    to_remove.push(*push_id);
                }
            }

            for push_id in &to_remove {
                pushes.remove(push_id);
                removed_count += 1;
            }
        }

        // Clean up by-stream mapping
        if removed_count > 0 {
            let mut by_stream = self.pushes_by_stream.write().await;
            let pushes = self.pushes.read().await;
            by_stream.retain(|_, push_ids| {
                push_ids.retain(|push_id| pushes.contains_key(push_id));
                !push_ids.is_empty()
            });
        }

        if removed_count > 0 {
            protocol_event!(
                Level::Debug,
                "Cleaned up old push promises";
                "removed_count" => removed_count
            );
        }

        removed_count
    }

    /// Check if a push ID was cancelled by the client
    pub async fn is_push_cancelled(&self, push_id: u64) -> bool {
        self.cancelled_pushes.read().await.contains_key(&push_id)
    }

    /// Validate push promise headers per RFC 9114
    fn validate_push_headers(&self, headers: &[HeaderField]) -> Result<()> {
        let mut has_method = false;
        let mut has_scheme = false;
        let mut has_authority = false;
        let mut has_path = false;

        for header in headers {
            let name = String::from_utf8_lossy(&header.name);
            match name.as_ref() {
                ":method" => {
                    if has_method {
                        return Err("Duplicate :method header"
                            .to_http3_error(Http3ErrorCode::MessageError));
                    }
                    has_method = true;
                    
                    // Only safe methods allowed for push
                    let method = String::from_utf8_lossy(&header.value);
                    if !matches!(method.as_ref(), "GET" | "HEAD") {
                        return Err("Unsafe method in push promise"
                            .to_http3_error(Http3ErrorCode::MessageError));
                    }
                }
                ":scheme" => {
                    if has_scheme {
                        return Err("Duplicate :scheme header"
                            .to_http3_error(Http3ErrorCode::MessageError));
                    }
                    has_scheme = true;
                }
                ":authority" => {
                    if has_authority {
                        return Err("Duplicate :authority header"
                            .to_http3_error(Http3ErrorCode::MessageError));
                    }
                    has_authority = true;
                }
                ":path" => {
                    if has_path {
                        return Err("Duplicate :path header"
                            .to_http3_error(Http3ErrorCode::MessageError));
                    }
                    has_path = true;
                }
                _ if name.starts_with(':') => {
                    return Err("Unknown pseudo-header in push promise"
                        .to_http3_error(Http3ErrorCode::MessageError));
                }
                _ => {} // Regular headers are fine
            }
        }

        // All pseudo-headers are required
        if !has_method || !has_scheme || !has_authority || !has_path {
            return Err("Missing required pseudo-headers"
                .to_http3_error(Http3ErrorCode::MessageError));
        }

        Ok(())
    }

    /// Encode headers for PUSH_PROMISE frame (placeholder - would use QPACK)
    fn encode_headers(&self, headers: &[HeaderField]) -> Result<Bytes> {
        // This is a simplified implementation
        // In practice, this would use the QPACK encoder
        let mut buf = BytesMut::new();
        
        for header in headers {
            // Simple encoding: length + name + length + value
            let name_bytes = &header.name;
            let value_bytes = &header.value;
            
            buf.extend_from_slice(&[name_bytes.len() as u8]);
            buf.extend_from_slice(name_bytes);
            buf.extend_from_slice(&[value_bytes.len() as u8]);
            buf.extend_from_slice(value_bytes);
        }
        
        Ok(buf.freeze())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_headers() -> Vec<HeaderField> {
        vec![
            HeaderField {
                name: b":method".to_vec(),
                value: b"GET".to_vec(),
            },
            HeaderField {
                name: b":scheme".to_vec(),
                value: b"https".to_vec(),
            },
            HeaderField {
                name: b":authority".to_vec(),
                value: b"example.com".to_vec(),
            },
            HeaderField {
                name: b":path".to_vec(),
                value: b"/style.css".to_vec(),
            },
        ]
    }

    #[tokio::test]
    async fn test_create_push_promise() {
        let config = ServerPushConfig::default();
        let manager = ServerPushManager::new(config);
        
        let headers = create_test_headers();
        let result = manager.create_push_promise(1, headers).await.unwrap();
        
        assert!(result.is_some());
        let frame = result.unwrap();
        assert_eq!(frame.push_id.0, 0);
        
        let stats = manager.get_stats().await;
        assert_eq!(stats.promises_made, 1);
        assert_eq!(stats.active_pushes, 1);
    }

    #[tokio::test]
    async fn test_cancel_push() {
        let config = ServerPushConfig::default();
        let manager = ServerPushManager::new(config);
        
        let headers = create_test_headers();
        let frame = manager.create_push_promise(1, headers).await.unwrap().unwrap();
        let push_id = frame.push_id.0;
        
        let cancel_frame = CancelPushFrame::new(VarInt::from_u64(push_id).unwrap());
        manager.handle_cancel_push(&cancel_frame).await.unwrap();
        
        assert!(manager.is_push_cancelled(push_id).await);
        
        let promise = manager.get_push_promise(push_id).await.unwrap();
        assert_eq!(promise.state, PushStreamState::Cancelled);
    }

    #[tokio::test]
    async fn test_max_push_id_enforcement() {
        let config = ServerPushConfig::default();
        let manager = ServerPushManager::new(config);
        
        // Set client max push ID to 4
        let max_push_frame = MaxPushIdFrame::new(VarInt::from_u32(4));
        manager.handle_max_push_id(&max_push_frame).await.unwrap();
        
        let headers = create_test_headers();
        
        // First push should succeed (ID 0)
        let result1 = manager.create_push_promise(1, headers.clone()).await.unwrap();
        assert!(result1.is_some());
        
        // Second push should succeed (ID 4)
        let result2 = manager.create_push_promise(1, headers.clone()).await.unwrap();
        assert!(result2.is_some());
        
        // Third push should fail (ID 8 > 4)
        let result3 = manager.create_push_promise(1, headers).await;
        assert!(result3.is_err()); // Should fail with push ID exceeds limit
    }

    #[tokio::test]
    async fn test_invalid_push_headers() {
        let config = ServerPushConfig::default();
        let manager = ServerPushManager::new(config);
        
        // Missing :path header
        let invalid_headers = vec![
            HeaderField { name: b":method".to_vec(), value: b"GET".to_vec() },
            HeaderField { name: b":scheme".to_vec(), value: b"https".to_vec() },
            HeaderField { name: b":authority".to_vec(), value: b"example.com".to_vec() },
        ];
        
        let result = manager.create_push_promise(1, invalid_headers).await;
        assert!(result.is_err());
        
        // Unsafe method
        let unsafe_headers = vec![
            HeaderField { name: b":method".to_vec(), value: b"POST".to_vec() },
            HeaderField { name: b":scheme".to_vec(), value: b"https".to_vec() },
            HeaderField { name: b":authority".to_vec(), value: b"example.com".to_vec() },
            HeaderField { name: b":path".to_vec(), value: b"/api".to_vec() },
        ];
        
        let result = manager.create_push_promise(1, unsafe_headers).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_push_stream_lifecycle() {
        let config = ServerPushConfig::default();
        let manager = ServerPushManager::new(config);
        
        let headers = create_test_headers();
        let frame = manager.create_push_promise(1, headers).await.unwrap().unwrap();
        let push_id = frame.push_id.0;
        
        // Start push stream
        let response_headers = vec![
            HeaderField { name: b":status".to_vec(), value: b"200".to_vec() },
            HeaderField { name: b"content-type".to_vec(), value: b"text/css".to_vec() },
        ];
        
        manager.start_push_stream(push_id, 4, response_headers).await.unwrap();
        
        let promise = manager.get_push_promise(push_id).await.unwrap();
        assert_eq!(promise.state, PushStreamState::Active);
        assert_eq!(promise.push_stream_id, Some(4));
        
        // Complete push stream
        manager.complete_push_stream(push_id, 1024).await.unwrap();
        
        let promise = manager.get_push_promise(push_id).await.unwrap();
        assert_eq!(promise.state, PushStreamState::Completed);
        assert_eq!(promise.bytes_sent, 1024);
        
        let stats = manager.get_stats().await;
        assert_eq!(stats.promises_completed, 1);
        assert_eq!(stats.bytes_pushed, 1024);
    }
}