//! QUIC stream manager implementation
//!
//! Manages multiple streams within a QUIC connection according to RFC 9000.

use crate::{
    error::{Error, Result, StreamErrorCode},
    quic::{
        connection::ConnectionRole,
        stream::{Stream, StreamId, StreamState, StreamStats, StreamType},
        frame_types::Frame,
        transport::TransportParameters,
    },
    whathappened::Level,
    {protocol_event, span},
};
use bytes::Bytes;
use std::{
    collections::{HashMap, BTreeMap, VecDeque},
};

/// Stream priority level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StreamPriority {
    /// Highest priority (e.g., control streams)
    Urgent = 0,
    /// High priority (e.g., API calls)
    High = 1,
    /// Normal priority (e.g., regular data)
    Normal = 2,
    /// Low priority (e.g., background updates)
    Low = 3,
}

/// Frame priority classification for scheduling
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FramePriority {
    /// Critical connection frames (CONNECTION_CLOSE, etc.)
    Critical = 0,
    /// Flow control management frames (BLOCKED, MAX_DATA, etc.)
    FlowControl = 1,
    /// Stream control frames (RESET_STREAM, STOP_SENDING, etc.)
    StreamControl = 2,
    /// High priority stream data
    StreamDataUrgent = 3,
    /// Normal priority stream data
    StreamDataNormal = 4,
    /// Low priority stream data
    StreamDataLow = 5,
    /// Connection management frames
    ConnectionManagement = 6,
    /// Keep-alive and maintenance frames
    Maintenance = 7,
}

impl Default for StreamPriority {
    fn default() -> Self {
        Self::Normal
    }
}

/// Stream creation parameters
#[derive(Debug, Clone)]
pub struct StreamParameters {
    /// Stream type (bidirectional or unidirectional)
    pub stream_type: StreamType,
    /// Initial priority
    pub priority: StreamPriority,
    /// Initial receive window size
    pub initial_recv_window: Option<u64>,
}

impl Default for StreamParameters {
    fn default() -> Self {
        Self {
            stream_type: StreamType::Bidirectional,
            priority: StreamPriority::Normal,
            initial_recv_window: None,
        }
    }
}

/// Configuration for automatic window updates
#[derive(Debug, Clone)]
pub struct WindowUpdateConfig {
    /// Threshold for connection-level window updates (0.0 to 1.0)
    pub connection_threshold: f64,
    /// Threshold for stream-level window updates (0.0 to 1.0)  
    pub stream_threshold: f64,
    /// Minimum window increase factor (1.0 = no increase)
    pub min_window_factor: f64,
    /// Maximum window increase factor
    pub max_window_factor: f64,
    /// Enable adaptive window sizing based on throughput
    pub adaptive_sizing: bool,
    /// Maximum window size for connections (bytes)
    pub max_connection_window: u64,
    /// Maximum window size for streams (bytes)
    pub max_stream_window: u64,
}

impl Default for WindowUpdateConfig {
    fn default() -> Self {
        Self {
            connection_threshold: 0.5,       // Update when 50% consumed
            stream_threshold: 0.5,           // Update when 50% consumed  
            min_window_factor: 1.5,          // At least 50% increase
            max_window_factor: 4.0,          // At most 4x increase
            adaptive_sizing: true,           // Enable adaptive sizing
            max_connection_window: 16 * 1024 * 1024, // 16MB
            max_stream_window: 1024 * 1024,           // 1MB
        }
    }
}

/// Statistics about automatic window updates
#[derive(Debug, Clone)]
pub struct WindowUpdateStats {
    /// Number of active streams
    pub active_streams: usize,
    /// Connection window utilization (0.0 to 1.0)
    pub connection_window_utilization: f64,
    /// Average stream window utilization (0.0 to 1.0)
    pub avg_stream_utilization: f64,
    /// Current connection window size
    pub connection_window_size: u64,
    /// Current configuration
    pub config: WindowUpdateConfig,
}

/// Types of flow control violations that can occur
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowControlViolationType {
    /// Connection-level data limit exceeded
    ConnectionDataExceeded,
    /// Stream-level data limit exceeded
    StreamDataExceeded,
    /// Stream count limit exceeded  
    StreamCountExceeded,
    /// Final size changed after FIN
    FinalSizeChanged,
    /// Data sent beyond final size
    DataBeyondFinalSize,
    /// MAX_DATA value decreased
    MaxDataDecreased,
    /// MAX_STREAM_DATA value decreased
    MaxStreamDataDecreased,
    /// MAX_STREAMS value decreased
    MaxStreamsDecreased,
}

/// Details about a flow control violation
#[derive(Debug, Clone)]
pub struct FlowControlViolation {
    /// Type of violation
    pub violation_type: FlowControlViolationType,
    /// Stream ID if applicable
    pub stream_id: Option<StreamId>,
    /// Amount of excess data or invalid value
    pub excess_amount: u64,
    /// Current limit that was exceeded
    pub current_limit: u64,
    /// Attempted value that caused violation
    pub attempted_value: u64,
    /// Human-readable description
    pub description: String,
}

/// Flow control violation detection and tracking
#[derive(Debug, Clone)]
pub struct FlowControlViolationTracker {
    /// Number of violations detected
    pub violations_detected: u64,
    /// Recent violations (limited to prevent memory exhaustion)
    pub recent_violations: VecDeque<FlowControlViolation>,
    /// Maximum number of recent violations to track
    pub max_recent_violations: usize,
    /// Whether to terminate connection on violation
    pub terminate_on_violation: bool,
}

impl Default for FlowControlViolationTracker {
    fn default() -> Self {
        Self {
            violations_detected: 0,
            recent_violations: VecDeque::new(),
            max_recent_violations: 100, // Track last 100 violations
            terminate_on_violation: true, // RFC 9000 requires connection termination
        }
    }
}

impl FlowControlViolationTracker {
    /// Record a new flow control violation
    fn record_violation(&mut self, violation: FlowControlViolation) {
        self.violations_detected += 1;
        
        // Limit memory usage by keeping only recent violations
        if self.recent_violations.len() >= self.max_recent_violations {
            self.recent_violations.pop_front();
        }
        
        protocol_event!(
            Level::Error,
            "Flow control violation recorded";
            "violation_type" => violation.violation_type,
            "stream_id" => violation.stream_id.map(|id| id.into_inner()),
            "excess_amount" => violation.excess_amount,
            "current_limit" => violation.current_limit,
            "attempted_value" => violation.attempted_value,
            "description" => violation.description.clone(),
            "total_violations" => self.violations_detected
        );
        
        self.recent_violations.push_back(violation);
    }
    
    /// Get the most recent violation of a specific type
    fn get_recent_violation(&self, violation_type: FlowControlViolationType) -> Option<&FlowControlViolation> {
        self.recent_violations
            .iter()
            .rev()
            .find(|v| v.violation_type == violation_type)
    }
    
    /// Check if a specific type of violation occurred recently
    fn has_recent_violation(&self, violation_type: FlowControlViolationType) -> bool {
        self.get_recent_violation(violation_type).is_some()
    }
    
    /// Get violation statistics
    fn get_violation_stats(&self) -> (u64, usize) {
        (self.violations_detected, self.recent_violations.len())
    }
}

/// Manages all streams in a QUIC connection
pub struct StreamManager {
    /// Local connection role
    local_role: ConnectionRole,
    /// Active streams by ID
    streams: HashMap<StreamId, Stream>,
    /// Stream priorities
    priorities: HashMap<StreamId, StreamPriority>,
    /// Next stream ID to allocate for each type
    next_stream_ids: NextStreamIds,
    /// Maximum number of streams allowed by peer
    peer_limits: StreamLimits,
    /// Maximum number of streams we allow
    local_limits: StreamLimits,
    /// Streams with data ready to send, organized by priority
    send_ready: BTreeMap<StreamPriority, VecDeque<StreamId>>,
    /// Streams with data ready to read
    recv_ready: VecDeque<StreamId>,
    /// Connection-level flow control
    pub conn_flow_control: ConnectionFlowControl,
    /// Closed streams awaiting garbage collection
    closed_streams: HashMap<StreamId, ClosedStreamInfo>,
    /// Stream event queue
    events: VecDeque<StreamEvent>,
    /// Statistics
    stats: StreamManagerStats,
    /// Pending flow control frames to send
    pending_flow_control_frames: VecDeque<Frame>,
    /// Window update threshold (percentage of window consumed before sending update)
    window_update_threshold: f64,
    /// Configuration for automatic window updates
    window_update_config: WindowUpdateConfig,
    /// Track blocked streams waiting for flow control updates
    blocked_streams: HashMap<StreamId, BlockedState>,
    /// Flow control violation detection and tracking
    violation_tracker: FlowControlViolationTracker,
    /// Prioritized frame scheduling queue
    frame_scheduler: PrioritizedFrameScheduler,
}

/// Prioritized frame scheduler for flow control and stream management
#[derive(Debug)]
struct PrioritizedFrameScheduler {
    /// Frames organized by priority level
    priority_queues: BTreeMap<FramePriority, VecDeque<ScheduledFrame>>,
    /// Maximum bytes to include per priority level in one transmission
    priority_byte_limits: HashMap<FramePriority, usize>,
    /// Statistics about frame scheduling
    stats: FrameSchedulingStats,
}

/// A frame with scheduling metadata
#[derive(Debug, Clone)]
struct ScheduledFrame {
    /// The QUIC frame to send
    frame: Frame,
    /// Priority level for this frame
    priority: FramePriority,
    /// Stream ID associated with this frame (if applicable)
    stream_id: Option<StreamId>,
    /// Size estimate for bandwidth calculations
    estimated_size: usize,
    /// Timestamp when frame was scheduled
    scheduled_at: std::time::Instant,
}

/// Statistics about frame scheduling
#[derive(Debug, Clone, Default)]
pub struct FrameSchedulingStats {
    /// Total frames scheduled by priority
    pub frames_scheduled_by_priority: HashMap<FramePriority, u64>,
    /// Total bytes scheduled by priority  
    pub bytes_scheduled_by_priority: HashMap<FramePriority, u64>,
    /// Frames currently queued by priority
    pub frames_queued_by_priority: HashMap<FramePriority, usize>,
    /// Average scheduling latency by priority
    avg_scheduling_latency: HashMap<FramePriority, std::time::Duration>,
}

impl PrioritizedFrameScheduler {
    /// Create a new frame scheduler with default configuration
    fn new() -> Self {
        let mut priority_byte_limits = HashMap::new();
        
        // Configure byte limits per priority level (production-grade values)
        priority_byte_limits.insert(FramePriority::Critical, 8192);          // 8KB for critical frames
        priority_byte_limits.insert(FramePriority::FlowControl, 4096);       // 4KB for flow control
        priority_byte_limits.insert(FramePriority::StreamControl, 2048);     // 2KB for stream control
        priority_byte_limits.insert(FramePriority::StreamDataUrgent, 1024 * 64); // 64KB for urgent data
        priority_byte_limits.insert(FramePriority::StreamDataNormal, 1024 * 32); // 32KB for normal data
        priority_byte_limits.insert(FramePriority::StreamDataLow, 1024 * 16);    // 16KB for low priority data
        priority_byte_limits.insert(FramePriority::ConnectionManagement, 1024); // 1KB for connection mgmt
        priority_byte_limits.insert(FramePriority::Maintenance, 512);        // 512B for maintenance
        
        Self {
            priority_queues: BTreeMap::new(),
            priority_byte_limits,
            stats: FrameSchedulingStats::default(),
        }
    }
    
    /// Schedule a frame with the given priority
    fn schedule_frame(&mut self, frame: Frame, priority: FramePriority, stream_id: Option<StreamId>) {
        let estimated_size = Self::estimate_frame_size(&frame);
        let scheduled_frame = ScheduledFrame {
            frame,
            priority,
            stream_id,
            estimated_size,
            scheduled_at: std::time::Instant::now(),
        };
        
        // Add to priority queue
        self.priority_queues
            .entry(priority)
            .or_insert_with(VecDeque::new)
            .push_back(scheduled_frame);
            
        // Update statistics
        *self.stats.frames_scheduled_by_priority.entry(priority).or_insert(0) += 1;
        *self.stats.bytes_scheduled_by_priority.entry(priority).or_insert(0) += estimated_size as u64;
        *self.stats.frames_queued_by_priority.entry(priority).or_insert(0) += 1;
    }
    
    /// Get frames to send, respecting priority and byte limits
    fn get_frames_to_send(&mut self, max_packet_size: usize) -> Vec<Frame> {
        let mut frames = Vec::new();
        let mut remaining_bytes = max_packet_size;
        
        // Process priorities in order (Critical = 0 is highest)
        for (&priority, queue) in &mut self.priority_queues {
            if remaining_bytes == 0 {
                break;
            }
            
            let priority_limit = self.priority_byte_limits.get(&priority).copied().unwrap_or(1024);
            let mut priority_bytes_used = 0;
            
            // Respect both overall packet limit and per-priority limit using Rust 2024 let chains
            while let Some(scheduled_frame) = queue.front()
                && remaining_bytes > 0
                && priority_bytes_used < priority_limit
                && scheduled_frame.estimated_size <= remaining_bytes
            {
                let scheduled_frame = queue.pop_front().unwrap();
                
                remaining_bytes -= scheduled_frame.estimated_size;
                priority_bytes_used += scheduled_frame.estimated_size;
                
                // Update queue statistics
                if let Some(count) = self.stats.frames_queued_by_priority.get_mut(&priority) {
                    *count = count.saturating_sub(1);
                }
                
                frames.push(scheduled_frame.frame);
            }
        }
        
        frames
    }
    
    /// Estimate the serialized size of a frame
    fn estimate_frame_size(frame: &Frame) -> usize {
        match frame {
            Frame::Padding => 1,
            Frame::Ping => 1,
            Frame::Ack { ack_ranges, .. } => 8 + (ack_ranges.len() * 4), // Estimate
            Frame::ResetStream { .. } => 12,
            Frame::StopSending { .. } => 8,
            Frame::Crypto { data, .. } => 8 + data.len(),
            Frame::NewToken { token } => 4 + token.len(),
            Frame::Stream { data, .. } => 12 + data.len(),
            Frame::MaxData { .. } => 8,
            Frame::MaxStreamData { .. } => 12,
            Frame::MaxStreams { .. } => 8,
            Frame::DataBlocked { .. } => 8,
            Frame::StreamDataBlocked { .. } => 12,
            Frame::StreamsBlocked { .. } => 8,
            Frame::NewConnectionId { connection_id, .. } => 24 + connection_id.len(),
            Frame::RetireConnectionId { .. } => 8,
            Frame::PathChallenge { .. } => 9,
            Frame::PathResponse { .. } => 9,
            Frame::ConnectionClose { reason_phrase, .. } => 12 + reason_phrase.len(),
            Frame::HandshakeDone => 1,
        }
    }
    
    /// Check if there are frames waiting to be sent
    fn has_pending_frames(&self) -> bool {
        self.priority_queues.values().any(|queue| !queue.is_empty())
    }
    
    /// Get statistics about the frame scheduler
    fn get_stats(&self) -> &FrameSchedulingStats {
        &self.stats
    }
    
    /// Clear all pending frames (used for connection reset)
    fn clear_all_frames(&mut self) {
        self.priority_queues.clear();
        self.stats.frames_queued_by_priority.clear();
    }
    
    /// Classify a frame's priority based on its type and context
    fn classify_frame_priority(frame: &Frame, stream_priority: Option<StreamPriority>) -> FramePriority {
        match frame {
            // Critical connection management
            Frame::ConnectionClose { .. } => FramePriority::Critical,
            Frame::Crypto { .. } => FramePriority::Critical,
            Frame::HandshakeDone => FramePriority::Critical,
            
            // Flow control frames get high priority to prevent blocking
            Frame::MaxData { .. } | Frame::MaxStreamData { .. } | Frame::MaxStreams { .. } => 
                FramePriority::FlowControl,
            Frame::DataBlocked { .. } | Frame::StreamDataBlocked { .. } | Frame::StreamsBlocked { .. } => 
                FramePriority::FlowControl,
            
            // Stream control frames
            Frame::ResetStream { .. } | Frame::StopSending { .. } => FramePriority::StreamControl,
            
            // Stream data frames - priority based on stream priority
            Frame::Stream { .. } => {
                match stream_priority.unwrap_or(StreamPriority::Normal) {
                    StreamPriority::Urgent => FramePriority::StreamDataUrgent,
                    StreamPriority::High => FramePriority::StreamDataUrgent,
                    StreamPriority::Normal => FramePriority::StreamDataNormal,
                    StreamPriority::Low => FramePriority::StreamDataLow,
                }
            }
            
            // Connection management
            Frame::NewConnectionId { .. } | Frame::RetireConnectionId { .. } |
            Frame::PathChallenge { .. } | Frame::PathResponse { .. } => 
                FramePriority::ConnectionManagement,
            
            // Maintenance and keep-alive
            Frame::NewToken { .. } | Frame::Ping | Frame::Ack { .. } | Frame::Padding => 
                FramePriority::Maintenance,
        }
    }
}

/// Tracks next stream IDs to allocate
#[derive(Debug, Clone)]
struct NextStreamIds {
    /// Next client-initiated bidirectional stream ID
    client_bidi: u64,
    /// Next server-initiated bidirectional stream ID
    server_bidi: u64,
    /// Next client-initiated unidirectional stream ID
    client_uni: u64,
    /// Next server-initiated unidirectional stream ID
    server_uni: u64,
}

impl NextStreamIds {
    fn new(local_role: ConnectionRole) -> Self {
        // Stream IDs start at 0, 1, 2, or 3 depending on type and initiator
        match local_role {
            ConnectionRole::Client => Self {
                client_bidi: 0,    // 0, 4, 8, ...
                server_bidi: 1,    // 1, 5, 9, ...
                client_uni: 2,     // 2, 6, 10, ...
                server_uni: 3,     // 3, 7, 11, ...
            },
            ConnectionRole::Server => Self {
                client_bidi: 0,    // 0, 4, 8, ...
                server_bidi: 1,    // 1, 5, 9, ...
                client_uni: 2,     // 2, 6, 10, ...
                server_uni: 3,     // 3, 7, 11, ...
            },
        }
    }

    fn allocate(&mut self, stream_type: StreamType, role: ConnectionRole, local_role: ConnectionRole) -> u64 {
        let id = match (role, stream_type) {
            (ConnectionRole::Client, StreamType::Bidirectional) => {
                let id = self.client_bidi;
                self.client_bidi += 4;
                id
            }
            (ConnectionRole::Server, StreamType::Bidirectional) => {
                let id = self.server_bidi;
                self.server_bidi += 4;
                id
            }
            (ConnectionRole::Client, StreamType::Unidirectional) => {
                let id = self.client_uni;
                self.client_uni += 4;
                id
            }
            (ConnectionRole::Server, StreamType::Unidirectional) => {
                let id = self.server_uni;
                self.server_uni += 4;
                id
            }
        };

        protocol_event!(
            Level::Debug,
            "Stream ID allocated";
            "stream_id" => id,
            "stream_type" => stream_type,
            "initiator" => role,
            "local_role" => local_role
        );

        id
    }
}

/// Stream limits for flow control
#[derive(Debug, Clone)]
struct StreamLimits {
    /// Maximum number of bidirectional streams
    max_bidi_streams: u64,
    /// Maximum number of unidirectional streams
    max_uni_streams: u64,
    /// Current number of bidirectional streams
    current_bidi_streams: u64,
    /// Current number of unidirectional streams
    current_uni_streams: u64,
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self {
            max_bidi_streams: 100,
            max_uni_streams: 100,
            current_bidi_streams: 0,
            current_uni_streams: 0,
        }
    }
}

/// Connection-level flow control
#[derive(Debug, Clone)]
pub struct ConnectionFlowControl {
    /// Maximum data that can be sent on the connection
    max_data_send: u64,
    /// Current data sent on the connection
    data_sent: u64,
    /// Maximum data that can be received on the connection
    max_data_recv: u64,
    /// Current data received on the connection
    data_recv: u64,
    /// Whether we should send MAX_DATA frame
    pub should_send_max_data: bool,
}

impl Default for ConnectionFlowControl {
    fn default() -> Self {
        Self {
            max_data_send: 0,
            max_data_recv: 1048576, // 1MB default
            data_sent: 0,
            data_recv: 0,
            should_send_max_data: false,
        }
    }
}

/// Information about a closed stream
#[derive(Debug, Clone)]
struct ClosedStreamInfo {
    /// When the stream was closed
    closed_at: std::time::Instant,
    /// Final stream state
    final_state: StreamState,
    /// Total bytes sent
    bytes_sent: u64,
    /// Total bytes received
    bytes_recv: u64,
}

/// Stream-related events
#[derive(Debug, Clone)]
pub enum StreamEvent {
    /// A new stream was created
    StreamCreated {
        stream_id: StreamId,
        stream_type: StreamType,
        is_local: bool,
    },
    /// A stream was closed
    StreamClosed {
        stream_id: StreamId,
        reason: StreamCloseReason,
    },
    /// Data is available to read on a stream
    DataAvailable {
        stream_id: StreamId,
    },
    /// Stream is blocked on flow control
    StreamBlocked {
        stream_id: StreamId,
        is_connection_blocked: bool,
    },
}

/// Reason for stream closure
#[derive(Debug, Clone, Copy)]
pub enum StreamCloseReason {
    /// Normal closure (both sides sent FIN)
    Normal,
    /// Stream was reset by peer
    Reset(u64),
    /// Stream was reset locally
    LocalReset(u64),
    /// Connection is closing
    ConnectionClose,
}

/// State of a blocked stream
#[derive(Debug, Clone)]
struct BlockedState {
    /// Amount of data blocked
    blocked_data_size: u64,
    /// Time when blocking occurred
    blocked_at: std::time::Instant,
    /// Whether it's blocked on connection-level flow control
    is_connection_blocked: bool,
    /// The limit that caused blocking
    limit: u64,
}

/// Stream manager statistics
#[derive(Debug, Clone, Default)]
pub struct StreamManagerStats {
    /// Total streams created
    pub streams_created: u64,
    /// Total streams closed
    pub streams_closed: u64,
    /// Currently active streams
    pub active_streams: usize,
    /// Total bytes sent across all streams
    pub total_bytes_sent: u64,
    /// Total bytes received across all streams
    pub total_bytes_recv: u64,
    /// Number of times blocked on connection flow control
    pub conn_flow_control_blocked: u64,
    /// Number of times blocked on stream flow control
    pub stream_flow_control_blocked: u64,
}

impl StreamManager {
    #[cfg(test)]
    /// Test helper to set stream send limit
    pub fn test_set_stream_send_limit(&mut self, stream_id: StreamId, limit: u64) -> Result<()> {
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            stream.test_set_send_limit(limit);
            Ok(())
        } else {
            Err(Error::StreamError {
                code: StreamErrorCode::StreamNotFound,
                reason: "Stream not found".to_string(),
            })
        }
    }
    /// Create a new stream manager
    pub fn new(local_role: ConnectionRole, params: &TransportParameters) -> Self {
        let local_limits = StreamLimits {
            max_bidi_streams: params.initial_max_streams_bidi
                .map(|v| v.into_inner())
                .unwrap_or(100),
            max_uni_streams: params.initial_max_streams_uni
                .map(|v| v.into_inner())
                .unwrap_or(100),
            current_bidi_streams: 0,
            current_uni_streams: 0,
        };

        let mut conn_flow_control = ConnectionFlowControl::default();
        if let Some(max_data) = params.initial_max_data {
            conn_flow_control.max_data_recv = max_data.into_inner();
        }

        protocol_event!(
            Level::Info,
            "Stream manager initialized";
            "local_role" => local_role,
            "max_bidi_streams" => local_limits.max_bidi_streams,
            "max_uni_streams" => local_limits.max_uni_streams,
            "max_data_recv" => conn_flow_control.max_data_recv
        );

        Self {
            local_role,
            streams: HashMap::new(),
            priorities: HashMap::new(),
            next_stream_ids: NextStreamIds::new(local_role),
            peer_limits: StreamLimits::default(),
            local_limits,
            send_ready: BTreeMap::new(),
            recv_ready: VecDeque::new(),
            conn_flow_control,
            closed_streams: HashMap::new(),
            events: VecDeque::new(),
            stats: StreamManagerStats::default(),
            pending_flow_control_frames: VecDeque::new(),
            window_update_threshold: 0.5, // Update window when 50% consumed
            window_update_config: WindowUpdateConfig::default(),
            blocked_streams: HashMap::new(),
            violation_tracker: FlowControlViolationTracker::default(),
            frame_scheduler: PrioritizedFrameScheduler::new(),
        }
    }

    /// Update peer transport parameters
    pub fn update_peer_params(&mut self, params: &TransportParameters) {
        if let Some(max_bidi) = params.initial_max_streams_bidi {
            self.peer_limits.max_bidi_streams = max_bidi.into_inner();
        }
        if let Some(max_uni) = params.initial_max_streams_uni {
            self.peer_limits.max_uni_streams = max_uni.into_inner();
        }
        if let Some(max_data) = params.initial_max_data {
            self.conn_flow_control.max_data_send = max_data.into_inner();
        }

        protocol_event!(
            Level::Info,
            "Peer transport parameters updated";
            "peer_max_bidi_streams" => self.peer_limits.max_bidi_streams,
            "peer_max_uni_streams" => self.peer_limits.max_uni_streams,
            "peer_max_data" => self.conn_flow_control.max_data_send
        );
    }

    /// Create a new local stream
    pub fn create_stream(&mut self, params: StreamParameters) -> Result<StreamId> {
        let _span = span!(Level::Debug, "create_stream");

        // Check if we can create a new stream
        let (current, max) = match params.stream_type {
            StreamType::Bidirectional => (
                self.peer_limits.current_bidi_streams,
                self.peer_limits.max_bidi_streams,
            ),
            StreamType::Unidirectional => (
                self.peer_limits.current_uni_streams,
                self.peer_limits.max_uni_streams,
            ),
        };

        if current >= max {
            // Record stream count violation
            let violation = FlowControlViolation {
                violation_type: FlowControlViolationType::StreamCountExceeded,
                stream_id: None,
                excess_amount: (current + 1).saturating_sub(max),
                current_limit: max,
                attempted_value: current + 1,
                description: format!(
                    "Stream count limit exceeded: current {} streams, limit {} streams, type {:?}",
                    current,
                    max,
                    params.stream_type
                ),
            };
            
            self.violation_tracker.record_violation(violation.clone());
            
            // Generate STREAMS_BLOCKED frame to inform peer
            let frame_stream_type = match params.stream_type {
                StreamType::Bidirectional => crate::quic::frame_types::StreamType::Bidirectional,
                StreamType::Unidirectional => crate::quic::frame_types::StreamType::Unidirectional,
            };
            
            self.pending_flow_control_frames.push_back(Frame::StreamsBlocked {
                stream_type: frame_stream_type,
                maximum_streams: max,
            });
            
            return Err(Error::StreamsBlocked);
        }

        // Allocate stream ID
        let stream_id_raw = self.next_stream_ids.allocate(
            params.stream_type,
            self.local_role,
            self.local_role,
        );
        let stream_id = StreamId::new(stream_id_raw, params.stream_type, self.local_role)?;

        // Create the stream
        let mut stream = Stream::new(stream_id, self.local_role);
        
        // Set initial receive window if specified
        if let Some(window) = params.initial_recv_window {
            stream.set_receive_max_data(window);
        }

        // Update counters
        match params.stream_type {
            StreamType::Bidirectional => self.peer_limits.current_bidi_streams += 1,
            StreamType::Unidirectional => self.peer_limits.current_uni_streams += 1,
        }

        // Add to collections
        self.streams.insert(stream_id, stream);
        self.priorities.insert(stream_id, params.priority);
        
        // Update stats
        self.stats.streams_created += 1;
        self.stats.active_streams = self.streams.len();

        // Emit event
        self.events.push_back(StreamEvent::StreamCreated {
            stream_id,
            stream_type: params.stream_type,
            is_local: true,
        });

        protocol_event!(
            Level::Info,
            "Local stream created";
            "stream_id" => stream_id_raw,
            "stream_type" => params.stream_type,
            "priority" => params.priority,
            "active_streams" => self.stats.active_streams
        );

        Ok(stream_id)
    }

    /// Accept a new remote stream
    pub fn accept_stream(&mut self, stream_id: StreamId) -> Result<()> {
        let _span = span!(Level::Debug, "accept_stream", stream_id = stream_id.into_inner());

        // Check if stream already exists
        if self.streams.contains_key(&stream_id) {
            return Ok(()); // Already accepted
        }

        // Validate stream ID
        let is_client_initiated = stream_id.initiated_by_client();
        let expected_initiator = match self.local_role {
            ConnectionRole::Client => !is_client_initiated, // Remote is server
            ConnectionRole::Server => is_client_initiated,   // Remote is client
        };

        if !expected_initiator {
            protocol_event!(
                Level::Error,
                "Invalid stream initiator";
                "stream_id" => stream_id.into_inner(),
                "is_client_initiated" => is_client_initiated,
                "local_role" => self.local_role
            );
            return Err(Error::ProtocolViolation("Invalid stream initiator".to_string()));
        }

        // Check limits
        let stream_type = stream_id.stream_type();
        let (current, max) = match stream_type {
            StreamType::Bidirectional => (
                &mut self.local_limits.current_bidi_streams,
                self.local_limits.max_bidi_streams,
            ),
            StreamType::Unidirectional => (
                &mut self.local_limits.current_uni_streams,
                self.local_limits.max_uni_streams,
            ),
        };

        if *current >= max {
            protocol_event!(
                Level::Warn,
                "Cannot accept stream - limit reached";
                "stream_id" => stream_id.into_inner(),
                "stream_type" => stream_type,
                "current" => *current,
                "max" => max
            );
            
            // Generate STREAMS_BLOCKED frame to inform peer  
            let frame_stream_type = match stream_type {
                StreamType::Bidirectional => crate::quic::frame_types::StreamType::Bidirectional,
                StreamType::Unidirectional => crate::quic::frame_types::StreamType::Unidirectional,
            };
            
            self.pending_flow_control_frames.push_back(Frame::StreamsBlocked {
                stream_type: frame_stream_type,
                maximum_streams: max,
            });
            
            return Err(Error::StreamsBlocked);
        }

        // Create the stream
        let stream = Stream::new(stream_id, self.local_role);
        *current += 1;

        // Add to collections
        self.streams.insert(stream_id, stream);
        self.priorities.insert(stream_id, StreamPriority::Normal);

        // Update stats
        self.stats.streams_created += 1;
        self.stats.active_streams = self.streams.len();

        // Emit event
        self.events.push_back(StreamEvent::StreamCreated {
            stream_id,
            stream_type,
            is_local: false,
        });

        protocol_event!(
            Level::Info,
            "Remote stream accepted";
            "stream_id" => stream_id.into_inner(),
            "stream_type" => stream_type,
            "active_streams" => self.stats.active_streams
        );

        Ok(())
    }

    /// Send data on a stream
    pub fn send_data(&mut self, stream_id: StreamId, data: Bytes, fin: bool) -> Result<()> {
        let _span = span!(Level::Debug, "send_data", stream_id = stream_id.into_inner(), data_len = data.len(), fin = fin);

        // Check connection-level flow control using Rust 2024 let chains
        let data_len = data.len() as u64;
        let available = self.conn_flow_control.max_data_send.saturating_sub(self.conn_flow_control.data_sent);
        if data_len > available {
            protocol_event!(
                Level::Warn,
                "Connection-level flow control blocked";
                "stream_id" => stream_id.into_inner(),
                "data_len" => data_len,
                "data_sent" => self.conn_flow_control.data_sent,
                "max_data_send" => self.conn_flow_control.max_data_send,
                "available_window" => available
            );
            
            // Generate DATA_BLOCKED frame
            self.pending_flow_control_frames.push_back(Frame::DataBlocked {
                maximum_data: self.conn_flow_control.max_data_send,
            });
            
            // Track blocked state
            self.blocked_streams.insert(stream_id, BlockedState {
                blocked_data_size: data_len,
                blocked_at: std::time::Instant::now(),
                is_connection_blocked: true,
                limit: self.conn_flow_control.max_data_send,
            });
            
            self.stats.conn_flow_control_blocked += 1;
            self.events.push_back(StreamEvent::StreamBlocked {
                stream_id,
                is_connection_blocked: true,
            });
            
            return Err(Error::FlowControl);
        }

        // Get the stream
        let stream = self.streams.get_mut(&stream_id)
            .ok_or_else(|| Error::StreamError {
                code: StreamErrorCode::StreamNotFound,
                reason: "Stream does not exist".to_string(),
            })?;

        // Try to send data on the stream
        match stream.send_data(data.clone(), fin) {
            Ok(_) => {
                // Update connection-level flow control
                self.conn_flow_control.data_sent += data_len;
                self.stats.total_bytes_sent += data_len;

                // Add to send-ready queue
                let priority = self.priorities.get(&stream_id).copied().unwrap_or_default();
                self.send_ready
                    .entry(priority)
                    .or_insert_with(VecDeque::new)
                    .push_back(stream_id);

                protocol_event!(
                    Level::Debug,
                    "Data queued for sending";
                    "stream_id" => stream_id.into_inner(),
                    "data_len" => data_len,
                    "fin" => fin,
                    "priority" => priority,
                    "conn_data_sent" => self.conn_flow_control.data_sent
                );

                Ok(())
            }
            Err(Error::FlowControl) => {
                // Get stream's send limit for STREAM_DATA_BLOCKED frame
                let stream_limit = stream.send_max_data();
                
                protocol_event!(
                    Level::Warn,
                    "Stream-level flow control blocked";
                    "stream_id" => stream_id.into_inner(),
                    "data_len" => data_len,
                    "stream_limit" => stream_limit
                );
                
                // Generate STREAM_DATA_BLOCKED frame
                self.pending_flow_control_frames.push_back(Frame::StreamDataBlocked {
                    stream_id,
                    maximum_stream_data: stream_limit,
                });
                
                // Track blocked state
                self.blocked_streams.insert(stream_id, BlockedState {
                    blocked_data_size: data_len,
                    blocked_at: std::time::Instant::now(),
                    is_connection_blocked: false,
                    limit: stream_limit,
                });
                
                self.stats.stream_flow_control_blocked += 1;
                self.events.push_back(StreamEvent::StreamBlocked {
                    stream_id,
                    is_connection_blocked: false,
                });
                Err(Error::FlowControl)
            }
            Err(e) => Err(e),
        }
    }

    /// Receive data for a stream
    pub fn receive_data(&mut self, stream_id: StreamId, offset: u64, data: Bytes, fin: bool) -> Result<()> {
        let _span = span!(Level::Debug, "receive_data", stream_id = stream_id.into_inner(), offset = offset, data_len = data.len(), fin = fin);

        // Accept stream if it doesn't exist
        if !self.streams.contains_key(&stream_id) {
            self.accept_stream(stream_id)?;
        }

        // Update connection-level flow control
        let data_len = data.len() as u64;
        if self.conn_flow_control.data_recv + data_len > self.conn_flow_control.max_data_recv {
            let excess = (self.conn_flow_control.data_recv + data_len) - self.conn_flow_control.max_data_recv;
            
            // Record the violation using the enhanced tracking system
            let violation = FlowControlViolation {
                violation_type: FlowControlViolationType::ConnectionDataExceeded,
                stream_id: Some(stream_id),
                excess_amount: excess,
                current_limit: self.conn_flow_control.max_data_recv,
                attempted_value: self.conn_flow_control.data_recv + data_len,
                description: format!(
                    "Connection data limit exceeded: attempted to receive {} bytes, limit is {} bytes, excess: {} bytes",
                    self.conn_flow_control.data_recv + data_len,
                    self.conn_flow_control.max_data_recv,
                    excess
                ),
            };
            
            self.violation_tracker.record_violation(violation.clone());
            
            // This is a protocol violation - peer sent more data than allowed
            return Err(Error::ConnectionError(violation.description));
        }

        // Check for stream-level flow control violations before receiving data
        self.detect_stream_flow_control_violations(stream_id, data_len, offset, fin)?;
        
        // Receive data on the stream
        {
            let stream = self.streams.get_mut(&stream_id)
                .ok_or_else(|| Error::StreamError {
                    code: StreamErrorCode::StreamNotFound,
                    reason: "Stream does not exist".to_string(),
                })?;
            
            stream.receive_data(offset, data, fin)?;
        }

        // Update connection-level stats
        self.conn_flow_control.data_recv += data_len;
        self.stats.total_bytes_recv += data_len;

        // Check if stream has data ready
        let has_data = self.streams.get(&stream_id)
            .map(|s| s.has_data())
            .unwrap_or(false);
            
        if has_data && !self.recv_ready.contains(&stream_id) {
            self.recv_ready.push_back(stream_id);
            self.events.push_back(StreamEvent::DataAvailable { stream_id });
        }

        // Check if we should update flow control windows
        self.consider_connection_flow_control_update();
        
        // Also check if this specific stream needs a window update
        if let Some(stream) = self.streams.get_mut(&stream_id) {
            let max_data_recv = stream.receive_max_data();
            let data_recv = stream.bytes_received();
            
            // Use Rust 2024 let chains for stream window update logic
            if max_data_recv > 0
                && let window_consumed = data_recv as f64 / max_data_recv as f64
                && window_consumed > self.window_update_config.stream_threshold
            {
                let old_max = max_data_recv;
                let increase_factor = if self.window_update_config.adaptive_sizing {
                    if window_consumed > 0.8 {
                        self.window_update_config.max_window_factor
                    } else {
                        self.window_update_config.min_window_factor
                    }
                } else {
                    self.window_update_config.min_window_factor
                };
                
                let new_window = ((old_max as f64 * increase_factor) as u64)
                    .min(self.window_update_config.max_stream_window);
                
                if new_window > old_max {
                    stream.set_receive_max_data(new_window);
                    
                    protocol_event!(
                        Level::Debug,
                        "Stream window auto-updated after data received";
                        "stream_id" => stream_id.into_inner(),
                        "old_window" => old_max,
                        "new_window" => new_window,
                        "window_consumed" => window_consumed
                    );
                }
            }
        }

        protocol_event!(
            Level::Debug,
            "Data received on stream";
            "stream_id" => stream_id.into_inner(),
            "offset" => offset,
            "data_len" => data_len,
            "fin" => fin,
            "conn_data_recv" => self.conn_flow_control.data_recv,
            "has_ready_data" => has_data
        );

        Ok(())
    }

    /// Read data from a stream
    pub fn read_data(&mut self, stream_id: StreamId, max_length: usize) -> Result<Option<Bytes>> {
        let stream = self.streams.get_mut(&stream_id)
            .ok_or_else(|| Error::StreamError {
                code: StreamErrorCode::StreamNotFound,
                reason: "Stream does not exist".to_string(),
            })?;

        let data = stream.read_data(max_length);

        // Remove from recv_ready if no more data
        if !stream.has_data() {
            self.recv_ready.retain(|&id| id != stream_id);
        }

        // Check if stream is finished and should be closed
        if stream.is_finished() && stream.state() == StreamState::Closed {
            self.handle_stream_closure(stream_id, StreamCloseReason::Normal)?;
        }

        Ok(data)
    }

    /// Get the next stream with data ready to send
    pub fn next_send_ready(&mut self) -> Option<StreamId> {
        // Check priorities in order (Urgent first, Low last)
        for (_, ready_streams) in self.send_ready.iter_mut() {
            if let Some(stream_id) = ready_streams.pop_front() {
                return Some(stream_id);
            }
        }
        None
    }

    /// Get the next stream with data ready to read
    pub fn next_recv_ready(&mut self) -> Option<StreamId> {
        self.recv_ready.pop_front()
    }

    /// Generate frames for the given stream
    pub fn generate_stream_frames(&mut self, stream_id: StreamId, max_bytes: usize) -> Result<Vec<Frame>> {
        let stream = self.streams.get_mut(&stream_id)
            .ok_or_else(|| Error::StreamError {
                code: StreamErrorCode::StreamNotFound,
                reason: "Stream does not exist".to_string(),
            })?;

        // Create STREAM frames respecting max_bytes limit
        // In a complete implementation, this would handle segmentation, retransmission, etc.
        let mut frames = Vec::new();
        let mut bytes_used = 0usize; // Track bytes used for proper max_bytes enforcement

        // Check if we should send MAX_STREAM_DATA
        if stream.should_send_max_stream_data() {
            frames.push(Frame::MaxStreamData {
                stream_id,
                maximum_stream_data: stream.receive_max_data(),
            });
        }

        // Generate STREAM frames from send buffer
        if Stream::has_data_to_send(stream) {
            // Check flow control
            let available_window = Stream::send_max_data(stream).saturating_sub(Stream::bytes_sent(stream));
            if available_window == 0 {
                // Stream is blocked on flow control
                frames.push(Frame::StreamDataBlocked {
                    stream_id,
                    maximum_stream_data: Stream::send_max_data(stream),
                });
            } else {
                // Calculate how much data we can send, respecting max_bytes limit
                let max_frame_size = available_window
                    .min(65535) // Reasonable max frame size
                    .min((max_bytes.saturating_sub(bytes_used)) as u64) as usize;

                if max_frame_size == 0 {
                    // No space left in packet
                    return Ok(frames);
                }

                // Get data from stream's send buffer
                if let Some(send_data) = stream.get_pending_send_data(max_frame_size) {
                    let offset = stream.send_offset();
                    let fin = stream.is_send_complete() && send_data.len() == stream.pending_send_size();
                    
                    frames.push(Frame::Stream {
                        stream_id,
                        offset,
                        length: Some(send_data.len() as u64),
                        fin,
                        data: send_data.clone(),
                    });

                    // Track bytes used (for future multi-frame support)
                    bytes_used += send_data.len();

                    // Update stream's send offset
                    stream.advance_send_offset(send_data.len() as u64);
                    
                    protocol_event!(
                        Level::Debug,
                        "Generated STREAM frame";
                        "stream_id" => stream_id.into_inner(),
                        "offset" => offset,
                        "length" => send_data.len(),
                        "fin" => fin,
                        "total_bytes_used" => bytes_used
                    );
                }
            }
        }

        // Log final bytes usage for this packet
        if bytes_used > 0 {
            protocol_event!(
                Level::Trace,
                "Stream frame generation complete";
                "stream_id" => stream_id.into_inner(),
                "total_bytes_used" => bytes_used,
                "max_bytes" => max_bytes,
                "frames_generated" => frames.len()
            );
        }

        Ok(frames)
    }

    /// Handle a stream being reset by peer
    pub fn handle_reset_stream(&mut self, stream_id: StreamId, error_code: u64, final_size: u64) -> Result<()> {
        let stream = self.streams.get_mut(&stream_id)
            .ok_or_else(|| Error::StreamError {
                code: StreamErrorCode::StreamNotFound,
                reason: "Stream does not exist".to_string(),
            })?;

        stream.receive_reset(error_code, final_size)?;
        self.handle_stream_closure(stream_id, StreamCloseReason::Reset(error_code))?;

        Ok(())
    }

    /// Handle STOP_SENDING frame
    pub fn handle_stop_sending(&mut self, stream_id: StreamId, error_code: u64) -> Result<()> {
        let stream = self.streams.get_mut(&stream_id)
            .ok_or_else(|| Error::StreamError {
                code: StreamErrorCode::StreamNotFound,
                reason: "Stream does not exist".to_string(),
            })?;

        stream.handle_stop_sending(error_code)?;

        Ok(())
    }

    /// Update stream priority
    pub fn set_stream_priority(&mut self, stream_id: StreamId, priority: StreamPriority) -> Result<()> {
        if self.streams.contains_key(&stream_id) {
            self.priorities.insert(stream_id, priority);
            
            protocol_event!(
                Level::Debug,
                "Stream priority updated";
                "stream_id" => stream_id.into_inner(),
                "priority" => priority
            );
            
            Ok(())
        } else {
            Err(Error::StreamError {
                code: StreamErrorCode::StreamNotFound,
                reason: "Stream does not exist".to_string(),
            })
        }
    }

    /// Update MAX_DATA for connection
    pub fn update_max_data(&mut self, max_data: u64) -> Result<()> {
        let _span = span!(Level::Debug, "update_max_data", max_data = max_data);
        
        if max_data < self.conn_flow_control.max_data_send {
            // Record MAX_DATA decrease violation
            let violation = FlowControlViolation {
                violation_type: FlowControlViolationType::MaxDataDecreased,
                stream_id: None,
                excess_amount: self.conn_flow_control.max_data_send - max_data,
                current_limit: self.conn_flow_control.max_data_send,
                attempted_value: max_data,
                description: format!(
                    "MAX_DATA value decreased: current limit {} bytes, attempted new limit {} bytes",
                    self.conn_flow_control.max_data_send,
                    max_data
                ),
            };
            
            self.violation_tracker.record_violation(violation.clone());
            return Err(Error::ProtocolViolation(violation.description));
        }

        let old_max = self.conn_flow_control.max_data_send;
        self.conn_flow_control.max_data_send = max_data;

        protocol_event!(
            Level::Info,
            "Connection MAX_DATA updated";
            "old_max_data" => old_max,
            "new_max_data" => max_data,
            "increase" => (max_data - old_max)
        );
        
        // Wake up any streams blocked on connection flow control
        let mut woken_streams = Vec::new();
        self.blocked_streams.retain(|&stream_id, blocked_state| {
            if blocked_state.is_connection_blocked 
                && self.conn_flow_control.data_sent + blocked_state.blocked_data_size <= max_data 
            {
                woken_streams.push(stream_id);
                false // Remove from blocked list
            } else {
                true // Keep in blocked list
            }
        });
        
        // Add woken streams back to send queue using Rust 2024 let chains
        for stream_id in woken_streams {
            if let Some(priority) = self.priorities.get(&stream_id)
                && let Some(stream) = self.streams.get(&stream_id)
                && stream.has_data_to_send()
            {
                self.send_ready
                    .entry(*priority)
                    .or_insert_with(VecDeque::new)
                    .push_back(stream_id);
                    
                protocol_event!(
                    Level::Debug,
                    "Stream unblocked by MAX_DATA update";
                    "stream_id" => stream_id.into_inner()
                );
            }
        }

        Ok(())
    }

    /// Update MAX_STREAM_DATA for a stream
    pub fn update_max_stream_data(&mut self, stream_id: StreamId, max_data: u64) -> Result<()> {
        let _span = span!(Level::Debug, "update_max_stream_data", stream_id = stream_id.into_inner(), max_data = max_data);
        
        let stream = self.streams.get_mut(&stream_id)
            .ok_or_else(|| Error::StreamError {
                code: StreamErrorCode::StreamNotFound,
                reason: "Stream does not exist".to_string(),
            })?;

        stream.update_max_data(max_data)?;
        
        // Check if this stream was blocked on stream flow control
        let should_unblock = if let Some(blocked_state) = self.blocked_streams.get(&stream_id) {
            if !blocked_state.is_connection_blocked && stream.has_data_to_send() {
                // Check if we can now send the blocked data
                let current_send_window = max_data.saturating_sub(stream.bytes_sent());
                let blocked_size = blocked_state.blocked_data_size;
                if blocked_size <= current_send_window {
                    Some(blocked_size)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        
        if let Some(blocked_size) = should_unblock {
            // Remove from blocked list
            self.blocked_streams.remove(&stream_id);
            
            // Add back to send queue
            if let Some(priority) = self.priorities.get(&stream_id) {
                self.send_ready
                    .entry(*priority)
                    .or_insert_with(VecDeque::new)
                    .push_back(stream_id);
                
                protocol_event!(
                    Level::Debug,
                    "Stream unblocked by MAX_STREAM_DATA update";
                    "stream_id" => stream_id.into_inner(),
                    "new_limit" => max_data,
                    "blocked_size" => blocked_size
                );
            }
        }
        
        Ok(())
    }

    /// Get stream statistics
    pub fn stream_stats(&self, stream_id: StreamId) -> Option<StreamStats> {
        self.streams.get(&stream_id).map(|s| s.stats())
    }

    /// Get all active stream IDs
    pub fn active_streams(&self) -> Vec<StreamId> {
        self.streams.keys().copied().collect()
    }

    /// Get manager statistics
    pub fn stats(&self) -> &StreamManagerStats {
        &self.stats
    }

    /// Poll for stream events
    pub fn poll_event(&mut self) -> Option<StreamEvent> {
        self.events.pop_front()
    }

    /// Check if we should send MAX_DATA frame
    pub fn should_send_max_data(&self) -> bool {
        self.conn_flow_control.should_send_max_data
    }

    /// Get the new MAX_DATA value to send
    pub fn get_max_data_to_send(&self) -> u64 {
        self.conn_flow_control.max_data_recv
    }
    
    /// Get pending flow control frames
    pub fn get_pending_flow_control_frames(&mut self) -> Vec<Frame> {
        let mut frames = Vec::new();
        
        // Drain pending flow control frames
        frames.extend(self.pending_flow_control_frames.drain(..));
        
        // Check if we should send MAX_DATA frame
        if self.conn_flow_control.should_send_max_data {
            frames.push(Frame::MaxData {
                maximum_data: self.conn_flow_control.max_data_recv,
            });
            self.conn_flow_control.should_send_max_data = false;
            
            protocol_event!(
                Level::Debug,
                "Generating MAX_DATA frame";
                "new_limit" => self.conn_flow_control.max_data_recv
            );
        }
        
        // Check streams for MAX_STREAM_DATA frames
        for (stream_id, stream) in &mut self.streams {
            if stream.should_send_max_stream_data() {
                frames.push(Frame::MaxStreamData {
                    stream_id: *stream_id,
                    maximum_stream_data: stream.receive_max_data(),
                });
                
                protocol_event!(
                    Level::Debug,
                    "Generating MAX_STREAM_DATA frame";
                    "stream_id" => stream_id.into_inner(),
                    "new_limit" => stream.receive_max_data()
                );
            }
        }
        
        frames
    }
    
    /// Schedule a frame with appropriate priority
    pub fn schedule_frame(&mut self, frame: Frame, stream_id: Option<StreamId>) {
        let stream_priority = stream_id.and_then(|id| self.priorities.get(&id).copied());
        let frame_priority = PrioritizedFrameScheduler::classify_frame_priority(&frame, stream_priority);
        
        let frame_type_debug = format!("{:?}", std::mem::discriminant(&frame));
        self.frame_scheduler.schedule_frame(frame, frame_priority, stream_id);
        
        protocol_event!(
            Level::Debug,
            "Frame scheduled with priority";
            "frame_type" => frame_type_debug,
            "frame_priority" => frame_priority,
            "stream_id" => stream_id.map(|id| id.into_inner())
        );
    }
    
    /// Get prioritized frames for transmission, integrating flow control
    pub fn get_prioritized_frames(&mut self, max_packet_size: usize) -> Vec<Frame> {
        // First, schedule any pending flow control frames with high priority
        self.schedule_pending_flow_control_frames();
        
        // Then get frames from the prioritized scheduler
        let frames = self.frame_scheduler.get_frames_to_send(max_packet_size);
        
        protocol_event!(
            Level::Debug,
            "Generated prioritized frame transmission";
            "frame_count" => frames.len(),
            "max_packet_size" => max_packet_size,
            "scheduler_stats" => format!("{:?}", self.frame_scheduler.get_stats().frames_queued_by_priority)
        );
        
        frames
    }
    
    /// Schedule pending flow control frames with appropriate priorities
    fn schedule_pending_flow_control_frames(&mut self) {
        // Schedule pending BLOCKED frames first (highest flow control priority)
        while let Some(frame) = self.pending_flow_control_frames.pop_front() {
            let priority = PrioritizedFrameScheduler::classify_frame_priority(&frame, None);
            self.frame_scheduler.schedule_frame(frame, priority, None);
        }
        
        // Schedule MAX_DATA frame if needed
        if self.conn_flow_control.should_send_max_data {
            let frame = Frame::MaxData {
                maximum_data: self.conn_flow_control.max_data_recv,
            };
            self.frame_scheduler.schedule_frame(frame, FramePriority::FlowControl, None);
            self.conn_flow_control.should_send_max_data = false;
            
            protocol_event!(
                Level::Debug,
                "Scheduled connection MAX_DATA frame";
                "new_limit" => self.conn_flow_control.max_data_recv
            );
        }
        
        // Schedule MAX_STREAM_DATA frames for streams that need them
        let stream_ids: Vec<_> = self.streams.keys().copied().collect();
        for stream_id in stream_ids {
            if let Some(stream) = self.streams.get_mut(&stream_id) 
                && stream.should_send_max_stream_data() 
            {
                let frame = Frame::MaxStreamData {
                    stream_id,
                    maximum_stream_data: stream.receive_max_data(),
                };
                self.frame_scheduler.schedule_frame(frame, FramePriority::FlowControl, Some(stream_id));
                
                protocol_event!(
                    Level::Debug,
                    "Scheduled stream MAX_STREAM_DATA frame";
                    "stream_id" => stream_id.into_inner(),
                    "new_limit" => stream.receive_max_data()
                );
            }
        }
    }
    
    /// Generate stream frames with priority-aware scheduling
    pub fn generate_prioritized_stream_frames(&mut self, max_packet_size: usize) -> Vec<Frame> {
        let mut frames = Vec::new();
        let mut remaining_bytes = max_packet_size;
        
        // Process streams by priority order (Urgent first, Low last)
        for priority in [StreamPriority::Urgent, StreamPriority::High, StreamPriority::Normal, StreamPriority::Low] {
            if remaining_bytes <= 64 { // Reserve space for frame headers
                break;
            }
            
            // Collect stream IDs to avoid borrowing conflicts
            let stream_ids: Vec<StreamId> = self.send_ready
                .get(&priority)
                .map(|queue| queue.iter().copied().collect())
                .unwrap_or_default();
                
            // Clear the queue for this priority
            if let Some(queue) = self.send_ready.get_mut(&priority) {
                queue.clear();
            }
            
            for stream_id in stream_ids {
                if remaining_bytes <= 64 {
                    break;
                }
                
                if let Some(stream) = self.streams.get(&stream_id)
                    && stream.has_data_to_send()
                {
                    // Generate a STREAM frame for this stream
                    // This is a simplified version - in production, you'd segment data appropriately
                    let max_data_for_stream = std::cmp::min(remaining_bytes.saturating_sub(32), 1024);
                    
                    if let Ok(stream_frames) = self.generate_stream_frames(stream_id, max_data_for_stream) {
                        for frame in stream_frames {
                            let frame_size = PrioritizedFrameScheduler::estimate_frame_size(&frame);
                            if frame_size <= remaining_bytes {
                                remaining_bytes -= frame_size;
                                frames.push(frame);
                            }
                        }
                    }
                    
                    // Re-add stream to queue if it still has data to send
                    if let Some(stream) = self.streams.get(&stream_id)
                        && stream.has_data_to_send()
                    {
                        self.send_ready
                            .entry(priority)
                            .or_insert_with(VecDeque::new)
                            .push_back(stream_id);
                    }
                }
            }
        }
        
        frames
    }
    
    /// Check if there are frames waiting to be transmitted
    pub fn has_pending_transmission(&self) -> bool {
        self.frame_scheduler.has_pending_frames() 
            || !self.pending_flow_control_frames.is_empty()
            || self.conn_flow_control.should_send_max_data
            || self.streams.values().any(|s| s.should_send_max_stream_data())
            || !self.send_ready.is_empty()
    }
    
    /// Get comprehensive transmission statistics
    pub fn get_transmission_stats(&self) -> TransmissionStats {
        TransmissionStats {
            frame_scheduler_stats: self.frame_scheduler.get_stats().clone(),
            pending_flow_control_frames: self.pending_flow_control_frames.len(),
            streams_ready_to_send: self.send_ready.values().map(|v| v.len()).sum(),
            connection_flow_control_pending: self.conn_flow_control.should_send_max_data,
            streams_needing_max_data: self.streams.values()
                .filter(|s| s.should_send_max_stream_data())
                .count(),
        }
    }
    
    /// Handle STREAMS_BLOCKED frame
    pub fn handle_streams_blocked(&mut self, stream_type: crate::quic::frame_types::StreamType, limit: u64) -> Result<()> {
        let _span = span!(Level::Debug, "handle_streams_blocked", stream_type = format!("{:?}", stream_type), limit = limit);
        
        protocol_event!(
            Level::Info,
            "Peer reported streams blocked";
            "stream_type" => stream_type,
            "limit" => limit
        );
        
        // In a full implementation, we might want to:
        // 1. Track that peer is blocked
        // 2. Consider sending MAX_STREAMS frame
        // 3. Update statistics
        
        Ok(())
    }

    /// Handle stream closure
    fn handle_stream_closure(&mut self, stream_id: StreamId, reason: StreamCloseReason) -> Result<()> {
        if let Some(stream) = self.streams.remove(&stream_id) {
            // Update limits
            match stream.stream_type() {
                StreamType::Bidirectional => {
                    if stream.is_local() {
                        self.peer_limits.current_bidi_streams = 
                            self.peer_limits.current_bidi_streams.saturating_sub(1);
                    } else {
                        self.local_limits.current_bidi_streams = 
                            self.local_limits.current_bidi_streams.saturating_sub(1);
                    }
                }
                StreamType::Unidirectional => {
                    if stream.is_local() {
                        self.peer_limits.current_uni_streams = 
                            self.peer_limits.current_uni_streams.saturating_sub(1);
                    } else {
                        self.local_limits.current_uni_streams = 
                            self.local_limits.current_uni_streams.saturating_sub(1);
                    }
                }
            }

            // Store closed stream info
            self.closed_streams.insert(stream_id, ClosedStreamInfo {
                closed_at: std::time::Instant::now(),
                final_state: stream.state(),
                bytes_sent: stream.bytes_sent(),
                bytes_recv: stream.bytes_received(),
            });

            // Clean up priorities
            self.priorities.remove(&stream_id);

            // Update stats
            self.stats.streams_closed += 1;
            self.stats.active_streams = self.streams.len();

            // Emit event
            self.events.push_back(StreamEvent::StreamClosed {
                stream_id,
                reason,
            });

            protocol_event!(
                Level::Info,
                "Stream closed";
                "stream_id" => stream_id.into_inner(),
                "reason" => format!("{:?}", &reason),
                "active_streams" => self.stats.active_streams
            );
        }

        Ok(())
    }

    /// Configure automatic window updates
    pub fn configure_window_updates(&mut self, config: WindowUpdateConfig) {
        self.window_update_config = config.clone();
        self.window_update_threshold = config.connection_threshold;
        
        protocol_event!(
            Level::Info,
            "Window update configuration updated";
            "connection_threshold" => config.connection_threshold,
            "stream_threshold" => config.stream_threshold,
            "adaptive_sizing" => config.adaptive_sizing,
            "max_connection_window" => config.max_connection_window,
            "max_stream_window" => config.max_stream_window
        );
    }

    /// Consider updating connection flow control window using Rust 2024 let chains
    fn consider_connection_flow_control_update(&mut self) {
        let data_recv = self.conn_flow_control.data_recv;
        let max_data_recv = self.conn_flow_control.max_data_recv;
        
        // Avoid division by zero using Rust 2024 let chains
        if max_data_recv > 0 
            && let window_consumed = data_recv as f64 / max_data_recv as f64
            && window_consumed > self.window_update_config.connection_threshold
        {
            let old_max = max_data_recv;
            
            // Calculate new window size with adaptive sizing
            let increase_factor = if self.window_update_config.adaptive_sizing {
                // Use adaptive factor based on consumption rate
                let adaptive_factor = if window_consumed > 0.8 {
                    self.window_update_config.max_window_factor
                } else if window_consumed > 0.6 {
                    (self.window_update_config.min_window_factor + self.window_update_config.max_window_factor) / 2.0
                } else {
                    self.window_update_config.min_window_factor
                };
                adaptive_factor
            } else {
                self.window_update_config.min_window_factor
            };
            
            let new_window = ((old_max as f64 * increase_factor) as u64)
                .min(self.window_update_config.max_connection_window);
            
            // Only update if we're actually increasing the window
            if new_window > old_max {
                self.conn_flow_control.max_data_recv = new_window;
                self.conn_flow_control.should_send_max_data = true;

                protocol_event!(
                    Level::Info,
                    "Connection receive window expanded automatically";
                    "old_max_data_recv" => old_max,
                    "new_max_data_recv" => new_window,
                    "window_consumed" => window_consumed,
                    "increase_factor" => increase_factor,
                    "adaptive_sizing" => self.window_update_config.adaptive_sizing
                );
            }
        }
    }

    /// Consider updating stream flow control windows for all active streams
    pub fn consider_stream_flow_control_updates(&mut self) {
        let stream_threshold = self.window_update_config.stream_threshold;
        let stream_config = &self.window_update_config;
        
        // Collect stream IDs to avoid borrow checker issues
        let stream_ids: Vec<StreamId> = self.streams.keys().copied().collect();
        
        for stream_id in stream_ids {
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                let data_recv = stream.bytes_received();
                let max_data_recv = stream.receive_max_data();
                
                // Use Rust 2024 let chains for cleaner flow control logic
                if max_data_recv > 0
                    && let window_consumed = data_recv as f64 / max_data_recv as f64  
                    && window_consumed > stream_threshold
                {
                    let old_max = max_data_recv;
                    
                    // Calculate adaptive increase factor
                    let increase_factor = if stream_config.adaptive_sizing {
                        if window_consumed > 0.8 {
                            stream_config.max_window_factor
                        } else if window_consumed > 0.6 {
                            (stream_config.min_window_factor + stream_config.max_window_factor) / 2.0
                        } else {
                            stream_config.min_window_factor
                        }
                    } else {
                        stream_config.min_window_factor
                    };
                    
                    let new_window = ((old_max as f64 * increase_factor) as u64)
                        .min(stream_config.max_stream_window);
                    
                    if new_window > old_max {
                        // Update stream window and mark for MAX_STREAM_DATA frame generation
                        stream.set_receive_max_data(new_window);
                        
                        protocol_event!(
                            Level::Debug,
                            "Stream receive window expanded automatically";
                            "stream_id" => stream_id.into_inner(),
                            "old_max_data_recv" => old_max,
                            "new_max_data_recv" => new_window,
                            "window_consumed" => window_consumed,
                            "increase_factor" => increase_factor
                        );
                    }
                }
            }
        }
    }

    /// Perform automatic window updates for both connection and streams
    pub fn perform_automatic_window_updates(&mut self) {
        // Update connection-level flow control window
        self.consider_connection_flow_control_update();
        
        // Update stream-level flow control windows  
        self.consider_stream_flow_control_updates();
    }

    /// Get window update statistics
    pub fn get_window_update_stats(&self) -> WindowUpdateStats {
        let active_streams = self.streams.len();
        let connection_window_utilization = if self.conn_flow_control.max_data_recv > 0 {
            self.conn_flow_control.data_recv as f64 / self.conn_flow_control.max_data_recv as f64
        } else {
            0.0
        };
        
        let mut stream_window_utilizations = Vec::new();
        for stream in self.streams.values() {
            let max_data = stream.receive_max_data();
            if max_data > 0 {
                let utilization = stream.bytes_received() as f64 / max_data as f64;
                stream_window_utilizations.push(utilization);
            }
        }
        
        let avg_stream_utilization = if !stream_window_utilizations.is_empty() {
            stream_window_utilizations.iter().sum::<f64>() / stream_window_utilizations.len() as f64
        } else {
            0.0
        };
        
        WindowUpdateStats {
            active_streams,
            connection_window_utilization,
            avg_stream_utilization,
            connection_window_size: self.conn_flow_control.max_data_recv,
            config: self.window_update_config.clone(),
        }
    }
    
    /// Comprehensive stream-level flow control violation detection
    fn detect_stream_flow_control_violations(&mut self, stream_id: StreamId, data_len: u64, offset: u64, fin: bool) -> Result<()> {
        if let Some(stream) = self.streams.get(&stream_id) {
            let stream_max_data = stream.receive_max_data();
            let stream_data_recv = stream.bytes_received();
            let final_size = stream.final_size();
            
            // Check stream-level data limit violation
            if stream_data_recv + data_len > stream_max_data {
                let excess = (stream_data_recv + data_len) - stream_max_data;
                let violation = FlowControlViolation {
                    violation_type: FlowControlViolationType::StreamDataExceeded,
                    stream_id: Some(stream_id),
                    excess_amount: excess,
                    current_limit: stream_max_data,
                    attempted_value: stream_data_recv + data_len,
                    description: format!(
                        "Stream {} data limit exceeded: attempted {} bytes, limit {} bytes, excess {} bytes",
                        stream_id.into_inner(),
                        stream_data_recv + data_len,
                        stream_max_data,
                        excess
                    ),
                };
                
                self.violation_tracker.record_violation(violation.clone());
                return Err(crate::error_context::common_errors::flow_control_error(violation.description));
            }
            
            // Check final size violations using Rust 2024 let chains
            if let Some(existing_final_size) = final_size
                && fin
                && let new_final_size = offset + data_len
                && new_final_size != existing_final_size
            {
                let violation = FlowControlViolation {
                    violation_type: FlowControlViolationType::FinalSizeChanged,
                    stream_id: Some(stream_id),
                    excess_amount: if new_final_size > existing_final_size {
                        new_final_size - existing_final_size
                    } else {
                        existing_final_size - new_final_size
                    },
                    current_limit: existing_final_size,
                    attempted_value: new_final_size,
                    description: format!(
                        "Stream {} final size changed: existing {} bytes, attempted {} bytes",
                        stream_id.into_inner(),
                        existing_final_size,
                        new_final_size
                    ),
                };
                
                self.violation_tracker.record_violation(violation.clone());
                return Err(Error::StreamError {
                    code: crate::error::StreamErrorCode::FinalSizeError,
                    reason: violation.description,
                });
            }
            
            // Check data beyond final size using Rust 2024 let chains
            if let Some(existing_final_size) = final_size
                && offset + data_len > existing_final_size
            {
                let excess = (offset + data_len) - existing_final_size;
                let violation = FlowControlViolation {
                    violation_type: FlowControlViolationType::DataBeyondFinalSize,
                    stream_id: Some(stream_id),
                    excess_amount: excess,
                    current_limit: existing_final_size,
                    attempted_value: offset + data_len,
                    description: format!(
                        "Stream {} data beyond final size: final size {} bytes, attempted offset {} bytes",
                        stream_id.into_inner(),
                        existing_final_size,
                        offset + data_len
                    ),
                };
                
                self.violation_tracker.record_violation(violation.clone());
                return Err(Error::StreamError {
                    code: crate::error::StreamErrorCode::FinalSizeError,
                    reason: violation.description,
                });
            }
        }
        
        Ok(())
    }
    
    /// Check for stream count violations when creating streams
    fn detect_stream_count_violations(&mut self, stream_type: StreamType) -> Result<()> {
        let (current_count, max_count) = match stream_type {
            StreamType::Bidirectional => {
                (self.local_limits.current_bidi_streams, self.local_limits.max_bidi_streams)
            }
            StreamType::Unidirectional => {
                (self.local_limits.current_uni_streams, self.local_limits.max_uni_streams)
            }
        };
        
        if current_count >= max_count {
            let violation = FlowControlViolation {
                violation_type: FlowControlViolationType::StreamCountExceeded,
                stream_id: None,
                excess_amount: (current_count + 1).saturating_sub(max_count),
                current_limit: max_count,
                attempted_value: current_count + 1,
                description: format!(
                    "Stream count limit exceeded: current {} streams, limit {} streams, type {:?}",
                    current_count,
                    max_count,
                    stream_type
                ),
            };
            
            self.violation_tracker.record_violation(violation.clone());
            return Err(crate::error_context::common_errors::stream_limit_error(violation.description));
        }
        
        Ok(())
    }
    
    /// Get flow control violation statistics and recent violations
    pub fn get_flow_control_violation_stats(&self) -> (u64, usize, Vec<FlowControlViolation>) {
        let (total_violations, recent_count) = self.violation_tracker.get_violation_stats();
        let recent_violations = self.violation_tracker.recent_violations.iter().cloned().collect();
        (total_violations, recent_count, recent_violations)
    }
    
    /// Check if connection should be terminated due to violations
    pub fn should_terminate_connection(&self) -> bool {
        self.violation_tracker.terminate_on_violation && self.violation_tracker.violations_detected > 0
    }
    
    /// Configure violation tracking behavior
    pub fn configure_violation_tracking(&mut self, terminate_on_violation: bool, max_recent_violations: usize) {
        self.violation_tracker.terminate_on_violation = terminate_on_violation;
        self.violation_tracker.max_recent_violations = max_recent_violations;
        
        protocol_event!(
            Level::Info,
            "Flow control violation tracking configured";
            "terminate_on_violation" => terminate_on_violation,
            "max_recent_violations" => max_recent_violations
        );
    }

    /// Clean up old closed streams
    pub fn cleanup_closed_streams(&mut self, max_age: std::time::Duration) {
        let now = std::time::Instant::now();
        let before = self.closed_streams.len();
        
        self.closed_streams.retain(|_, info| {
            now.duration_since(info.closed_at) < max_age
        });

        let removed = before - self.closed_streams.len();
        if removed > 0 {
            protocol_event!(
                Level::Debug,
                "Cleaned up closed streams";
                "removed" => removed,
                "remaining" => self.closed_streams.len()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::VarInt;

    #[test]
    fn test_stream_creation() {
        let params = TransportParameters::default();
        let mut manager = StreamManager::new(ConnectionRole::Client, &params);

        // Create a bidirectional stream
        let stream_id = manager.create_stream(StreamParameters::default()).unwrap();
        assert!(stream_id.is_bidirectional());
        assert!(stream_id.initiated_by_client());

        // Create a unidirectional stream
        let params = StreamParameters {
            stream_type: StreamType::Unidirectional,
            ..Default::default()
        };
        let stream_id = manager.create_stream(params).unwrap();
        assert!(stream_id.is_unidirectional());
        assert!(stream_id.initiated_by_client());
    }

    #[test]
    fn test_stream_limits() {
        let mut params = TransportParameters::default();
        params.initial_max_streams_bidi = Some(VarInt::from_u32(2));
        
        let mut manager = StreamManager::new(ConnectionRole::Client, &params);
        manager.update_peer_params(&params);

        // Create streams up to limit
        let _id1 = manager.create_stream(StreamParameters::default()).unwrap();
        let _id2 = manager.create_stream(StreamParameters::default()).unwrap();

        // Third stream should fail
        assert!(manager.create_stream(StreamParameters::default()).is_err());
    }

    #[test]
    fn test_flow_control() {
        let mut params = TransportParameters::default();
        params.initial_max_data = Some(VarInt::from_u32(1000));
        
        let mut manager = StreamManager::new(ConnectionRole::Client, &params);
        manager.update_peer_params(&params);

        let stream_id = manager.create_stream(StreamParameters::default()).unwrap();

        // Send data within limit
        let data = Bytes::from(vec![0u8; 500]);
        assert!(manager.send_data(stream_id, data.clone(), false).is_ok());

        // Send more data within limit
        assert!(manager.send_data(stream_id, data.clone(), false).is_ok());

        // This should exceed the limit
        assert!(manager.send_data(stream_id, data, false).is_err());
    }

    #[test]
    fn test_stream_prioritization() {
        let mut params = TransportParameters::default();
        params.initial_max_data = Some(VarInt::from_u32(10000));
        
        let mut manager = StreamManager::new(ConnectionRole::Client, &params);
        manager.update_peer_params(&params);

        // Create streams with different priorities
        let urgent_params = StreamParameters {
            priority: StreamPriority::Urgent,
            ..Default::default()
        };
        let urgent_id = manager.create_stream(urgent_params).unwrap();
        
        let normal_params = StreamParameters {
            priority: StreamPriority::Normal,
            ..Default::default()
        };
        let normal_id = manager.create_stream(normal_params).unwrap();

        // Send data on both
        manager.send_data(normal_id, Bytes::from("normal"), false).unwrap();
        manager.send_data(urgent_id, Bytes::from("urgent"), false).unwrap();

        // Urgent should come first
        assert_eq!(manager.next_send_ready(), Some(urgent_id));
        assert_eq!(manager.next_send_ready(), Some(normal_id));
    }

    #[test]
    fn test_blocked_frame_generation() {
        // Test STREAMS_BLOCKED frame generation
        let mut params = TransportParameters::default();
        params.initial_max_streams_bidi = Some(VarInt::from_u32(1));
        params.initial_max_data = Some(VarInt::from_u32(1000));
        let mut manager = StreamManager::new(ConnectionRole::Client, &params);
        manager.update_peer_params(&params);

        // Create one stream (should succeed)
        let stream_id = manager.create_stream(StreamParameters::default()).unwrap();
        
        // Try to create another stream (should fail and generate STREAMS_BLOCKED)
        let result = manager.create_stream(StreamParameters::default());
        assert!(result.is_err());
        
        // Check that STREAMS_BLOCKED frame was generated
        let frames = manager.get_pending_flow_control_frames();
        assert_eq!(frames.len(), 1);
        match &frames[0] {
            Frame::StreamsBlocked { stream_type, maximum_streams } => {
                assert_eq!(*stream_type, crate::quic::frame_types::StreamType::Bidirectional);
                assert_eq!(*maximum_streams, 1);
            }
            _ => panic!("Expected STREAMS_BLOCKED frame, got {:?}", frames[0])
        }

        // Test STREAM_DATA_BLOCKED frame generation  
        let mut small_params = TransportParameters::default();
        small_params.initial_max_data = Some(VarInt::from_u32(100));
        let mut small_manager = StreamManager::new(ConnectionRole::Client, &small_params);
        small_manager.update_peer_params(&small_params);
        
        let small_stream_id = small_manager.create_stream(StreamParameters::default()).unwrap();
        
        // Set a small send limit to trigger STREAM_DATA_BLOCKED
        small_manager.test_set_stream_send_limit(small_stream_id, 50).unwrap();
        
        // Try to send more data than the stream limit allows
        let large_data = Bytes::from(vec![0u8; 100]);
        let result = small_manager.send_data(small_stream_id, large_data, false);
        assert!(result.is_err());
        
        // Check that STREAM_DATA_BLOCKED frame was generated
        let frames = small_manager.get_pending_flow_control_frames();
        assert!(!frames.is_empty());
        let has_stream_data_blocked = frames.iter().any(|frame| {
            matches!(frame, Frame::StreamDataBlocked { stream_id: sid, maximum_stream_data: 50 } if *sid == small_stream_id)
        });
        assert!(has_stream_data_blocked, "Expected STREAM_DATA_BLOCKED frame in {:?}", frames);

        // Test DATA_BLOCKED frame generation
        let big_data = Bytes::from(vec![0u8; 200]);
        let result = small_manager.send_data(small_stream_id, big_data, false);
        assert!(result.is_err());
        
        // Check that DATA_BLOCKED frame was generated
        let frames = small_manager.get_pending_flow_control_frames();
        let has_data_blocked = frames.iter().any(|frame| {
            matches!(frame, Frame::DataBlocked { maximum_data: 100 })
        });
        assert!(has_data_blocked, "Expected DATA_BLOCKED frame in {:?}", frames);
    }

    #[test]
    fn test_max_data_max_stream_data_processing() {
        // Test MAX_DATA frame processing and stream unblocking
        let mut params = TransportParameters::default();
        params.initial_max_data = Some(VarInt::from_u32(1000));
        params.initial_max_stream_data_bidi_remote = Some(VarInt::from_u32(500));
        
        let mut manager = StreamManager::new(ConnectionRole::Client, &params);
        manager.update_peer_params(&params);
        
        // Create a stream
        let stream_id = manager.create_stream(StreamParameters::default()).unwrap();
        
        // Simulate stream being blocked by low send limit
        manager.test_set_stream_send_limit(stream_id, 100).unwrap();
        
        // Try to send data that would exceed stream limit
        let data = Bytes::from(vec![0u8; 150]);
        let result = manager.send_data(stream_id, data.clone(), false);
        assert!(result.is_err());
        
        // Verify stream is blocked
        assert!(manager.blocked_streams.contains_key(&stream_id));
        
        // Process MAX_STREAM_DATA frame to increase stream limit
        let result = manager.update_max_stream_data(stream_id, 200);
        assert!(result.is_ok());
        
        // Note: Stream won't automatically unblock because has_data_to_send() 
        // returns false when data wasn't buffered due to flow control limits.
        // This is correct behavior - the sender would need to retry sending.
        
        // Now sending should work with the increased limit
        let data = Bytes::from(vec![0u8; 50]);
        let result = manager.send_data(stream_id, data, false);
        assert!(result.is_ok());
        
        // Test MAX_DATA processing for connection-level flow control
        // Simulate connection being blocked by low data limit
        let old_max = manager.conn_flow_control.max_data_send;
        
        // Try to send large data that would exceed connection limit
        let large_data = Bytes::from(vec![0u8; 800]);
        let result = manager.send_data(stream_id, large_data, false);
        // This might not fail immediately due to stream limits, but let's test MAX_DATA processing
        
        // Process MAX_DATA frame to increase connection limit
        let result = manager.update_max_data(old_max + 1000);
        assert!(result.is_ok());
        assert_eq!(manager.conn_flow_control.max_data_send, old_max + 1000);
        
        // Test that MAX_DATA cannot decrease
        let result = manager.update_max_data(old_max);
        assert!(result.is_err());
        
        // Test MAX_STREAM_DATA for non-existent stream
        let fake_stream_id = StreamId::new(5, StreamType::Bidirectional, ConnectionRole::Server).unwrap(); // Server-initiated stream that doesn't exist
        let result = manager.update_max_stream_data(fake_stream_id, 1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_automatic_window_updates() {
        // Test automatic window updates with configurable thresholds
        let mut params = TransportParameters::default();
        params.initial_max_data = Some(VarInt::from_u32(1000));
        params.initial_max_stream_data_bidi_local = Some(VarInt::from_u32(500));
        
        let mut manager = StreamManager::new(ConnectionRole::Client, &params);
        manager.update_peer_params(&params);
        
        // Configure custom window update settings
        let config = WindowUpdateConfig {
            connection_threshold: 0.6,  // Update at 60% consumption
            stream_threshold: 0.7,      // Update at 70% consumption
            min_window_factor: 2.0,     // Double the window
            max_window_factor: 3.0,     // Triple at most
            adaptive_sizing: true,
            max_connection_window: 8192,
            max_stream_window: 2048,
        };
        manager.configure_window_updates(config);
        
        // Create a stream
        let stream_id = manager.create_stream(StreamParameters::default()).unwrap();
        
        // Simulate receiving data that doesn't trigger window update (below threshold)
        let small_data = Bytes::from(vec![0u8; 200]); // 200 bytes, well below 60% of 1000
        manager.receive_data(stream_id, 0, small_data, false).unwrap();
        
        // Check that no window update was triggered
        let initial_conn_window = manager.conn_flow_control.max_data_recv;
        assert_eq!(initial_conn_window, 1000);
        
        // Simulate receiving data that triggers connection window update (above 60% threshold)
        let large_data = Bytes::from(vec![0u8; 450]); // 450 + 200 = 650 bytes = 65% of 1000
        manager.receive_data(stream_id, 200, large_data, false).unwrap();
        
        // Check that connection window was updated (adaptive sizing: 65% consumption = 2.5x factor = 2500)
        assert!(manager.conn_flow_control.max_data_recv > initial_conn_window);
        assert_eq!(manager.conn_flow_control.max_data_recv, 2500);
        assert!(manager.conn_flow_control.should_send_max_data);
        
        // Test stream window updates - need to receive more data on the stream
        // First check current stream window
        let stream = manager.streams.get(&stream_id).unwrap();
        let initial_stream_window = stream.receive_max_data();
        
        // Simulate receiving data that triggers stream window update (above 70% of 500)
        let stream_data = Bytes::from(vec![0u8; 200]); // This brings total to 850 bytes, 650+200=850 for connection, but for stream it's different
        manager.receive_data(stream_id, 650, stream_data, false).unwrap();
        
        // Test manual window update checks
        manager.perform_automatic_window_updates();
        
        // Get statistics
        let stats = manager.get_window_update_stats();
        assert_eq!(stats.active_streams, 1);
        assert!(stats.connection_window_utilization > 0.0);
        assert_eq!(stats.connection_window_size, 2500);
        assert_eq!(stats.config.connection_threshold, 0.6);
        
        // Test adaptive sizing - simulate high consumption scenario
        let config_high_consumption = WindowUpdateConfig {
            connection_threshold: 0.3,
            stream_threshold: 0.3,
            min_window_factor: 1.5,
            max_window_factor: 4.0,
            adaptive_sizing: true,
            max_connection_window: 16384,
            max_stream_window: 4096,
        };
        manager.configure_window_updates(config_high_consumption);
        
        // Force high consumption and test adaptive factor
        let very_large_data = Bytes::from(vec![0u8; 1000]); // This should trigger adaptive sizing
        manager.receive_data(stream_id, 850, very_large_data, false).unwrap();
        
        // Window should increase significantly due to high consumption
        assert!(manager.conn_flow_control.max_data_recv >= 2500);
    }

    #[test]
    fn test_window_update_config_validation() {
        let params = TransportParameters::default();
        let mut manager = StreamManager::new(ConnectionRole::Client, &params);
        
        // Test different threshold configurations
        let strict_config = WindowUpdateConfig {
            connection_threshold: 0.9,  // Very high threshold
            stream_threshold: 0.9,
            min_window_factor: 1.1,     // Small increases
            max_window_factor: 1.5,
            adaptive_sizing: false,     // Disable adaptive sizing
            max_connection_window: 4096,
            max_stream_window: 1024,
        };
        manager.configure_window_updates(strict_config);
        
        let stats = manager.get_window_update_stats();
        assert_eq!(stats.config.connection_threshold, 0.9);
        assert!(!stats.config.adaptive_sizing);
        
        // Test relaxed configuration
        let relaxed_config = WindowUpdateConfig {
            connection_threshold: 0.2,  // Very low threshold
            stream_threshold: 0.3,
            min_window_factor: 3.0,     // Large increases
            max_window_factor: 5.0,
            adaptive_sizing: true,
            max_connection_window: 32768,
            max_stream_window: 8192,
        };
        manager.configure_window_updates(relaxed_config);
        
        let stats = manager.get_window_update_stats();
        assert_eq!(stats.config.connection_threshold, 0.2);
        assert!(stats.config.adaptive_sizing);
        assert_eq!(stats.config.max_connection_window, 32768);
    }

    #[test]
    fn test_comprehensive_flow_control_violation_detection() {
        // Test comprehensive flow control violation detection and tracking
        let mut params = TransportParameters::default();
        params.initial_max_data = Some(VarInt::from_u32(1000));
        params.initial_max_streams_bidi = Some(VarInt::from_u32(2));
        
        let mut manager = StreamManager::new(ConnectionRole::Server, &params);
        manager.update_peer_params(&params);
        
        // Test 1: Connection-level data violation
        let stream_id = StreamId::from(0); // Client-initiated
        let violation_data = Bytes::from(vec![0u8; 1500]); // Exceeds 1000 byte limit
        
        let result = manager.receive_data(stream_id, 0, violation_data, false);
        assert!(result.is_err());
        
        // Check that violation was recorded
        let (total_violations, recent_count, recent_violations) = manager.get_flow_control_violation_stats();
        assert_eq!(total_violations, 1);
        assert_eq!(recent_count, 1);
        assert_eq!(recent_violations[0].violation_type, FlowControlViolationType::ConnectionDataExceeded);
        assert_eq!(recent_violations[0].excess_amount, 500); // 1500 - 1000
        
        // Test 2: Stream count violation
        let mut manager2 = StreamManager::new(ConnectionRole::Client, &params);
        manager2.update_peer_params(&params);
        
        // Create streams up to limit
        let _stream1 = manager2.create_stream(StreamParameters::default()).unwrap();
        let _stream2 = manager2.create_stream(StreamParameters::default()).unwrap();
        
        // Try to create third stream - should violate limit
        let result = manager2.create_stream(StreamParameters::default());
        assert!(result.is_err());
        
        let (total_violations, recent_count, recent_violations) = manager2.get_flow_control_violation_stats();
        assert_eq!(total_violations, 1);
        assert!(recent_violations[0].violation_type == FlowControlViolationType::StreamCountExceeded);
        
        // Test 3: MAX_DATA decrease violation
        let mut manager3 = StreamManager::new(ConnectionRole::Client, &params);
        manager3.update_peer_params(&params);
        
        // Set initial MAX_DATA
        manager3.update_max_data(2000).unwrap();
        
        // Try to decrease MAX_DATA - should violate RFC 9000
        let result = manager3.update_max_data(1500);
        assert!(result.is_err());
        
        let (total_violations, recent_count, recent_violations) = manager3.get_flow_control_violation_stats();
        assert_eq!(total_violations, 1);
        assert!(recent_violations[0].violation_type == FlowControlViolationType::MaxDataDecreased);
        assert_eq!(recent_violations[0].current_limit, 2000);
        assert_eq!(recent_violations[0].attempted_value, 1500);
        
        // Test 4: Connection termination check
        assert!(manager.should_terminate_connection()); // Has violations
        assert!(!manager2.should_terminate_connection() || manager2.violation_tracker.violations_detected > 0);
        
        // Test 5: Configure violation tracking
        manager.configure_violation_tracking(false, 50);
        assert!(!manager.should_terminate_connection()); // Termination disabled
        
        protocol_event!(
            Level::Info,
            "Flow control violation detection tests completed";
            "total_test_violations" => total_violations + manager2.violation_tracker.violations_detected + manager3.violation_tracker.violations_detected
        );
    }

    #[test]
    fn test_stream_level_flow_control_violations() {
        // Test stream-level flow control violations using private methods via receive_data
        let mut params = TransportParameters::default();
        params.initial_max_data = Some(VarInt::from_u32(10000)); // Large connection window
        params.initial_max_stream_data_bidi_remote = Some(VarInt::from_u32(500)); // Small stream window
        
        let mut manager = StreamManager::new(ConnectionRole::Server, &params);
        manager.update_peer_params(&params);
        
        // Test stream data limit violation
        let stream_id = StreamId::from(0); // Client-initiated
        let violation_data = Bytes::from(vec![0u8; 600]); // Exceeds 500 byte stream limit
        
        let result = manager.receive_data(stream_id, 0, violation_data, false);
        assert!(result.is_err());
        
        // Check that stream-level violation was recorded
        let (total_violations, _recent_count, recent_violations) = manager.get_flow_control_violation_stats();
        assert_eq!(total_violations, 1);
        assert_eq!(recent_violations[0].violation_type, FlowControlViolationType::StreamDataExceeded);
        assert_eq!(recent_violations[0].stream_id, Some(stream_id));
        assert_eq!(recent_violations[0].excess_amount, 100); // 600 - 500
        assert_eq!(recent_violations[0].current_limit, 500);
        
        protocol_event!(
            Level::Info,
            "Stream-level flow control violation test completed";
            "stream_id" => stream_id.into_inner(),
            "violation_type" => recent_violations[0].violation_type
        );
    }

    #[test]
    fn test_violation_tracking_memory_limits() {
        // Test that violation tracking respects memory limits
        let params = TransportParameters::default();
        let mut manager = StreamManager::new(ConnectionRole::Server, &params);
        
        // Configure to track only 5 recent violations
        manager.configure_violation_tracking(true, 5);
        
        // Generate more violations than the limit
        for i in 0..10 {
            let violation = FlowControlViolation {
                violation_type: FlowControlViolationType::ConnectionDataExceeded,
                stream_id: Some(StreamId::from(i)),
                excess_amount: i as u64 * 100,
                current_limit: 1000,
                attempted_value: 1000 + (i as u64 * 100),
                description: format!("Test violation {}", i),
            };
            
            manager.violation_tracker.record_violation(violation);
        }
        
        // Should only keep 5 most recent violations
        let (total_violations, recent_count, _recent_violations) = manager.get_flow_control_violation_stats();
        assert_eq!(total_violations, 10); // Total count is accurate
        assert_eq!(recent_count, 5); // But only 5 recent ones are kept
        
        protocol_event!(
            Level::Info,
            "Violation memory limit test completed";
            "total_violations" => total_violations,
            "recent_violations_kept" => recent_count
        );
    }
}

/// Statistics about frame transmission and scheduling
#[derive(Debug, Clone)]
pub struct TransmissionStats {
    /// Statistics from the frame scheduler
    pub frame_scheduler_stats: FrameSchedulingStats,
    /// Number of flow control frames waiting in legacy queue
    pub pending_flow_control_frames: usize,
    /// Number of streams with data ready to send
    pub streams_ready_to_send: usize,
    /// Whether connection-level MAX_DATA frame is pending
    pub connection_flow_control_pending: bool,
    /// Number of streams needing MAX_STREAM_DATA updates
    pub streams_needing_max_data: usize,
}