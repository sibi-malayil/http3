//! HTTP/3 prioritization implementation (RFC 9297)
//!
//! This module implements HTTP/3 request prioritization using urgency and incremental
//! parameters as defined in RFC 9297. The prioritization system allows clients to
//! express the relative importance and scheduling preferences for their requests.

use crate::{
    error::{Error, Result, Http3ErrorCode},
    util::{varint::VarInt, buffer::{BufExt, BufMutExt}},
    quic::stream::StreamId,
    whathappened::Level,
    protocol_event,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Instant,
};
use tokio::sync::{RwLock, Mutex};

/// Maximum urgency value (RFC 9297 Section 4)
pub const MAX_URGENCY: u8 = 7;

/// Default urgency for new streams
pub const DEFAULT_URGENCY: u8 = 3;

/// PRIORITY_UPDATE frame type (RFC 9297 Section 7.1)
pub const PRIORITY_UPDATE_FRAME_TYPE: u64 = 0x0f;

/// Priority parameters as defined in RFC 9297 Section 4
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Priority {
    /// Urgency parameter (0-7, with 0 being most urgent)
    pub urgency: u8,
    /// Incremental parameter (boolean)
    pub incremental: bool,
}

impl Priority {
    /// Creates a new priority with default values
    pub fn new() -> Self {
        Self {
            urgency: DEFAULT_URGENCY,
            incremental: false,
        }
    }

    /// Creates a new priority with specified values
    pub fn with_urgency_and_incremental(urgency: u8, incremental: bool) -> Result<Self> {
        if urgency > MAX_URGENCY {
            return Err(Error::Http3Error {
                code: Http3ErrorCode::FrameError,
                reason: format!("Invalid urgency value: {} (max: {})", urgency, MAX_URGENCY),
            });
        }

        Ok(Self {
            urgency,
            incremental,
        })
    }

    /// Creates a priority from structured field parameters
    pub fn from_structured_field(params: &str) -> Result<Self> {
        let mut urgency = DEFAULT_URGENCY;
        let mut incremental = false;

        // Parse structured field format: u=3, i
        for param in params.split(',').map(|s| s.trim()) {
            if let Some(eq_pos) = param.find('=') {
                let (key, value) = param.split_at(eq_pos);
                let value = &value[1..]; // Skip '='
                
                match key.trim() {
                    "u" => {
                        urgency = value.parse().map_err(|_| Error::Http3Error {
                            code: Http3ErrorCode::FrameError,
                            reason: format!("Invalid urgency value: {}", value),
                        })?;
                        
                        if urgency > MAX_URGENCY {
                            return Err(Error::Http3Error {
                                code: Http3ErrorCode::FrameError,
                                reason: format!("Urgency {} exceeds maximum {}", urgency, MAX_URGENCY),
                            });
                        }
                    }
                    _ => {
                        // Ignore unknown parameters per RFC 9297
                    }
                }
            } else if param.trim() == "i" {
                incremental = true;
            }
        }

        Ok(Self {
            urgency,
            incremental,
        })
    }

    /// Converts priority to structured field format
    pub fn to_structured_field(&self) -> String {
        if self.incremental {
            format!("u={}, i", self.urgency)
        } else {
            format!("u={}", self.urgency)
        }
    }

    /// Returns the scheduling weight (lower urgency = higher weight)
    pub fn weight(&self) -> u32 {
        // Use exponential scaling for urgency levels
        1u32 << (MAX_URGENCY - self.urgency)
    }

    /// Returns true if this priority has higher precedence than another
    pub fn has_higher_precedence(&self, other: &Priority) -> bool {
        self.urgency < other.urgency
    }
}

impl Default for Priority {
    fn default() -> Self {
        Self::new()
    }
}

/// PRIORITY_UPDATE frame payload (RFC 9297 Section 7.1)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorityUpdateFrame {
    /// Stream ID or Push ID being updated
    pub prioritized_element_id: VarInt,
    /// Priority field value
    pub priority_field_value: Bytes,
}

impl PriorityUpdateFrame {
    /// Creates a new PRIORITY_UPDATE frame
    pub fn new(prioritized_element_id: VarInt, priority_field_value: Bytes) -> Self {
        Self {
            prioritized_element_id,
            priority_field_value,
        }
    }

    /// Creates a PRIORITY_UPDATE frame from a priority
    pub fn from_priority(stream_id: StreamId, priority: &Priority) -> Self {
        let priority_value = priority.to_structured_field();
        Self {
            prioritized_element_id: VarInt::try_from(stream_id.into_inner()).unwrap(),
            priority_field_value: Bytes::from(priority_value),
        }
    }

    /// Encodes the frame
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        buf.put_var(VarInt::try_from(PRIORITY_UPDATE_FRAME_TYPE)?);
        
        let payload_len = VarInt::size(self.prioritized_element_id) + self.priority_field_value.len();
        buf.put_var(VarInt::try_from(payload_len)?);
        buf.put_var(self.prioritized_element_id);
        buf.put(self.priority_field_value.as_ref());
        
        Ok(())
    }

    /// Decodes the frame
    pub fn decode(mut payload: Bytes) -> Result<Self> {
        if payload.remaining() < VarInt::size(VarInt::from_u32(0)) {
            return Err(Error::Http3Error {
                code: Http3ErrorCode::FrameError,
                reason: "Insufficient data for PRIORITY_UPDATE element ID".to_string(),
            });
        }

        let prioritized_element_id = payload.get_var()?;
        let priority_field_value = payload;

        Ok(Self {
            prioritized_element_id,
            priority_field_value,
        })
    }

    /// Extracts priority from the frame
    pub fn to_priority(&self) -> Result<Priority> {
        let priority_str = std::str::from_utf8(&self.priority_field_value)
            .map_err(|_| Error::Http3Error {
                code: Http3ErrorCode::FrameError,
                reason: "Invalid UTF-8 in priority field value".to_string(),
            })?;
        
        Priority::from_structured_field(priority_str)
    }
}

/// Stream priority information with scheduling state
#[derive(Debug, Clone)]
pub struct StreamPriority {
    /// The priority parameters
    pub priority: Priority,
    /// Last update timestamp
    pub last_updated: Instant,
    /// Amount of data sent (for fair queuing within same urgency)
    pub bytes_sent: u64,
    /// Whether the stream is currently active
    pub active: bool,
}

impl StreamPriority {
    /// Creates a new stream priority with default values
    pub fn new() -> Self {
        Self {
            priority: Priority::new(),
            last_updated: Instant::now(),
            bytes_sent: 0,
            active: true,
        }
    }

    /// Creates a new stream priority with specified priority
    pub fn with_priority(priority: Priority) -> Self {
        Self {
            priority,
            last_updated: Instant::now(),
            bytes_sent: 0,
            active: true,
        }
    }

    /// Updates the priority
    pub fn update_priority(&mut self, new_priority: Priority) {
        self.priority = new_priority;
        self.last_updated = Instant::now();
    }

    /// Records bytes sent for fair queuing
    pub fn record_bytes_sent(&mut self, bytes: u64) {
        self.bytes_sent += bytes;
    }

    /// Marks stream as inactive
    pub fn set_inactive(&mut self) {
        self.active = false;
    }
}

impl Default for StreamPriority {
    fn default() -> Self {
        Self::new()
    }
}

/// HTTP/3 priority scheduler implementing RFC 9297
pub struct PriorityScheduler {
    /// Stream priorities indexed by stream ID
    stream_priorities: Arc<RwLock<HashMap<u64, StreamPriority>>>,
    /// Urgency-based queues (0 = highest urgency, 7 = lowest urgency)
    urgency_queues: Arc<Mutex<[VecDeque<u64>; 8]>>,
    /// Round-robin state for fair queuing within urgency levels
    round_robin_state: Arc<Mutex<HashMap<usize, usize>>>,
    /// Default priority for new streams
    default_priority: Priority,
}

impl PriorityScheduler {
    /// Creates a new priority scheduler
    pub fn new() -> Self {
        Self {
            stream_priorities: Arc::new(RwLock::new(HashMap::new())),
            urgency_queues: Arc::new(Mutex::new([
                VecDeque::new(), VecDeque::new(), VecDeque::new(), VecDeque::new(),
                VecDeque::new(), VecDeque::new(), VecDeque::new(), VecDeque::new(),
            ])),
            round_robin_state: Arc::new(Mutex::new(HashMap::new())),
            default_priority: Priority::new(),
        }
    }

    /// Registers a new stream with default priority
    pub async fn register_stream(&self, stream_id: u64) -> Result<()> {
        let priority = StreamPriority::new();
        self.register_stream_with_priority(stream_id, priority).await
    }

    /// Registers a new stream with specified priority
    pub async fn register_stream_with_priority(&self, stream_id: u64, priority: StreamPriority) -> Result<()> {
        let urgency = priority.priority.urgency;
        
        // Add to stream priorities
        {
            let mut priorities = self.stream_priorities.write().await;
            priorities.insert(stream_id, priority);
        }

        // Add to appropriate urgency queue
        {
            let mut queues = self.urgency_queues.lock().await;
            queues[urgency as usize].push_back(stream_id);
        }

        protocol_event!(
            Level::Debug,
            "Stream registered with priority";
            "stream_id" => stream_id,
            "urgency" => urgency
        );

        Ok(())
    }

    /// Updates stream priority
    pub async fn update_stream_priority(&self, stream_id: u64, new_priority: Priority) -> Result<()> {
        let old_urgency = {
            let mut priorities = self.stream_priorities.write().await;
            if let Some(stream_priority) = priorities.get_mut(&stream_id) {
                let old_urgency = stream_priority.priority.urgency;
                stream_priority.update_priority(new_priority.clone());
                old_urgency
            } else {
                // Stream not found, register it
                let priority = StreamPriority::with_priority(new_priority.clone());
                priorities.insert(stream_id, priority);
                return self.add_to_urgency_queue(stream_id, new_priority.urgency).await;
            }
        };

        // Move stream between urgency queues if needed
        if old_urgency != new_priority.urgency {
            self.move_between_urgency_queues(stream_id, old_urgency, new_priority.urgency).await?;
        }

        protocol_event!(
            Level::Debug,
            "Stream priority updated";
            "stream_id" => stream_id,
            "old_urgency" => old_urgency,
            "new_urgency" => new_priority.urgency,
            "incremental" => new_priority.incremental
        );

        Ok(())
    }

    /// Handles PRIORITY_UPDATE frame
    pub async fn handle_priority_update(&self, frame: PriorityUpdateFrame) -> Result<()> {
        let stream_id = frame.prioritized_element_id.into_inner();
        let priority = frame.to_priority()?;
        
        self.update_stream_priority(stream_id, priority).await
    }

    /// Schedules the next stream to send data
    pub async fn schedule_next_stream(&self) -> Option<u64> {
        let mut queues = self.urgency_queues.lock().await;
        let mut round_robin = self.round_robin_state.lock().await;
        
        // Check urgency levels from 0 (highest) to 7 (lowest)
        for urgency in 0..=7 {
            let queue = &mut queues[urgency];
            if queue.is_empty() {
                continue;
            }

            // Use round-robin within the urgency level
            let start_pos = round_robin.get(&{ urgency }).copied().unwrap_or(0);
            let mut current_pos = start_pos;
            
            loop {
                if current_pos >= queue.len() {
                    current_pos = 0;
                }
                
                if let Some(&stream_id) = queue.get(current_pos) {
                    // Check if stream is still active
                    let is_active = {
                        let priorities = self.stream_priorities.read().await;
                        priorities.get(&stream_id)
                            .map(|p| p.active)
                            .unwrap_or(false)
                    };
                    
                    if is_active {
                        // Update round-robin state
                        round_robin.insert(urgency, (current_pos + 1) % queue.len());
                        
                        protocol_event!(
                            Level::Trace,
                            "Stream scheduled";
                            "stream_id" => stream_id,
                            "urgency" => urgency
                        );
                        
                        return Some(stream_id);
                    } else {
                        // Remove inactive stream
                        queue.remove(current_pos);
                        if queue.is_empty() {
                            break;
                        }
                        continue;
                    }
                }
                
                current_pos = (current_pos + 1) % queue.len();
                if current_pos == start_pos {
                    break; // Checked all streams in this urgency level
                }
            }
        }
        
        None
    }

    /// Records bytes sent for a stream (for fair queuing)
    pub async fn record_bytes_sent(&self, stream_id: u64, bytes: u64) {
        let mut priorities = self.stream_priorities.write().await;
        if let Some(priority) = priorities.get_mut(&stream_id) {
            priority.record_bytes_sent(bytes);
        }
    }

    /// Removes a stream from the scheduler
    pub async fn remove_stream(&self, stream_id: u64) -> Result<()> {
        // Remove from stream priorities
        let old_urgency = {
            let mut priorities = self.stream_priorities.write().await;
            priorities.remove(&stream_id)
                .map(|p| p.priority.urgency)
        };

        // Remove from urgency queue
        if let Some(urgency) = old_urgency {
            let mut queues = self.urgency_queues.lock().await;
            let queue = &mut queues[urgency as usize];
            if let Some(pos) = queue.iter().position(|&id| id == stream_id) {
                queue.remove(pos);
            }
        }

        protocol_event!(
            Level::Debug,
            "Stream removed from scheduler";
            "stream_id" => stream_id
        );

        Ok(())
    }

    /// Marks a stream as inactive
    pub async fn mark_stream_inactive(&self, stream_id: u64) {
        let mut priorities = self.stream_priorities.write().await;
        if let Some(priority) = priorities.get_mut(&stream_id) {
            priority.set_inactive();
        }
    }

    /// Gets the priority for a stream
    pub async fn get_stream_priority(&self, stream_id: u64) -> Option<Priority> {
        let priorities = self.stream_priorities.read().await;
        priorities.get(&stream_id).map(|p| p.priority.clone())
    }

    /// Gets scheduler statistics
    pub async fn get_stats(&self) -> SchedulerStats {
        let priorities = self.stream_priorities.read().await;
        let queues = self.urgency_queues.lock().await;
        
        let total_streams = priorities.len();
        let active_streams = priorities.values().filter(|p| p.active).count();
        let mut urgency_counts = [0; 8];
        
        for queue in queues.iter() {
            urgency_counts[0] += queue.len(); // Simplified for example
        }

        SchedulerStats {
            total_streams,
            active_streams,
            urgency_distribution: urgency_counts,
        }
    }

    /// Adds stream to urgency queue
    async fn add_to_urgency_queue(&self, stream_id: u64, urgency: u8) -> Result<()> {
        let mut queues = self.urgency_queues.lock().await;
        queues[urgency as usize].push_back(stream_id);
        Ok(())
    }

    /// Moves stream between urgency queues
    async fn move_between_urgency_queues(&self, stream_id: u64, old_urgency: u8, new_urgency: u8) -> Result<()> {
        let mut queues = self.urgency_queues.lock().await;
        
        // Remove from old queue
        let old_queue = &mut queues[old_urgency as usize];
        if let Some(pos) = old_queue.iter().position(|&id| id == stream_id) {
            old_queue.remove(pos);
        }
        
        // Add to new queue
        queues[new_urgency as usize].push_back(stream_id);
        
        Ok(())
    }
}

impl Default for PriorityScheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// Scheduler statistics
#[derive(Debug, Clone)]
pub struct SchedulerStats {
    /// Total number of streams
    pub total_streams: usize,
    /// Number of active streams
    pub active_streams: usize,
    /// Distribution of streams across urgency levels
    pub urgency_distribution: [usize; 8],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_creation() {
        let priority = Priority::new();
        assert_eq!(priority.urgency, DEFAULT_URGENCY);
        assert!(!priority.incremental);

        let priority = Priority::with_urgency_and_incremental(1, true).unwrap();
        assert_eq!(priority.urgency, 1);
        assert!(priority.incremental);

        assert!(Priority::with_urgency_and_incremental(8, false).is_err());
    }

    #[test]
    fn test_priority_structured_field() {
        let priority = Priority::from_structured_field("u=2, i").unwrap();
        assert_eq!(priority.urgency, 2);
        assert!(priority.incremental);

        let priority = Priority::from_structured_field("u=5").unwrap();
        assert_eq!(priority.urgency, 5);
        assert!(!priority.incremental);

        let field = priority.to_structured_field();
        assert_eq!(field, "u=5");

        let priority = Priority::with_urgency_and_incremental(3, true).unwrap();
        let field = priority.to_structured_field();
        assert_eq!(field, "u=3, i");
    }

    #[test]
    fn test_priority_update_frame() {
        let priority = Priority::with_urgency_and_incremental(2, true).unwrap();
        let stream_id = StreamId::try_from(4).unwrap();
        let frame = PriorityUpdateFrame::from_priority(stream_id, &priority);
        
        assert_eq!(frame.prioritized_element_id.into_inner(), 4);
        
        let decoded_priority = frame.to_priority().unwrap();
        assert_eq!(decoded_priority, priority);
    }

    #[test]
    fn test_priority_frame_encoding() {
        let frame = PriorityUpdateFrame::new(
            VarInt::from_u32(8),
            Bytes::from("u=1, i"),
        );
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        
        assert!(!buf.is_empty());
        
        // Skip frame type and length for decoding
        let mut decode_buf = buf.clone();
        let _frame_type = decode_buf.get_var().unwrap();
        let _length = decode_buf.get_var().unwrap();
        
        let decoded = PriorityUpdateFrame::decode(decode_buf.freeze()).unwrap();
        assert_eq!(decoded.prioritized_element_id.into_inner(), 8);
        assert_eq!(decoded.priority_field_value, Bytes::from("u=1, i"));
    }

    #[tokio::test]
    async fn test_priority_scheduler() {
        let scheduler = PriorityScheduler::new();
        
        // Register streams with different priorities
        let priority1 = StreamPriority::with_priority(
            Priority::with_urgency_and_incremental(0, false).unwrap()
        );
        let priority2 = StreamPriority::with_priority(
            Priority::with_urgency_and_incremental(3, false).unwrap()
        );
        
        scheduler.register_stream_with_priority(1, priority1).await.unwrap();
        scheduler.register_stream_with_priority(2, priority2).await.unwrap();
        
        // Higher urgency stream should be scheduled first
        let next_stream = scheduler.schedule_next_stream().await;
        assert_eq!(next_stream, Some(1)); // urgency 0 has higher priority than urgency 3
        
        // Update priority
        let new_priority = Priority::with_urgency_and_incremental(7, true).unwrap();
        scheduler.update_stream_priority(1, new_priority).await.unwrap();
        
        let next_stream = scheduler.schedule_next_stream().await;
        assert_eq!(next_stream, Some(2)); // Now stream 2 has higher priority
    }

    #[test]
    fn test_priority_precedence() {
        let high_priority = Priority::with_urgency_and_incremental(0, false).unwrap();
        let low_priority = Priority::with_urgency_and_incremental(7, false).unwrap();
        
        assert!(high_priority.has_higher_precedence(&low_priority));
        assert!(!low_priority.has_higher_precedence(&high_priority));
        
        assert_eq!(high_priority.weight(), 128); // 2^(7-0)
        assert_eq!(low_priority.weight(), 1);    // 2^(7-7)
    }
}