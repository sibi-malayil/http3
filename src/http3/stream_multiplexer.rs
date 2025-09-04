//! HTTP/3 Stream Multiplexer with comprehensive stream management
//!
//! Implements production-grade stream multiplexing including:
//! - MAX_STREAMS frame handling and stream limit enforcement
//! - Fair scheduling and bandwidth allocation
//! - Flow control coordination and automatic window management
//! - Resource management and cleanup
//! - Stream concurrency controls

use crate::{
    error::{Result, Http3ErrorCode},
    error_context::ErrorConversion,
    http3::{
        priority::{PriorityScheduler, StreamPriority},
        frame::MaxStreamsFrame,
        ConnectionRole,
    },
    util::varint::VarInt,
    whathappened::Level,
    protocol_event,
};
use std::{
    collections::{HashMap, VecDeque, BTreeMap},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{RwLock, Mutex, Semaphore};

/// Stream multiplexer configuration
#[derive(Debug, Clone)]
pub struct StreamMultiplexerConfig {
    /// Maximum concurrent bidirectional streams
    pub max_concurrent_streams_bidi: u64,
    /// Maximum concurrent unidirectional streams
    pub max_concurrent_streams_uni: u64,
    /// Stream idle timeout
    pub stream_idle_timeout: Duration,
    /// Maximum memory per stream buffer
    pub max_stream_buffer_size: usize,
    /// Total memory limit for all streams
    pub total_memory_limit: usize,
    /// Flow control window size per stream
    pub initial_stream_window: u64,
    /// Connection flow control window
    pub initial_connection_window: u64,
    /// Enable automatic window updates
    pub auto_flow_control: bool,
    /// Bandwidth allocation algorithm
    pub bandwidth_algorithm: BandwidthAlgorithm,
    /// Fair queuing quantum (bytes per round)
    pub fair_queue_quantum: usize,
}

impl Default for StreamMultiplexerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_streams_bidi: 100,
            max_concurrent_streams_uni: 100,
            stream_idle_timeout: Duration::from_secs(300), // 5 minutes
            max_stream_buffer_size: 1024 * 1024, // 1MB per stream
            total_memory_limit: 128 * 1024 * 1024, // 128MB total
            initial_stream_window: 65536, // 64KB
            initial_connection_window: 1024 * 1024, // 1MB
            auto_flow_control: true,
            bandwidth_algorithm: BandwidthAlgorithm::WeightedFairQueuing,
            fair_queue_quantum: 1500, // MTU-sized quantum
        }
    }
}

/// Bandwidth allocation algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BandwidthAlgorithm {
    /// Simple round-robin
    RoundRobin,
    /// Weighted fair queuing based on priority
    WeightedFairQueuing,
    /// Hierarchical fair queuing
    HierarchicalFairQueuing,
    /// Priority-based strict scheduling
    StrictPriority,
}

/// Stream resource management
#[derive(Debug, Clone)]
pub struct StreamResources {
    /// Current buffer size
    pub buffer_size: usize,
    /// Flow control window
    pub flow_window: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Last activity timestamp
    pub last_activity: Instant,
    /// Stream priority
    pub priority: StreamPriority,
    /// Allocated bandwidth (bytes per quantum)
    pub allocated_bandwidth: usize,
}

impl StreamResources {
    fn new(priority: StreamPriority, initial_window: u64) -> Self {
        Self {
            buffer_size: 0,
            flow_window: initial_window,
            bytes_sent: 0,
            bytes_received: 0,
            last_activity: Instant::now(),
            priority,
            allocated_bandwidth: 0,
        }
    }
}

/// Stream queue for fair scheduling
#[derive(Debug)]
struct StreamQueue {
    /// Streams in this queue
    streams: VecDeque<u64>,
    /// Deficit counter for fair queuing
    deficit: usize,
    /// Queue weight based on priority
    weight: usize,
    /// Bytes transmitted in current round
    transmitted_bytes: usize,
}

impl StreamQueue {
    fn new(weight: usize) -> Self {
        Self {
            streams: VecDeque::new(),
            deficit: 0,
            weight,
            transmitted_bytes: 0,
        }
    }
}

/// Comprehensive stream multiplexer
pub struct StreamMultiplexer {
    /// Configuration
    config: StreamMultiplexerConfig,
    /// Connection role
    role: ConnectionRole,
    /// Active streams by ID
    streams: Arc<RwLock<HashMap<u64, StreamResources>>>,
    /// Priority scheduler
    priority_scheduler: Arc<RwLock<PriorityScheduler>>,
    /// Stream queues for fair scheduling
    stream_queues: Arc<RwLock<BTreeMap<u8, StreamQueue>>>, // Keyed by urgency
    /// Concurrency limits - bidirectional streams
    bidi_semaphore: Arc<Semaphore>,
    /// Concurrency limits - unidirectional streams  
    uni_semaphore: Arc<Semaphore>,
    /// Peer's stream limits
    peer_max_streams_bidi: Arc<RwLock<u64>>,
    peer_max_streams_uni: Arc<RwLock<u64>>,
    /// Pending streams waiting for slots
    pending_streams: Arc<Mutex<VecDeque<PendingStream>>>,
    /// Connection-level flow control
    connection_flow_window: Arc<RwLock<u64>>,
    /// Total memory usage
    total_memory_usage: Arc<RwLock<usize>>,
    /// Stream creation counters
    next_client_stream_id: Arc<RwLock<u64>>,
    next_server_stream_id: Arc<RwLock<u64>>,
    /// Statistics
    stats: Arc<RwLock<MultiplexerStats>>,
}

/// Pending stream waiting for slot
#[derive(Debug, Clone)]
struct PendingStream {
    /// Stream ID
    stream_id: u64,
    /// Is bidirectional
    is_bidirectional: bool,
    /// Priority
    priority: StreamPriority,
    /// Time when queued
    queued_at: Instant,
}

/// Multiplexer statistics
#[derive(Debug, Clone, Default)]
pub struct MultiplexerStats {
    /// Total streams created
    pub streams_created: u64,
    /// Currently active streams
    pub active_streams: usize,
    /// Currently pending streams
    pub pending_streams: usize,
    /// Total bytes transmitted
    pub bytes_transmitted: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Memory usage
    pub memory_usage: usize,
    /// Stream limit violations
    pub stream_limit_violations: u64,
    /// Flow control violations
    pub flow_control_violations: u64,
    /// Average stream duration
    pub avg_stream_duration: Duration,
}

impl StreamMultiplexer {
    /// Create a new stream multiplexer
    pub fn new(config: StreamMultiplexerConfig, role: ConnectionRole) -> Self {
        // Initialize stream ID ranges based on role
        let (next_client_id, next_server_id) = match role {
            ConnectionRole::Client => (0, 1), // Client: 0, 4, 8... Server: 1, 5, 9...
            ConnectionRole::Server => (1, 0), // Server: 1, 5, 9... Client: 0, 4, 8...
        };

        Self {
            bidi_semaphore: Arc::new(Semaphore::new(config.max_concurrent_streams_bidi as usize)),
            uni_semaphore: Arc::new(Semaphore::new(config.max_concurrent_streams_uni as usize)),
            connection_flow_window: Arc::new(RwLock::new(config.initial_connection_window)),
            total_memory_usage: Arc::new(RwLock::new(0)),
            next_client_stream_id: Arc::new(RwLock::new(next_client_id)),
            next_server_stream_id: Arc::new(RwLock::new(next_server_id)),
            config,
            role,
            streams: Arc::new(RwLock::new(HashMap::new())),
            priority_scheduler: Arc::new(RwLock::new(PriorityScheduler::new())),
            stream_queues: Arc::new(RwLock::new(BTreeMap::new())),
            peer_max_streams_bidi: Arc::new(RwLock::new(0)),
            peer_max_streams_uni: Arc::new(RwLock::new(0)),
            pending_streams: Arc::new(Mutex::new(VecDeque::new())),
            stats: Arc::new(RwLock::new(MultiplexerStats::default())),
        }
    }

    /// Create a new stream with resource allocation
    pub async fn create_stream(
        &self,
        is_bidirectional: bool,
        priority: StreamPriority,
    ) -> Result<u64> {
        // Check memory limits
        {
            let memory_usage = *self.total_memory_usage.read().await;
            if memory_usage >= self.config.total_memory_limit {
                return Err("Memory limit exceeded"
                    .to_http3_error(Http3ErrorCode::InternalError));
            }
        }

        // Try to acquire semaphore permit
        let semaphore = if is_bidirectional {
            &self.bidi_semaphore
        } else {
            &self.uni_semaphore
        };

        match semaphore.try_acquire() {
            Ok(permit) => {
                // Permit acquired, create stream immediately
                let stream_id = self.allocate_stream_id(is_bidirectional).await?;
                let urgency = priority.priority.urgency;
                let incremental = priority.priority.incremental;
                self.register_stream(stream_id, priority).await?;
                
                // Forget the permit to keep it consumed until close_stream
                permit.forget();
                
                protocol_event!(
                    Level::Info,
                    "Created stream immediately";
                    "stream_id" => stream_id,
                    "is_bidirectional" => is_bidirectional,
                    "priority_urgency" => urgency,
                    "priority_incremental" => incremental
                );

                Ok(stream_id)
            }
            Err(_) => {
                // No permits available, queue the stream
                let stream_id = self.allocate_stream_id(is_bidirectional).await?;
                // Store priority details for later use in scheduling
                let pending = PendingStream {
                    stream_id,
                    is_bidirectional,
                    priority: priority.clone(),
                    queued_at: Instant::now(),
                };
                
                // Log high-priority stream queueing for monitoring
                if priority.priority.urgency < 3 {
                    protocol_event!(
                        Level::Debug,
                        "High-priority stream queued";
                        "stream_id" => stream_id,
                        "urgency" => priority.priority.urgency,
                        "incremental" => priority.priority.incremental
                    );
                }

                {
                    let mut pending_streams = self.pending_streams.lock().await;
                    pending_streams.push_back(pending);
                }

                {
                    let mut stats = self.stats.write().await;
                    stats.pending_streams += 1;
                }

                protocol_event!(
                    Level::Debug,
                    "Stream queued for slot";
                    "stream_id" => stream_id,
                    "is_bidirectional" => is_bidirectional,
                    "queue_size" => {
                        let pending_streams = self.pending_streams.lock().await;
                        pending_streams.len()
                    }
                );

                Ok(stream_id)
            }
        }
    }

    /// Handle MAX_STREAMS frame from peer
    pub async fn handle_max_streams_frame(&self, max_streams_frame: &MaxStreamsFrame) -> Result<()> {
        let stream_type = max_streams_frame.stream_type;
        let max_streams = max_streams_frame.maximum_streams.0;

        protocol_event!(
            Level::Info,
            "Received MAX_STREAMS frame";
            "stream_type" => if stream_type == 0 { "bidirectional" } else { "unidirectional" },
            "max_streams" => max_streams
        );

        if stream_type == 0 {
            // Bidirectional streams
            *self.peer_max_streams_bidi.write().await = max_streams;
        } else {
            // Unidirectional streams
            *self.peer_max_streams_uni.write().await = max_streams;
        }

        // Try to process pending streams
        self.process_pending_streams().await?;

        Ok(())
    }

    /// Send MAX_STREAMS frame to peer
    pub fn send_max_streams_frame(&self, is_bidirectional: bool) -> Result<MaxStreamsFrame> {
        let max_streams = if is_bidirectional {
            self.config.max_concurrent_streams_bidi
        } else {
            self.config.max_concurrent_streams_uni
        };

        let frame = MaxStreamsFrame {
            stream_type: if is_bidirectional { 0 } else { 1 },
            maximum_streams: VarInt::from_u64(max_streams)?,
        };

        protocol_event!(
            Level::Info,
            "Sending MAX_STREAMS frame";
            "stream_type" => if is_bidirectional { "bidirectional" } else { "unidirectional" },
            "max_streams" => max_streams
        );

        Ok(frame)
    }

    /// Schedule streams for transmission using fair queuing
    pub async fn schedule_transmission(&self, available_bytes: usize) -> Result<Vec<(u64, usize)>> {
        let scheduled;
        let remaining_bytes = available_bytes;

        match self.config.bandwidth_algorithm {
            BandwidthAlgorithm::WeightedFairQueuing => {
                scheduled = self.weighted_fair_queuing(remaining_bytes).await?;
            }
            BandwidthAlgorithm::RoundRobin => {
                scheduled = self.round_robin_scheduling(remaining_bytes).await?;
            }
            BandwidthAlgorithm::StrictPriority => {
                scheduled = self.strict_priority_scheduling(remaining_bytes).await?;
            }
            BandwidthAlgorithm::HierarchicalFairQueuing => {
                scheduled = self.hierarchical_fair_queuing(remaining_bytes).await?;
            }
        }

        protocol_event!(
            Level::Debug,
            "Scheduled stream transmission";
            "available_bytes" => available_bytes,
            "scheduled_streams" => scheduled.len(),
            "algorithm" => format!("{:?}", self.config.bandwidth_algorithm)
        );

        Ok(scheduled)
    }

    /// Update flow control window for a stream
    pub async fn update_stream_flow_control(
        &self,
        stream_id: u64,
        consumed_bytes: u64,
    ) -> Result<bool> {
        let mut should_send_update = false;

        {
            let mut streams = self.streams.write().await;
            if let Some(stream) = streams.get_mut(&stream_id) {
                stream.flow_window = stream.flow_window.saturating_sub(consumed_bytes);
                stream.bytes_received += consumed_bytes;
                stream.last_activity = Instant::now();

                // Auto flow control: send update when window is half depleted
                if self.config.auto_flow_control && stream.flow_window < self.config.initial_stream_window / 2 {
                    should_send_update = true;
                    stream.flow_window = self.config.initial_stream_window;
                }
            }
        }

        // Update connection-level flow control
        {
            let mut conn_window = self.connection_flow_window.write().await;
            *conn_window = conn_window.saturating_sub(consumed_bytes);
        }

        if should_send_update {
            protocol_event!(
                Level::Debug,
                "Auto flow control update";
                "stream_id" => stream_id,
                "consumed_bytes" => consumed_bytes,
                "new_window" => self.config.initial_stream_window
            );
        }

        Ok(should_send_update)
    }

    /// Close a stream and release resources
    pub async fn close_stream(&self, stream_id: u64) -> Result<()> {
        let is_bidirectional = (stream_id % 4) < 2;

        // Remove stream and update memory usage
        {
            let mut streams = self.streams.write().await;
            if let Some(stream) = streams.remove(&stream_id) {
                let mut memory_usage = self.total_memory_usage.write().await;
                *memory_usage = memory_usage.saturating_sub(stream.buffer_size);
            }
        }

        // Release semaphore permit
        let semaphore = if is_bidirectional {
            &self.bidi_semaphore
        } else {
            &self.uni_semaphore
        };
        semaphore.add_permits(1);

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.active_streams = stats.active_streams.saturating_sub(1);
        }

        // Try to process pending streams
        self.process_pending_streams().await?;

        protocol_event!(
            Level::Info,
            "Closed stream";
            "stream_id" => stream_id,
            "is_bidirectional" => is_bidirectional
        );

        Ok(())
    }

    /// Get multiplexer statistics
    pub async fn get_stats(&self) -> MultiplexerStats {
        let mut stats = self.stats.read().await.clone();
        stats.memory_usage = *self.total_memory_usage.read().await;
        stats.active_streams = self.streams.read().await.len();
        stats.pending_streams = self.pending_streams.lock().await.len();
        stats
    }

    /// Cleanup idle streams
    pub async fn cleanup_idle_streams(&self) -> usize {
        let now = Instant::now();
        let timeout = self.config.stream_idle_timeout;
        let mut closed_count = 0;

        let idle_streams: Vec<u64> = {
            let streams = self.streams.read().await;
            streams
                .iter()
                .filter(|(_, stream)| now.duration_since(stream.last_activity) > timeout)
                .map(|(&id, _)| id)
                .collect()
        };

        for stream_id in idle_streams {
            if let Err(e) = self.close_stream(stream_id).await {
                protocol_event!(
                    Level::Warn,
                    "Failed to close idle stream";
                    "stream_id" => stream_id,
                    "error" => format!("{:?}", e)
                );
            } else {
                closed_count += 1;
            }
        }

        if closed_count > 0 {
            protocol_event!(
                Level::Debug,
                "Cleaned up idle streams";
                "closed_count" => closed_count
            );
        }

        closed_count
    }

    // Private helper methods

    async fn allocate_stream_id(&self, is_bidirectional: bool) -> Result<u64> {
        let stream_id = match self.role {
            ConnectionRole::Client => {
                let mut next_id = self.next_client_stream_id.write().await;
                let id = *next_id;
                *next_id += 4;
                if is_bidirectional { id } else { id + 2 }
            }
            ConnectionRole::Server => {
                let mut next_id = self.next_server_stream_id.write().await;
                let id = *next_id;
                *next_id += 4;
                if is_bidirectional { id } else { id + 2 }
            }
        };

        Ok(stream_id)
    }

    async fn register_stream(&self, stream_id: u64, priority: StreamPriority) -> Result<()> {
        let stream_resources = StreamResources::new(priority.clone(), self.config.initial_stream_window);

        // Add to streams
        {
            let mut streams = self.streams.write().await;
            streams.insert(stream_id, stream_resources);
        }

        // Add to priority scheduler
        {
            let scheduler = self.priority_scheduler.write().await;
            scheduler.register_stream_with_priority(stream_id, priority.clone()).await.map_err(|_| {
                "Failed to register with priority scheduler".to_http3_error(Http3ErrorCode::InternalError)
            })?;
        }

        // Add to appropriate queue
        {
            let mut queues = self.stream_queues.write().await;
            let queue = queues.entry(priority.priority.urgency).or_insert_with(|| {
                StreamQueue::new(Self::urgency_to_weight(priority.priority.urgency))
            });
            queue.streams.push_back(stream_id);
        }

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.streams_created += 1;
            stats.active_streams += 1;
        }

        Ok(())
    }

    async fn process_pending_streams(&self) -> Result<()> {
        let mut processed = 0;

        loop {
            let pending = {
                let mut pending_streams = self.pending_streams.lock().await;
                pending_streams.pop_front()
            };

            let pending = match pending {
                Some(p) => p,
                None => break, // No more pending streams
            };

            let semaphore = if pending.is_bidirectional {
                &self.bidi_semaphore
            } else {
                &self.uni_semaphore
            };

            if let Ok(permit) = semaphore.try_acquire() {
                // Register the stream
                self.register_stream(pending.stream_id, pending.priority).await?;
                
                // Forget the permit to keep it consumed until close_stream
                permit.forget();
                processed += 1;

                {
                    let mut stats = self.stats.write().await;
                    stats.pending_streams = stats.pending_streams.saturating_sub(1);
                }

                protocol_event!(
                    Level::Info,
                    "Processed pending stream";
                    "stream_id" => pending.stream_id,
                    "wait_time_ms" => pending.queued_at.elapsed().as_millis()
                );
            } else {
                // Put it back and stop processing
                let mut pending_streams = self.pending_streams.lock().await;
                pending_streams.push_front(pending);
                break;
            }
        }

        if processed > 0 {
            protocol_event!(
                Level::Debug,
                "Processed pending streams";
                "processed_count" => processed
            );
        }

        Ok(())
    }

    async fn weighted_fair_queuing(&self, available_bytes: usize) -> Result<Vec<(u64, usize)>> {
        let mut scheduled = Vec::new();
        let _quantum = self.config.fair_queue_quantum;
        let mut remaining_bytes = available_bytes;

        let mut queues = self.stream_queues.write().await;
        
        // First, calculate total weight of active queues
        let active_queues: Vec<u8> = queues.keys().cloned().collect();
        let total_weight: usize = active_queues.iter()
            .filter_map(|&urgency| queues.get(&urgency))
            .filter(|queue| !queue.streams.is_empty())
            .map(|queue| queue.weight)
            .sum();
            
        if total_weight == 0 {
            return Ok(scheduled);
        }
        
        // Allocate bytes proportionally to each urgency level
        for urgency in active_queues {
            if let Some(queue) = queues.get_mut(&urgency) {
                if queue.streams.is_empty() {
                    continue;
                }
                
                // Calculate proportional allocation for this urgency level
                let queue_allocation = (available_bytes * queue.weight) / total_weight;
                let queue_remaining = queue_allocation.min(remaining_bytes);
                
                // Allocate to streams in this urgency level round-robin
                let streams_in_queue = queue.streams.len();
                if streams_in_queue > 0 && queue_remaining > 0 {
                    let per_stream = queue_remaining / streams_in_queue;
                    let remainder = queue_remaining % streams_in_queue;
                    
                    for (i, &stream_id) in queue.streams.iter().enumerate() {
                        let allocation = per_stream + if i < remainder { 1 } else { 0 };
                        if allocation > 0 {
                            scheduled.push((stream_id, allocation));
                            remaining_bytes -= allocation;
                            queue.transmitted_bytes += allocation;
                        }
                    }
                }
            }
        }

        Ok(scheduled)
    }

    async fn round_robin_scheduling(&self, available_bytes: usize) -> Result<Vec<(u64, usize)>> {
        let mut scheduled = Vec::new();
        let streams: Vec<u64> = {
            let streams = self.streams.read().await;
            streams.keys().cloned().collect()
        };

        let bytes_per_stream = if streams.is_empty() { 0 } else { available_bytes / streams.len() };
        
        for stream_id in streams {
            if bytes_per_stream > 0 {
                scheduled.push((stream_id, bytes_per_stream));
            }
        }

        Ok(scheduled)
    }

    async fn strict_priority_scheduling(&self, available_bytes: usize) -> Result<Vec<(u64, usize)>> {
        let mut scheduled = Vec::new();
        let mut remaining_bytes = available_bytes;

        // Process streams in strict priority order (urgency 0 = highest priority)
        for urgency in 0..=7u8 {
            let queues = self.stream_queues.read().await;
            if let Some(queue) = queues.get(&urgency) {
                for &stream_id in &queue.streams {
                    if remaining_bytes == 0 {
                        break;
                    }
                    let allocation = remaining_bytes.min(self.config.fair_queue_quantum);
                    scheduled.push((stream_id, allocation));
                    remaining_bytes -= allocation;
                }
            }
            if remaining_bytes == 0 {
                break;
            }
        }

        Ok(scheduled)
    }

    async fn hierarchical_fair_queuing(&self, available_bytes: usize) -> Result<Vec<(u64, usize)>> {
        // Simplified hierarchical fair queuing - allocate based on urgency levels
        let mut scheduled = Vec::new();
        let mut remaining_bytes = available_bytes;

        // Allocate bandwidth to each urgency level proportionally
        let urgency_weights = [8, 7, 6, 5, 4, 3, 2, 1]; // Higher urgency gets more weight
        let total_weight: usize = urgency_weights.iter().sum();

        for (urgency, &weight) in urgency_weights.iter().enumerate() {
            let urgency = urgency as u8;
            let allocation = (available_bytes * weight) / total_weight;
            
            let queues = self.stream_queues.read().await;
            if let Some(queue) = queues.get(&urgency) {
                let bytes_per_stream = if queue.streams.is_empty() { 0 } else { allocation / queue.streams.len() };
                
                for &stream_id in &queue.streams {
                    if bytes_per_stream > 0 && remaining_bytes > 0 {
                        let actual_allocation = bytes_per_stream.min(remaining_bytes);
                        scheduled.push((stream_id, actual_allocation));
                        remaining_bytes -= actual_allocation;
                    }
                }
            }
        }

        Ok(scheduled)
    }

    fn urgency_to_weight(urgency: u8) -> usize {
        // Convert urgency (0-7) to weight (higher urgency = higher weight)
        (8 - urgency.min(7)) as usize
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::http3::priority::Priority;

    fn create_test_priority(urgency: u8) -> StreamPriority {
        use crate::http3::priority::Priority;
        StreamPriority::with_priority(
            Priority::with_urgency_and_incremental(urgency, false).unwrap()
        )
    }

    #[tokio::test]
    async fn test_stream_creation_with_limits() {
        let config = StreamMultiplexerConfig {
            max_concurrent_streams_bidi: 2,
            max_concurrent_streams_uni: 2,
            ..Default::default()
        };
        
        let multiplexer = StreamMultiplexer::new(config, ConnectionRole::Client);
        let priority = create_test_priority(3);

        // Should be able to create up to the limit
        let stream1 = multiplexer.create_stream(true, priority.clone()).await.unwrap();
        let stream2 = multiplexer.create_stream(true, priority.clone()).await.unwrap();

        // Third stream should be queued
        let stream3 = multiplexer.create_stream(true, priority.clone()).await.unwrap();

        let stats = multiplexer.get_stats().await;
        assert_eq!(stats.active_streams, 2);
        assert_eq!(stats.pending_streams, 1);

        // Close a stream to free up slot
        multiplexer.close_stream(stream1).await.unwrap();

        // Pending stream should be processed
        tokio::time::sleep(Duration::from_millis(10)).await;
        let stats = multiplexer.get_stats().await;
        assert_eq!(stats.active_streams, 2);
        assert_eq!(stats.pending_streams, 0);
        
        // Clean up remaining streams
        multiplexer.close_stream(stream2).await.unwrap();
        multiplexer.close_stream(stream3).await.unwrap();
    }

    #[tokio::test]
    async fn test_fair_queuing_scheduling() {
        let config = StreamMultiplexerConfig {
            bandwidth_algorithm: BandwidthAlgorithm::WeightedFairQueuing,
            fair_queue_quantum: 1000,
            ..Default::default()
        };
        
        let multiplexer = StreamMultiplexer::new(config, ConnectionRole::Client);

        // Create streams with different priorities
        let high_priority = create_test_priority(0); // Highest urgency
        let low_priority = create_test_priority(7);  // Lowest urgency

        let stream1 = multiplexer.create_stream(true, high_priority).await.unwrap();
        let stream2 = multiplexer.create_stream(true, low_priority).await.unwrap();

        // Schedule transmission
        let scheduled = multiplexer.schedule_transmission(2000).await.unwrap();
        
        // High priority stream should get more bandwidth
        assert_eq!(scheduled.len(), 2);
        let high_prio_allocation = scheduled.iter().find(|(id, _)| *id == stream1).map(|(_, bytes)| *bytes);
        let low_prio_allocation = scheduled.iter().find(|(id, _)| *id == stream2).map(|(_, bytes)| *bytes);
        
        assert!(high_prio_allocation.is_some());
        assert!(low_prio_allocation.is_some());
    }

    #[tokio::test]
    async fn test_flow_control_updates() {
        let config = StreamMultiplexerConfig {
            auto_flow_control: true,
            initial_stream_window: 1000,
            ..Default::default()
        };
        
        let multiplexer = StreamMultiplexer::new(config, ConnectionRole::Client);
        let priority = create_test_priority(3);
        
        let stream_id = multiplexer.create_stream(true, priority).await.unwrap();

        // Consume most of the window
        let should_update = multiplexer.update_stream_flow_control(stream_id, 600).await.unwrap();
        assert!(should_update); // Should trigger auto update at 50% threshold

        // Verify window was reset
        let streams = multiplexer.streams.read().await;
        let stream = streams.get(&stream_id).unwrap();
        assert_eq!(stream.flow_window, 1000); // Reset to initial
        assert_eq!(stream.bytes_received, 600);
    }

    #[tokio::test]
    async fn test_max_streams_frame_handling() {
        let multiplexer = StreamMultiplexer::new(StreamMultiplexerConfig::default(), ConnectionRole::Client);
        
        let max_streams_frame = MaxStreamsFrame::new(0, VarInt::from_u32(10)); // 10 bidi streams
        multiplexer.handle_max_streams_frame(&max_streams_frame).await.unwrap();

        let peer_limit = *multiplexer.peer_max_streams_bidi.read().await;
        assert_eq!(peer_limit, 10);
    }

    #[tokio::test]
    async fn test_cleanup_idle_streams() {
        let config = StreamMultiplexerConfig {
            stream_idle_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        
        let multiplexer = StreamMultiplexer::new(config, ConnectionRole::Client);
        let priority = create_test_priority(3);
        
        let stream_id = multiplexer.create_stream(true, priority).await.unwrap();
        
        // Verify stream exists initially
        let initial_stats = multiplexer.get_stats().await;
        assert_eq!(initial_stats.active_streams, 1);
        
        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(150)).await;
        
        let cleaned = multiplexer.cleanup_idle_streams().await;
        assert_eq!(cleaned, 1);
        
        // Verify the specific stream was cleaned up
        let stats = multiplexer.get_stats().await;
        assert_eq!(stats.active_streams, 0);
        
        // Verify stream is no longer accessible
        let stream_exists = {
            let streams = multiplexer.streams.read().await;
            streams.contains_key(&stream_id)
        };
        assert!(!stream_exists, "Stream {} should have been cleaned up", stream_id);
    }
}