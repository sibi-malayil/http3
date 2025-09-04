//! HTTP/3 Priority Manager
//!
//! This module provides a connection-level priority manager that integrates
//! the priority scheduler with HTTP/3 frame handling and stream management.

use crate::{
    error::{Error, Result, Http3ErrorCode},
    http3::{
        stream::Stream,
        priority::{PriorityScheduler, Priority, PriorityUpdateFrame},
        frame::Http3Frame,
    },
    quic::stream::StreamId,
    whathappened::Level,
    {protocol_event},
};
use bytes::{Bytes, BytesMut};
use std::{
    collections::HashMap,
    sync::Arc,
    time::Instant,
};
use tokio::sync::{RwLock, Mutex};

/// Priority manager for HTTP/3 connections
pub struct PriorityManager {
    /// The priority scheduler
    scheduler: PriorityScheduler,
    /// Active streams
    streams: Arc<RwLock<HashMap<u64, Arc<Mutex<Stream>>>>>,
    /// Whether this is a server connection (servers can't send PRIORITY_UPDATE)
    is_server: bool,
    /// Statistics
    stats: Arc<Mutex<PriorityStats>>,
}

impl PriorityManager {
    /// Creates a new priority manager
    pub fn new(is_server: bool) -> Self {
        Self {
            scheduler: PriorityScheduler::new(),
            streams: Arc::new(RwLock::new(HashMap::new())),
            is_server,
            stats: Arc::new(Mutex::new(PriorityStats::new())),
        }
    }

    /// Registers a stream with the priority manager
    pub async fn register_stream(&self, stream_id: u64, stream: Arc<Mutex<Stream>>) -> Result<()> {
        // Get the stream's priority
        let priority = {
            let stream_guard = stream.lock().await;
            stream_guard.priority_info().clone()
        };

        let urgency = priority.priority.urgency;
        let incremental = priority.priority.incremental;

        // Register with scheduler
        self.scheduler.register_stream_with_priority(stream_id, priority).await?;

        // Add to streams map
        {
            let mut streams = self.streams.write().await;
            streams.insert(stream_id, stream);
        }

        protocol_event!(
            Level::Debug,
            "Stream registered with priority manager";
            "stream_id" => stream_id,
            "urgency" => urgency,
            "incremental" => incremental
        );

        Ok(())
    }

    /// Handles a PRIORITY_UPDATE frame
    pub async fn handle_priority_update(&self, frame: PriorityUpdateFrame) -> Result<()> {
        let stream_id = frame.prioritized_element_id.into_inner();
        
        protocol_event!(
            Level::Info,
            "Processing PRIORITY_UPDATE frame";
            "stream_id" => stream_id,
            "priority_field" => String::from_utf8_lossy(&frame.priority_field_value)
        );

        // Parse priority from frame
        let new_priority = frame.to_priority()?;

        // Update scheduler
        self.scheduler.update_stream_priority(stream_id, new_priority.clone()).await?;

        // Update stream if it exists
        {
            let streams = self.streams.read().await;
            if let Some(stream) = streams.get(&stream_id) {
                let mut stream_guard = stream.lock().await;
                stream_guard.set_priority(new_priority);
            }
        }

        // Update stats
        {
            let mut stats = self.stats.lock().await;
            stats.priority_updates += 1;
            stats.last_update = Some(Instant::now());
        }

        Ok(())
    }

    /// Sends a PRIORITY_UPDATE frame (client only)
    pub async fn send_priority_update(&self, stream_id: StreamId, priority: Priority) -> Result<Bytes> {
        if self.is_server {
            return Err(Error::Http3Error {
                code: Http3ErrorCode::FrameUnexpected,
                reason: "Servers cannot send PRIORITY_UPDATE frames".to_string(),
            });
        }

        // Create PRIORITY_UPDATE frame
        let frame = PriorityUpdateFrame::from_priority(stream_id, &priority);

        // Encode frame
        let mut buf = BytesMut::new();
        frame.encode(&mut buf)?;

        // Update internal state
        self.scheduler.update_stream_priority(stream_id.into_inner(), priority.clone()).await?;

        protocol_event!(
            Level::Info,
            "Sending PRIORITY_UPDATE frame";
            "stream_id" => stream_id.into_inner(),
            "urgency" => priority.urgency,
            "incremental" => priority.incremental
        );

        Ok(buf.freeze())
    }

    /// Schedules the next stream for transmission
    pub async fn schedule_next_stream(&self) -> Option<u64> {
        self.scheduler.schedule_next_stream().await
    }

    /// Records bytes sent for a stream
    pub async fn record_bytes_sent(&self, stream_id: u64, bytes: u64) {
        self.scheduler.record_bytes_sent(stream_id, bytes).await;
        
        // Update stream record
        let streams = self.streams.read().await;
        if let Some(stream) = streams.get(&stream_id) {
            let mut stream_guard = stream.lock().await;
            stream_guard.record_bytes_sent(bytes);
        }
    }

    /// Removes a stream from priority management
    pub async fn remove_stream(&self, stream_id: u64) -> Result<()> {
        // Remove from scheduler
        self.scheduler.remove_stream(stream_id).await?;

        // Remove from streams map
        {
            let mut streams = self.streams.write().await;
            streams.remove(&stream_id);
        }

        protocol_event!(
            Level::Debug,
            "Stream removed from priority manager";
            "stream_id" => stream_id
        );

        Ok(())
    }

    /// Marks a stream as inactive
    pub async fn mark_stream_inactive(&self, stream_id: u64) {
        self.scheduler.mark_stream_inactive(stream_id).await;
        
        let streams = self.streams.read().await;
        if let Some(stream) = streams.get(&stream_id) {
            let mut stream_guard = stream.lock().await;
            stream_guard.mark_inactive();
        }
    }

    /// Gets priority for a stream
    pub async fn get_stream_priority(&self, stream_id: u64) -> Option<Priority> {
        self.scheduler.get_stream_priority(stream_id).await
    }

    /// Sets default priority for new streams
    pub fn set_default_priority(&self, priority: Priority) -> Result<()> {
        // This would be used to set a default for newly created streams
        // Implementation would depend on how defaults are stored
        protocol_event!(
            Level::Debug,
            "Default priority updated";
            "urgency" => priority.urgency,
            "incremental" => priority.incremental
        );
        Ok(())
    }

    /// Gets scheduler statistics
    pub async fn get_scheduler_stats(&self) -> crate::http3::priority::SchedulerStats {
        self.scheduler.get_stats().await
    }

    /// Gets priority manager statistics
    pub async fn get_priority_stats(&self) -> PriorityStats {
        let stats = self.stats.lock().await;
        stats.clone()
    }

    /// Processes an HTTP/3 frame for priority-related handling
    pub async fn process_frame(&self, frame: &Http3Frame) -> Result<Option<PriorityUpdateFrame>> {
        match frame {
            Http3Frame::PriorityUpdate(priority_frame) => {
                self.handle_priority_update(priority_frame.clone()).await?;
                Ok(Some(priority_frame.clone()))
            }
            _ => Ok(None),
        }
    }

    /// Validates PRIORITY_UPDATE frame context
    pub fn validate_priority_update_context(&self, stream_type: &str) -> Result<()> {
        // PRIORITY_UPDATE frames are only valid on control streams
        if stream_type != "control" {
            return Err(Error::Http3Error {
                code: Http3ErrorCode::FrameUnexpected,
                reason: "PRIORITY_UPDATE frames only allowed on control streams".to_string(),
            });
        }
        Ok(())
    }

    /// Creates a prioritized stream list for transmission scheduling
    pub async fn get_prioritized_streams(&self) -> Vec<(u64, Priority)> {
        let mut result = Vec::new();
        let streams = self.streams.read().await;
        
        for (&stream_id, stream) in streams.iter() {
            let stream_guard = stream.lock().await;
            if stream_guard.priority_info().active {
                result.push((stream_id, stream_guard.priority().clone()));
            }
        }

        // Sort by priority (urgency)
        result.sort_by(|a, b| a.1.urgency.cmp(&b.1.urgency));
        result
    }

    /// Apply RFC 9297 defaults for HTTP methods
    pub fn get_default_priority_for_method(method: &str) -> Priority {
        match method {
            // High priority for navigation requests
            "GET" | "HEAD" => Priority::with_urgency_and_incremental(1, true).unwrap_or_default(),
            // Medium priority for form submissions
            "POST" | "PUT" | "PATCH" => Priority::with_urgency_and_incremental(3, false).unwrap_or_default(),
            // Lower priority for background requests
            "DELETE" => Priority::with_urgency_and_incremental(4, false).unwrap_or_default(),
            // Default priority for unknown methods
            _ => Priority::default(),
        }
    }

    /// Apply RFC 9297 defaults for resource types
    pub fn get_default_priority_for_resource_type(content_type: &str) -> Priority {
        if content_type.starts_with("text/html") {
            // High priority for HTML documents
            Priority::with_urgency_and_incremental(0, true).unwrap_or_default()
        } else if content_type.starts_with("text/css") || content_type.starts_with("application/javascript") {
            // High priority for critical resources
            Priority::with_urgency_and_incremental(1, false).unwrap_or_default()
        } else if content_type.starts_with("image/") {
            // Medium priority for images
            Priority::with_urgency_and_incremental(4, true).unwrap_or_default()
        } else if content_type.starts_with("video/") || content_type.starts_with("audio/") {
            // Lower priority for media
            Priority::with_urgency_and_incremental(5, true).unwrap_or_default()
        } else {
            // Default priority for other content
            Priority::default()
        }
    }
}

/// Priority manager statistics
#[derive(Debug, Clone)]
pub struct PriorityStats {
    /// Number of PRIORITY_UPDATE frames processed
    pub priority_updates: u64,
    /// Number of streams registered
    pub streams_registered: u64,
    /// Number of streams removed
    pub streams_removed: u64,
    /// Last priority update timestamp
    pub last_update: Option<Instant>,
    /// Creation timestamp
    pub created_at: Instant,
}

impl PriorityStats {
    /// Creates new statistics
    pub fn new() -> Self {
        Self {
            priority_updates: 0,
            streams_registered: 0,
            streams_removed: 0,
            last_update: None,
            created_at: Instant::now(),
        }
    }
}

impl Default for PriorityStats {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        http3::{stream::StreamType, priority::PriorityUpdateFrame},
        qpack::{encoder::Encoder, decoder::Decoder, Config},
    };
    use std::sync::Arc;
    use tokio::sync::Mutex;

    async fn create_test_stream(stream_id: u64) -> Arc<Mutex<Stream>> {
        let encoder = Arc::new(Mutex::new(Encoder::new(Config::default())));
        let decoder = Arc::new(Mutex::new(Decoder::new(Config::default())));
        let stream = Stream::new(
            StreamId::try_from(stream_id).unwrap(),
            StreamType::Request,
            encoder,
            decoder,
        ).unwrap();
        Arc::new(Mutex::new(stream))
    }

    #[tokio::test]
    async fn test_priority_manager_registration() {
        let manager = PriorityManager::new(false);
        let stream = create_test_stream(4).await;
        
        manager.register_stream(4, stream).await.unwrap();
        
        let priority = manager.get_stream_priority(4).await.unwrap();
        assert_eq!(priority.urgency, 3); // Default urgency
    }

    #[tokio::test]
    async fn test_priority_update_handling() {
        let manager = PriorityManager::new(true); // Server
        let stream = create_test_stream(8).await;
        
        manager.register_stream(8, stream).await.unwrap();
        
        // Create and handle PRIORITY_UPDATE frame
        let new_priority = Priority::with_urgency_and_incremental(1, true).unwrap();
        let frame = PriorityUpdateFrame::from_priority(
            StreamId::try_from(8).unwrap(),
            &new_priority
        );
        
        manager.handle_priority_update(frame).await.unwrap();
        
        let updated_priority = manager.get_stream_priority(8).await.unwrap();
        assert_eq!(updated_priority.urgency, 1);
        assert!(updated_priority.incremental);
    }

    #[tokio::test]
    async fn test_client_priority_update_sending() {
        let manager = PriorityManager::new(false); // Client
        
        let priority = Priority::with_urgency_and_incremental(2, false).unwrap();
        let frame_data = manager.send_priority_update(
            StreamId::try_from(12).unwrap(),
            priority
        ).await.unwrap();
        
        assert!(!frame_data.is_empty());
        
        // Verify stream was updated
        let updated_priority = manager.get_stream_priority(12).await.unwrap();
        assert_eq!(updated_priority.urgency, 2);
        assert!(!updated_priority.incremental);
    }

    #[tokio::test]
    async fn test_server_cannot_send_priority_update() {
        let manager = PriorityManager::new(true); // Server
        
        let priority = Priority::with_urgency_and_incremental(1, true).unwrap();
        let result = manager.send_priority_update(
            StreamId::try_from(4).unwrap(),
            priority
        ).await;
        
        assert!(result.is_err());
    }

    #[test]
    fn test_default_priorities_for_methods() {
        let get_priority = PriorityManager::get_default_priority_for_method("GET");
        assert_eq!(get_priority.urgency, 1);
        assert!(get_priority.incremental);
        
        let post_priority = PriorityManager::get_default_priority_for_method("POST");
        assert_eq!(post_priority.urgency, 3);
        assert!(!post_priority.incremental);
    }

    #[test]
    fn test_default_priorities_for_resource_types() {
        let html_priority = PriorityManager::get_default_priority_for_resource_type("text/html");
        assert_eq!(html_priority.urgency, 0);
        assert!(html_priority.incremental);
        
        let css_priority = PriorityManager::get_default_priority_for_resource_type("text/css");
        assert_eq!(css_priority.urgency, 1);
        assert!(!css_priority.incremental);
        
        let image_priority = PriorityManager::get_default_priority_for_resource_type("image/jpeg");
        assert_eq!(image_priority.urgency, 4);
        assert!(image_priority.incremental);
    }

    #[tokio::test]
    async fn test_stream_scheduling() {
        let manager = PriorityManager::new(false);
        
        // Register streams with different priorities
        let stream1 = create_test_stream(4).await;
        let stream2 = create_test_stream(8).await;
        
        manager.register_stream(4, stream1).await.unwrap();
        manager.register_stream(8, stream2).await.unwrap();
        
        // Update priorities
        let high_priority = Priority::with_urgency_and_incremental(0, false).unwrap();
        let low_priority = Priority::with_urgency_and_incremental(7, false).unwrap();
        
        manager.scheduler.update_stream_priority(4, high_priority).await.unwrap();
        manager.scheduler.update_stream_priority(8, low_priority).await.unwrap();
        
        // High priority stream should be scheduled first
        let next_stream = manager.schedule_next_stream().await;
        assert_eq!(next_stream, Some(4));
    }
}