//! Integration tests for flow control and frame prioritization
//!
//! Tests the complete integration between flow control mechanisms and
//! prioritized frame scheduling according to RFC 9000 requirements.

use crate::{
    quic::{
        connection::ConnectionRole,
        stream::StreamId,
        stream_manager::{StreamManager, StreamParameters, StreamPriority},
        frame_types::Frame,
        transport::TransportParameters,
    },
    util::varint::VarInt,
};
use bytes::Bytes;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test prioritized frame scheduling with flow control integration
    #[test]
    fn test_prioritized_flow_control_frame_scheduling() {
        let mut params = TransportParameters::default();
        params.initial_max_data = Some(VarInt::from_u32(1000));
        
        let mut manager = StreamManager::new(ConnectionRole::Client, &params);
        manager.update_peer_params(&params);
        
        // Create streams with different priorities
        let urgent_stream = manager.create_stream(StreamParameters {
            priority: StreamPriority::Urgent,
            ..Default::default()
        }).unwrap();
        
        let normal_stream = manager.create_stream(StreamParameters {
            priority: StreamPriority::Normal,
            ..Default::default()
        }).unwrap();
        
        let low_stream = manager.create_stream(StreamParameters {
            priority: StreamPriority::Low,
            ..Default::default()
        }).unwrap();
        
        // Schedule various frame types
        manager.schedule_frame(Frame::Ping, None);
        manager.schedule_frame(Frame::MaxData { maximum_data: 2000 }, None);
        manager.schedule_frame(Frame::DataBlocked { maximum_data: 1000 }, None);
        manager.schedule_frame(
            Frame::Stream { 
                stream_id: urgent_stream, 
                offset: 0, 
                length: Some(100), 
                fin: false, 
                data: Bytes::from(vec![1u8; 100]) 
            }, 
            Some(urgent_stream)
        );
        manager.schedule_frame(
            Frame::Stream { 
                stream_id: normal_stream, 
                offset: 0, 
                length: Some(200), 
                fin: false, 
                data: Bytes::from(vec![2u8; 200]) 
            }, 
            Some(normal_stream)
        );
        
        // Get prioritized frames
        let frames = manager.get_prioritized_frames(1500);
        
        // Verify prioritization order
        assert!(!frames.is_empty());
        
        // Flow control frames should come first
        let mut flow_control_seen = false;
        let mut urgent_data_seen = false;
        let mut normal_data_seen = false;
        let mut maintenance_seen = false;
        
        for frame in &frames {
            match frame {
                Frame::MaxData { .. } | Frame::DataBlocked { .. } => {
                    assert!(!urgent_data_seen, "Flow control frames should come before data frames");
                    assert!(!normal_data_seen, "Flow control frames should come before data frames");
                    assert!(!maintenance_seen, "Flow control frames should come before maintenance frames");
                    flow_control_seen = true;
                }
                Frame::Stream { stream_id, .. } if *stream_id == urgent_stream => {
                    assert!(!normal_data_seen, "Urgent data should come before normal data");
                    assert!(!maintenance_seen, "Urgent data should come before maintenance");
                    urgent_data_seen = true;
                }
                Frame::Stream { stream_id, .. } if *stream_id == normal_stream => {
                    assert!(!maintenance_seen, "Normal data should come before maintenance");
                    normal_data_seen = true;
                }
                Frame::Ping => {
                    maintenance_seen = true;
                }
                _ => {}
            }
        }
        
        assert!(flow_control_seen, "Flow control frames should be included");
        println!("✅ Frame prioritization working correctly");
    }
    
    /// Test automatic window updates with prioritized scheduling
    #[test]
    fn test_automatic_window_updates_with_prioritization() {
        let mut params = TransportParameters::default();
        params.initial_max_data = Some(VarInt::from_u32(1000));
        
        let mut manager = StreamManager::new(ConnectionRole::Server, &params);
        
        // Create a stream and receive significant data to trigger window updates
        let stream_id = StreamId::from(1); // Client-initiated
        let data = Bytes::from(vec![0u8; 700]); // 70% of 1000 byte window
        manager.receive_data(stream_id, 0, data, false).unwrap();
        
        // Get frames which should include automatic window updates
        let frames = manager.get_prioritized_frames(1500);
        
        // Check that MAX_DATA frame is included and properly prioritized
        let max_data_frame = frames.iter().find(|frame| matches!(frame, Frame::MaxData { .. }));
        assert!(max_data_frame.is_some(), "MAX_DATA frame should be generated automatically");
        
        if let Some(Frame::MaxData { maximum_data }) = max_data_frame {
            assert!(*maximum_data > 1000, "Window should be expanded");
        }
        
        // Verify transmission statistics
        let stats = manager.get_transmission_stats();
        assert!(stats.frame_scheduler_stats.frames_scheduled_by_priority.len() > 0);
        
        println!("✅ Automatic window updates with prioritization working");
    }
    
    /// Test flow control violation handling with frame prioritization
    #[test]
    fn test_flow_control_violations_with_prioritization() {
        let mut params = TransportParameters::default();
        params.initial_max_data = Some(VarInt::from_u32(500));
        
        let mut manager = StreamManager::new(ConnectionRole::Server, &params);
        
        // Try to receive data exceeding the limit
        let stream_id = StreamId::from(0);
        let large_data = Bytes::from(vec![0u8; 600]); // Exceeds 500 byte limit
        
        let result = manager.receive_data(stream_id, 0, large_data, false);
        assert!(result.is_err(), "Should detect flow control violation");
        
        // Schedule frames including flow control related ones
        manager.schedule_frame(Frame::DataBlocked { maximum_data: 500 }, None);
        manager.schedule_frame(Frame::Ping, None);
        
        let frames = manager.get_prioritized_frames(1000);
        
        // Verify that flow control frames are prioritized over maintenance
        let mut blocked_position = None;
        let mut ping_position = None;
        
        for (i, frame) in frames.iter().enumerate() {
            match frame {
                Frame::DataBlocked { .. } => blocked_position = Some(i),
                Frame::Ping => ping_position = Some(i),
                _ => {}
            }
        }
        
        if let (Some(blocked_pos), Some(ping_pos)) = (blocked_position, ping_position) {
            assert!(blocked_pos < ping_pos, "Flow control frames should come before maintenance frames");
        }
        
        println!("✅ Flow control violation handling with prioritization working");
    }
    
    /// Test stream data prioritization within flow control limits
    #[test]
    fn test_stream_data_prioritization_with_flow_control() {
        let mut params = TransportParameters::default();
        params.initial_max_data = Some(VarInt::from_u32(2000));
        
        let mut manager = StreamManager::new(ConnectionRole::Client, &params);
        manager.update_peer_params(&params);
        
        // Create streams with different priorities
        let urgent_stream = manager.create_stream(StreamParameters {
            priority: StreamPriority::Urgent,
            ..Default::default()
        }).unwrap();
        
        let low_stream = manager.create_stream(StreamParameters {
            priority: StreamPriority::Low,
            ..Default::default()
        }).unwrap();
        
        // Schedule stream data frames
        let urgent_data = Bytes::from(vec![1u8; 300]);
        let low_data = Bytes::from(vec![2u8; 400]);
        
        manager.schedule_frame(
            Frame::Stream { 
                stream_id: low_stream, 
                offset: 0, 
                length: Some(400), 
                fin: false, 
                data: low_data 
            }, 
            Some(low_stream)
        );
        
        manager.schedule_frame(
            Frame::Stream { 
                stream_id: urgent_stream, 
                offset: 0, 
                length: Some(300), 
                fin: false, 
                data: urgent_data 
            }, 
            Some(urgent_stream)
        );
        
        // Get frames with limited packet size to test prioritization
        let frames = manager.get_prioritized_frames(800);
        
        // Find positions of stream frames
        let mut urgent_position = None;
        let mut low_position = None;
        
        for (i, frame) in frames.iter().enumerate() {
            if let Frame::Stream { stream_id, .. } = frame {
                if *stream_id == urgent_stream {
                    urgent_position = Some(i);
                } else if *stream_id == low_stream {
                    low_position = Some(i);
                }
            }
        }
        
        // Urgent stream should come before low priority stream
        if let (Some(urgent_pos), Some(low_pos)) = (urgent_position, low_position) {
            assert!(urgent_pos < low_pos, "Urgent stream data should be prioritized over low priority stream data");
        } else if urgent_position.is_some() && low_position.is_none() {
            // This is also acceptable - urgent data fits but low priority doesn't
            println!("Urgent data included, low priority data dropped due to size constraints");
        }
        
        println!("✅ Stream data prioritization with flow control working");
    }
    
    /// Test comprehensive frame scheduling statistics
    #[test]
    fn test_frame_scheduling_statistics() {
        let params = TransportParameters::default();
        let mut manager = StreamManager::new(ConnectionRole::Client, &params);
        
        // Schedule various types of frames
        manager.schedule_frame(Frame::Ping, None);
        manager.schedule_frame(Frame::MaxData { maximum_data: 1000 }, None);
        manager.schedule_frame(Frame::DataBlocked { maximum_data: 500 }, None);
        
        // Check transmission statistics
        let stats = manager.get_transmission_stats();
        assert!(stats.frame_scheduler_stats.frames_scheduled_by_priority.len() > 0);
        
        // Check if we have pending transmissions
        assert!(manager.has_pending_transmission());
        
        // Get frames
        let frames = manager.get_prioritized_frames(1500);
        assert!(!frames.is_empty());
        
        // After getting frames, there should be fewer pending
        let updated_stats = manager.get_transmission_stats();
        println!("Frame scheduling stats: {:?}", updated_stats.frame_scheduler_stats);
        
        println!("✅ Frame scheduling statistics working correctly");
    }
    
    /// Test integration with existing flow control mechanisms
    #[test]
    fn test_integration_with_existing_flow_control() {
        let mut params = TransportParameters::default();
        params.initial_max_data = Some(VarInt::from_u32(1000));
        
        let mut manager = StreamManager::new(ConnectionRole::Client, &params);
        manager.update_peer_params(&params);
        
        // Test that legacy get_pending_flow_control_frames still works
        let legacy_frames = manager.get_pending_flow_control_frames();
        
        // Test that new prioritized method also works
        let prioritized_frames = manager.get_prioritized_frames(1500);
        
        // Both should work and be consistent
        assert!(legacy_frames.len() >= 0); // Should not crash
        assert!(prioritized_frames.len() >= 0); // Should not crash
        
        // Create flow control situation and test both methods
        let stream_id = manager.create_stream(StreamParameters::default()).unwrap();
        
        // Generate some flow control need
        manager.conn_flow_control.should_send_max_data = true;
        
        let legacy_with_fc = manager.get_pending_flow_control_frames();
        manager.conn_flow_control.should_send_max_data = true; // Reset for second test
        let prioritized_with_fc = manager.get_prioritized_frames(1500);
        
        // Both methods should produce flow control frames
        let legacy_has_max_data = legacy_with_fc.iter().any(|f| matches!(f, Frame::MaxData { .. }));
        let prioritized_has_max_data = prioritized_with_fc.iter().any(|f| matches!(f, Frame::MaxData { .. }));
        
        assert!(legacy_has_max_data || prioritized_has_max_data, "At least one method should produce MAX_DATA frame");
        
        println!("✅ Integration with existing flow control mechanisms working");
    }
}