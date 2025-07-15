//! Flow control integration tests
//!
//! Tests the complete flow control implementation including:
//! - BLOCKED frame generation
//! - MAX_DATA/MAX_STREAM_DATA frame processing
//! - Automatic window updates
//! - Flow control violation detection

use crate::{
    error::{Error, Result},
    quic::{
        connection::ConnectionRole,
        stream::{StreamId, StreamType},
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

    /// Test that DATA_BLOCKED frames are generated when hitting connection flow control limits
    #[test]
    fn test_data_blocked_frame_generation() {
        // Create stream manager with small connection window
        let mut params = TransportParameters::default();
        params.initial_max_data = Some(VarInt::from_u32(1000)); // 1KB connection window
        
        let mut manager = StreamManager::new(ConnectionRole::Client, &params);
        manager.update_peer_params(&params);
        
        // Create a stream
        let stream_id = manager.create_stream(StreamParameters::default()).unwrap();
        
        // Send data up to the limit
        let data = Bytes::from(vec![0u8; 800]);
        assert!(manager.send_data(stream_id, data.clone(), false).is_ok());
        
        // Try to send more data - should be blocked
        let blocked_data = Bytes::from(vec![0u8; 300]);
        assert!(matches!(manager.send_data(stream_id, blocked_data, false), Err(Error::FlowControl)));
        
        // Check that DATA_BLOCKED frame was generated
        let frames = manager.get_pending_flow_control_frames();
        assert!(frames.iter().any(|frame| matches!(frame, Frame::DataBlocked { .. })));
        
        println!("✅ DATA_BLOCKED frame generated correctly");
    }

    /// Test that STREAM_DATA_BLOCKED frames are generated when hitting stream flow control limits
    #[test]
    fn test_stream_data_blocked_frame_generation() {
        let mut params = TransportParameters::default();
        params.initial_max_data = Some(VarInt::from_u32(10000)); // Large connection window
        
        let mut manager = StreamManager::new(ConnectionRole::Client, &params);
        manager.update_peer_params(&params);
        
        // Create a stream with limited send window
        let stream_id = manager.create_stream(StreamParameters::default()).unwrap();
        
        // Set a small stream send limit using test helper
        manager.test_set_stream_send_limit(stream_id, 500).unwrap();
        
        // Try to send data exceeding stream limit
        let data = Bytes::from(vec![0u8; 600]);
        assert!(matches!(manager.send_data(stream_id, data, false), Err(Error::FlowControl)));
        
        // Check that STREAM_DATA_BLOCKED frame was generated
        let frames = manager.get_pending_flow_control_frames();
        assert!(frames.iter().any(|frame| matches!(
            frame, 
            Frame::StreamDataBlocked { stream_id: sid, .. } if *sid == stream_id
        )));
        
        println!("✅ STREAM_DATA_BLOCKED frame generated correctly");
    }

    /// Test that blocked streams are unblocked when MAX_DATA is received
    #[test]
    fn test_max_data_unblocks_streams() {
        let mut params = TransportParameters::default();
        params.initial_max_data = Some(VarInt::from_u32(1000));
        
        let mut manager = StreamManager::new(ConnectionRole::Client, &params);
        manager.update_peer_params(&params);
        
        // Create two streams
        let stream1 = manager.create_stream(StreamParameters::default()).unwrap();
        let stream2 = manager.create_stream(StreamParameters::default()).unwrap();
        
        // Send data to exhaust connection window
        let data1 = Bytes::from(vec![1u8; 600]);
        let data2 = Bytes::from(vec![2u8; 400]);
        manager.send_data(stream1, data1, false).unwrap();
        manager.send_data(stream2, data2, false).unwrap();
        
        // Both streams should now be blocked
        let blocked_data = Bytes::from(vec![3u8; 200]);
        assert!(manager.send_data(stream1, blocked_data.clone(), false).is_err());
        assert!(manager.send_data(stream2, blocked_data.clone(), false).is_err());
        
        // Receive MAX_DATA frame increasing limit
        manager.update_max_data(2000).unwrap();
        
        // Now sending should succeed
        assert!(manager.send_data(stream1, blocked_data.clone(), false).is_ok());
        assert!(manager.send_data(stream2, blocked_data, false).is_ok());
        
        println!("✅ MAX_DATA correctly unblocks streams");
    }

    /// Test that blocked streams are unblocked when MAX_STREAM_DATA is received
    #[test]
    fn test_max_stream_data_unblocks_stream() {
        let mut params = TransportParameters::default();
        params.initial_max_data = Some(VarInt::from_u32(10000));
        
        let mut manager = StreamManager::new(ConnectionRole::Client, &params);
        manager.update_peer_params(&params);
        
        let stream_id = manager.create_stream(StreamParameters::default()).unwrap();
        
        // Set small stream limit using test helper
        manager.test_set_stream_send_limit(stream_id, 100).unwrap();
        
        // Send data up to limit
        let data = Bytes::from(vec![0u8; 100]);
        manager.send_data(stream_id, data, false).unwrap();
        
        // Should be blocked now
        let blocked_data = Bytes::from(vec![1u8; 50]);
        assert!(manager.send_data(stream_id, blocked_data.clone(), false).is_err());
        
        // Increase stream limit
        manager.update_max_stream_data(stream_id, 200).unwrap();
        
        // Should succeed now
        assert!(manager.send_data(stream_id, blocked_data, false).is_ok());
        
        println!("✅ MAX_STREAM_DATA correctly unblocks stream");
    }

    /// Test automatic connection window updates
    #[test]
    fn test_automatic_connection_window_update() {
        let mut params = TransportParameters::default();
        params.initial_max_data = Some(VarInt::from_u32(2000));
        
        let mut manager = StreamManager::new(ConnectionRole::Client, &params);
        
        // Create a stream and receive data
        let stream_id = StreamId::from(1); // Server-initiated stream
        
        // Receive data consuming 60% of window (1200 bytes of 2000)
        let data = Bytes::from(vec![0u8; 1200]);
        manager.receive_data(stream_id, 0, data, false).unwrap();
        
        // Check that MAX_DATA frame is generated (window > 50% consumed)
        let frames = manager.get_pending_flow_control_frames();
        let max_data_frame = frames.iter().find(|frame| matches!(frame, Frame::MaxData { .. }));
        
        assert!(max_data_frame.is_some());
        if let Some(Frame::MaxData { maximum_data }) = max_data_frame {
            assert!(*maximum_data > 2000); // Window should be increased
            println!("✅ Automatic MAX_DATA generated: new limit = {}", maximum_data);
        }
    }

    /// Test automatic stream window updates
    #[test]
    fn test_automatic_stream_window_update() {
        let params = TransportParameters::default();
        let mut manager = StreamManager::new(ConnectionRole::Client, &params);
        
        // Accept a server-initiated stream
        let stream_id = StreamId::from(1);
        
        // Receive data consuming > 50% of default stream window  
        let window_size = 65536; // Default 64KB per stream
        let data_size = (window_size * 6) / 10; // 60% of window
        let data = Bytes::from(vec![0u8; data_size]);
        
        manager.receive_data(stream_id, 0, data, false).unwrap();
        
        // Check that MAX_STREAM_DATA frame is generated
        let frames = manager.get_pending_flow_control_frames();
        let max_stream_data_frame = frames.iter().find(|frame| 
            matches!(frame, Frame::MaxStreamData { stream_id: sid, .. } if *sid == stream_id)
        );
        
        assert!(max_stream_data_frame.is_some());
        println!("✅ Automatic MAX_STREAM_DATA generated for stream");
    }

    /// Test flow control violation detection
    #[test]
    fn test_flow_control_violation_detection() {
        let mut params = TransportParameters::default();
        params.initial_max_data = Some(VarInt::from_u32(1000));
        
        let mut manager = StreamManager::new(ConnectionRole::Server, &params);
        
        // Try to receive data exceeding connection limit
        let stream_id = StreamId::from(0); // Client-initiated
        let data = Bytes::from(vec![0u8; 1500]); // Exceeds 1000 byte limit
        
        let result = manager.receive_data(stream_id, 0, data, false);
        assert!(result.is_err());
        
        match result {
            Err(Error::ConnectionError(msg)) => {
                assert!(msg.contains("Flow control violation"));
                println!("✅ Flow control violation detected: {}", msg);
            }
            _ => panic!("Expected flow control violation error"),
        }
    }

    /// Test prioritized sending with flow control
    #[test]
    fn test_flow_control_with_priorities() {
        let mut params = TransportParameters::default();
        params.initial_max_data = Some(VarInt::from_u32(2000));
        
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
        
        // Send data on both
        let data = Bytes::from(vec![0u8; 500]);
        manager.send_data(normal_stream, data.clone(), false).unwrap();
        manager.send_data(urgent_stream, data.clone(), false).unwrap();
        
        // Urgent stream should be first in send queue
        assert_eq!(manager.next_send_ready(), Some(urgent_stream));
        assert_eq!(manager.next_send_ready(), Some(normal_stream));
        
        println!("✅ Flow control respects stream priorities");
    }

    /// Test STREAMS_BLOCKED frame handling
    #[test]
    fn test_streams_blocked_handling() {
        let params = TransportParameters::default();
        let mut manager = StreamManager::new(ConnectionRole::Server, &params);
        
        // Handle STREAMS_BLOCKED frame
        let result = manager.handle_streams_blocked(
            crate::quic::frame_types::StreamType::Bidirectional, 
            10
        );
        
        assert!(result.is_ok());
        println!("✅ STREAMS_BLOCKED frame handled correctly");
    }

    /// Test multiple window updates don't cause issues
    #[test]
    fn test_multiple_window_updates() {
        let mut params = TransportParameters::default();
        params.initial_max_data = Some(VarInt::from_u32(1000));
        
        let mut manager = StreamManager::new(ConnectionRole::Client, &params);
        manager.update_peer_params(&params);
        
        // Multiple MAX_DATA updates should work correctly
        assert!(manager.update_max_data(2000).is_ok());
        assert!(manager.update_max_data(3000).is_ok());
        assert!(manager.update_max_data(4000).is_ok());
        
        // Decreasing MAX_DATA should fail
        assert!(manager.update_max_data(3500).is_err());
        
        println!("✅ Multiple window updates handled correctly");
    }
}

