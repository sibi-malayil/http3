use http3::{
    http3::{
        datagram::{DatagramManager, DatagramConfig, DatagramResult},
        frame::{DatagramFrame, Http3Frame},
    },
    quic::stream::{StreamId, StreamType},
    quic::connection::ConnectionRole,
};
use bytes::Bytes;

#[test]
fn test_complete_datagram_workflow() {
    let mut manager = DatagramManager::default();
    let stream_id = StreamId::new(4, StreamType::Bidirectional, ConnectionRole::Client).unwrap();
    
    // Test basic datagram functionality
    assert!(manager.is_enabled());
    assert_eq!(manager.total_pending_datagrams(), 0);
    
    // Send a datagram
    let data = Bytes::from_static(b"Hello, Datagram World!");
    let result = manager.send_datagram(stream_id, data.clone());
    assert_eq!(result, DatagramResult::Queued);
    assert_eq!(manager.pending_datagram_count(stream_id), 1);
    
    // Get the frame for transmission
    let frame = manager.next_datagram_frame(stream_id).unwrap();
    match frame {
        Http3Frame::Datagram(datagram_frame) => {
            assert_eq!(datagram_frame.data, data);
        }
        _ => panic!("Expected DATAGRAM frame"),
    }
    
    // Queue should be empty now
    assert_eq!(manager.pending_datagram_count(stream_id), 0);
    
    // Simulate receiving a datagram
    let received_data = Bytes::from_static(b"Response datagram");
    let received_frame = DatagramFrame::new(received_data.clone());
    manager.on_datagram_received(stream_id, received_frame).unwrap();
    
    // Check received datagram
    let received = manager.next_received_datagram().unwrap();
    assert_eq!(received.stream_id, stream_id);
    assert_eq!(received.data, received_data);
    
    // Verify statistics
    let stats = manager.stats();
    assert_eq!(stats.datagrams_sent, 1);
    assert_eq!(stats.datagrams_received, 1);
    assert_eq!(stats.bytes_sent, data.len() as u64);
    assert_eq!(stats.bytes_received, received_data.len() as u64);
}

#[test]
fn test_datagram_size_limits() {
    let config = DatagramConfig {
        max_datagram_size: 100,
        ..Default::default()
    };
    let mut manager = DatagramManager::new(config);
    let stream_id = StreamId::new(4, StreamType::Bidirectional, ConnectionRole::Client).unwrap();
    
    // Small datagram should work
    let small_data = Bytes::from(vec![0u8; 50]);
    let result = manager.send_datagram(stream_id, small_data);
    assert_eq!(result, DatagramResult::Queued);
    
    // Large datagram should be rejected
    let large_data = Bytes::from(vec![0u8; 200]);
    let result = manager.send_datagram(stream_id, large_data);
    assert_eq!(result, DatagramResult::TooLarge);
    
    let stats = manager.stats();
    assert_eq!(stats.dropped_too_large, 1);
}

#[test]
fn test_datagram_queue_limits() {
    let config = DatagramConfig {
        max_queue_size: 2,
        ..Default::default()
    };
    let mut manager = DatagramManager::new(config);
    let stream_id = StreamId::new(4, StreamType::Bidirectional, ConnectionRole::Client).unwrap();
    let data = Bytes::from_static(b"test");
    
    // Fill the queue
    assert_eq!(manager.send_datagram(stream_id, data.clone()), DatagramResult::Queued);
    assert_eq!(manager.send_datagram(stream_id, data.clone()), DatagramResult::Queued);
    
    // Next one should be rejected
    assert_eq!(manager.send_datagram(stream_id, data), DatagramResult::QueueFull);
    
    let stats = manager.stats();
    assert_eq!(stats.dropped_queue_full, 1);
}

#[test]
fn test_datagram_disabled() {
    let config = DatagramConfig {
        enabled: false,
        ..Default::default()
    };
    let mut manager = DatagramManager::new(config);
    let stream_id = StreamId::new(4, StreamType::Bidirectional, ConnectionRole::Client).unwrap();
    let data = Bytes::from_static(b"test");
    
    assert!(!manager.is_enabled());
    assert_eq!(manager.send_datagram(stream_id, data), DatagramResult::NotSupported);
    assert!(manager.next_datagram_frame(stream_id).is_none());
}

#[test]
fn test_multiple_streams() {
    let mut manager = DatagramManager::default();
    let stream1 = StreamId::new(4, StreamType::Bidirectional, ConnectionRole::Client).unwrap();
    let stream2 = StreamId::new(8, StreamType::Bidirectional, ConnectionRole::Client).unwrap();
    
    let data1 = Bytes::from_static(b"Stream 1 data");
    let data2 = Bytes::from_static(b"Stream 2 data");
    
    // Send datagrams on both streams
    assert_eq!(manager.send_datagram(stream1, data1.clone()), DatagramResult::Queued);
    assert_eq!(manager.send_datagram(stream2, data2.clone()), DatagramResult::Queued);
    
    assert_eq!(manager.pending_datagram_count(stream1), 1);
    assert_eq!(manager.pending_datagram_count(stream2), 1);
    assert_eq!(manager.total_pending_datagrams(), 2);
    
    // Get frames from each stream
    let frame1 = manager.next_datagram_frame(stream1).unwrap();
    let frame2 = manager.next_datagram_frame(stream2).unwrap();
    
    match (frame1, frame2) {
        (Http3Frame::Datagram(f1), Http3Frame::Datagram(f2)) => {
            assert_eq!(f1.data, data1);
            assert_eq!(f2.data, data2);
        }
        _ => panic!("Expected DATAGRAM frames"),
    }
    
    assert_eq!(manager.total_pending_datagrams(), 0);
}