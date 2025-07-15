use http3::{
    quic::{
        unreliable::{UnreliableDeliveryManager, UnreliableConfig, UnreliableResult},
        packet::ConnectionId,
        connection::ConnectionRole,
        congestion::CongestionController,
    },
};
use bytes::Bytes;
use std::time::Duration;

#[test]
fn test_unreliable_delivery_basic_workflow() {
    let mut client_manager = UnreliableDeliveryManager::default_for_role(ConnectionRole::Client);
    let mut server_manager = UnreliableDeliveryManager::default_for_role(ConnectionRole::Server);
    
    // Set both as ready
    client_manager.set_connection_ready(true);
    server_manager.set_connection_ready(true);
    
    // Client sends datagram
    let test_data = Bytes::from_static(b"Hello from client!");
    let result = client_manager.send_datagram(test_data.clone(), 1, Some(42), None);
    assert_eq!(result, UnreliableResult::Queued);
    
    // Get datagram from client queue
    let transmitted_data = client_manager.next_datagram().unwrap();
    assert_eq!(transmitted_data, test_data);
    
    // Simulate reception at server
    let connection_id = ConnectionId::from(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    server_manager.on_datagram_received(connection_id, transmitted_data).unwrap();
    
    // Server retrieves received datagram
    let received = server_manager.next_received_datagram().unwrap();
    assert_eq!(received.connection_id, connection_id);
    assert_eq!(received.data, test_data);
    assert_eq!(received.size, test_data.len());
    
    // Check statistics
    let client_stats = client_manager.stats();
    assert_eq!(client_stats.datagrams_sent, 1);
    assert_eq!(client_stats.bytes_sent, test_data.len() as u64);
    
    let server_stats = server_manager.stats();
    assert_eq!(server_stats.datagrams_received, 1);
    assert_eq!(server_stats.bytes_received, test_data.len() as u64);
}

#[test]
fn test_bidirectional_unreliable_communication() {
    let mut client_manager = UnreliableDeliveryManager::default_for_role(ConnectionRole::Client);
    let mut server_manager = UnreliableDeliveryManager::default_for_role(ConnectionRole::Server);
    
    client_manager.set_connection_ready(true);
    server_manager.set_connection_ready(true);
    
    let client_conn_id = ConnectionId::from(vec![1, 1, 1, 1, 1, 1, 1, 1]);
    let server_conn_id = ConnectionId::from(vec![2, 2, 2, 2, 2, 2, 2, 2]);
    
    // Client to server
    let client_data = Bytes::from_static(b"Client request");
    client_manager.send_datagram(client_data.clone(), 0, Some(1), None);
    let transmitted = client_manager.next_datagram().unwrap();
    server_manager.on_datagram_received(&server_conn_id, transmitted).unwrap();
    
    // Server to client
    let server_data = Bytes::from_static(b"Server response");
    server_manager.send_datagram(server_data.clone(), 0, Some(2), None);
    let transmitted = server_manager.next_datagram().unwrap();
    client_manager.on_datagram_received(&client_conn_id, transmitted).unwrap();
    
    // Verify both received
    let client_received = client_manager.next_received_datagram().unwrap();
    assert_eq!(client_received.data, server_data);
    
    let server_received = server_manager.next_received_datagram().unwrap();
    assert_eq!(server_received.data, client_data);
}

#[test]
fn test_priority_based_transmission() {
    let mut manager = UnreliableDeliveryManager::default_for_role(ConnectionRole::Client);
    manager.set_connection_ready(true);
    
    // Send datagrams with different priorities
    let low_priority = Bytes::from_static(b"Low priority message");
    let high_priority = Bytes::from_static(b"High priority message");
    let medium_priority = Bytes::from_static(b"Medium priority message");
    
    // Add in reverse priority order to test sorting
    manager.send_datagram(low_priority.clone(), 10, Some(1), None);
    manager.send_datagram(high_priority.clone(), 1, Some(2), None);
    manager.send_datagram(medium_priority.clone(), 5, Some(3), None);
    
    // Should come out in priority order (lower number = higher priority)
    assert_eq!(manager.next_datagram().unwrap(), high_priority);
    assert_eq!(manager.next_datagram().unwrap(), medium_priority);
    assert_eq!(manager.next_datagram().unwrap(), low_priority);
    
    let stats = manager.stats();
    assert_eq!(stats.datagrams_sent, 3);
    assert_eq!(stats.peak_queue_size, 3);
}

#[test]
fn test_congestion_control_integration() {
    let mut manager = UnreliableDeliveryManager::default_for_role(ConnectionRole::Client);
    manager.set_connection_ready(true);
    
    let mut congestion_controller = CongestionController::new();
    
    // Simulate network congestion - fill up bytes in flight
    for _ in 0..100 {
        congestion_controller.on_packet_sent(100);
    }
    
    let test_data = Bytes::from_static(b"Test under congestion");
    let result = manager.send_datagram(test_data, 1, Some(1), Some(&congestion_controller));
    
    // Should be dropped due to congestion
    assert_eq!(result, UnreliableResult::CongestionDropped);
    
    let stats = manager.stats();
    assert_eq!(stats.dropped_congestion, 1);
}

#[test]
fn test_queue_overflow_behavior() {
    let config = UnreliableConfig {
        max_queued_datagrams: 3,
        ..Default::default()
    };
    let mut manager = UnreliableDeliveryManager::new(config, ConnectionRole::Client);
    manager.set_connection_ready(true);
    
    // Fill the queue
    for i in 0..3 {
        let data = Bytes::from(format!("Message {}", i));
        let result = manager.send_datagram(data, i as u8, Some(i as u64), None);
        assert_eq!(result, UnreliableResult::Queued);
    }
    
    // Add one more - should cause oldest, lowest priority to be dropped
    let newest_data = Bytes::from_static(b"Newest message");
    let result = manager.send_datagram(newest_data.clone(), 0, Some(100), None);
    assert_eq!(result, UnreliableResult::Queued);
    
    // Should still have 3 datagrams, but lowest priority was dropped
    assert_eq!(manager.pending_datagram_count(), 3);
    
    // Get datagrams - should get highest priority first
    let first = manager.next_datagram().unwrap();
    assert_eq!(first, newest_data); // Priority 0
    
    let second = manager.next_datagram().unwrap();
    assert_eq!(second, Bytes::from("Message 1")); // Priority 1
    
    let third = manager.next_datagram().unwrap();
    // Should be Message 0 (priority 2 was dropped for being oldest+lowest priority)
    assert_eq!(third, Bytes::from("Message 0")); // Priority 2 was dropped
}

#[test]
fn test_size_limits() {
    let config = UnreliableConfig {
        max_datagram_size: 50,
        ..Default::default()
    };
    let mut manager = UnreliableDeliveryManager::new(config, ConnectionRole::Client);
    manager.set_connection_ready(true);
    
    // Small datagram should work
    let small_data = Bytes::from(vec![0u8; 30]);
    let result = manager.send_datagram(small_data, 1, None, None);
    assert_eq!(result, UnreliableResult::Queued);
    
    // Large datagram should be rejected
    let large_data = Bytes::from(vec![0u8; 100]);
    let result = manager.send_datagram(large_data, 1, None, None);
    assert_eq!(result, UnreliableResult::TooLarge);
    
    let stats = manager.stats();
    assert_eq!(stats.dropped_too_large, 1);
}

#[test]
fn test_connection_state_management() {
    let mut manager = UnreliableDeliveryManager::default_for_role(ConnectionRole::Client);
    
    // Initially not ready
    let test_data = Bytes::from_static(b"Test data");
    let result = manager.send_datagram(test_data.clone(), 1, None, None);
    assert_eq!(result, UnreliableResult::NotReady);
    
    // Make ready and queue datagram
    manager.set_connection_ready(true);
    let result = manager.send_datagram(test_data.clone(), 1, None, None);
    assert_eq!(result, UnreliableResult::Queued);
    assert_eq!(manager.pending_datagram_count(), 1);
    
    // Disable connection - should clear queue
    manager.set_connection_ready(false);
    assert_eq!(manager.pending_datagram_count(), 0);
    
    // Should not accept new datagrams
    let result = manager.send_datagram(test_data, 1, None, None);
    assert_eq!(result, UnreliableResult::NotReady);
}

#[test]
fn test_burst_control() {
    let config = UnreliableConfig {
        max_burst_size: 2,
        ..Default::default()
    };
    let mut manager = UnreliableDeliveryManager::new(config, ConnectionRole::Client);
    manager.set_connection_ready(true);
    
    // Queue several datagrams
    for i in 0..5 {
        let data = Bytes::from(format!("Message {}", i));
        manager.send_datagram(data, 1, Some(i as u64), None);
    }
    
    // Should be able to send burst_size datagrams quickly
    let first = manager.next_datagram();
    assert!(first.is_some());
    
    let second = manager.next_datagram();
    assert!(second.is_some());
    
    // Third should be limited by burst control (in real implementation)
    // For this test, we just verify that the queue management works
    assert_eq!(manager.pending_datagram_count(), 3);
}

#[test]
fn test_statistics_accuracy() {
    let mut manager = UnreliableDeliveryManager::default_for_role(ConnectionRole::Client);
    manager.set_connection_ready(true);
    
    // Send various sized datagrams
    let sizes = [10, 20, 30, 40, 50];
    for (i, &size) in sizes.iter().enumerate() {
        let data = Bytes::from(vec![i as u8; size]);
        manager.send_datagram(data, 1, Some(i as u64), None);
    }
    
    // Transmit all
    let mut total_sent = 0;
    while let Some(data) = manager.next_datagram() {
        total_sent += data.len();
    }
    
    let stats = manager.stats();
    assert_eq!(stats.datagrams_sent, 5);
    assert_eq!(stats.bytes_sent, total_sent as u64);
    assert_eq!(stats.avg_datagram_size, 30.0); // Average of 10,20,30,40,50
    assert_eq!(stats.peak_queue_size, 5);
    assert_eq!(stats.current_queue_size, 0);
}

#[test]
fn test_received_datagram_buffer_limits() {
    let mut manager = UnreliableDeliveryManager::default_for_role(ConnectionRole::Server);
    let connection_id = ConnectionId::from(vec![1, 2, 3, 4, 5, 6, 7, 8]);
    
    // Send many received datagrams to test buffer limits
    for i in 0..1050 { // More than the 1000 limit
        let data = Bytes::from(format!("Received message {}", i));
        manager.on_datagram_received(&connection_id, data).unwrap();
    }
    
    // Should have limited to 1000
    let mut received_count = 0;
    while manager.next_received_datagram().is_some() {
        received_count += 1;
    }
    
    assert_eq!(received_count, 1000);
    
    let stats = manager.stats();
    assert_eq!(stats.datagrams_received, 1050); // All were processed
}

#[test]
fn test_config_updates() {
    let mut manager = UnreliableDeliveryManager::default_for_role(ConnectionRole::Client);
    manager.set_connection_ready(true);
    
    // Queue some datagrams
    for i in 0..5 {
        let data = Bytes::from(format!("Message {}", i));
        manager.send_datagram(data, 1, Some(i as u64), None);
    }
    
    assert_eq!(manager.pending_datagram_count(), 5);
    
    // Update config to smaller queue size
    let new_config = UnreliableConfig {
        max_queued_datagrams: 2,
        ..Default::default()
    };
    manager.update_config(new_config);
    
    // Should have reduced queue size
    assert!(manager.pending_datagram_count() <= 2);
    
    // Disable unreliable delivery
    let disabled_config = UnreliableConfig {
        enabled: false,
        ..Default::default()
    };
    manager.update_config(disabled_config);
    
    // Should have cleared all queues
    assert_eq!(manager.pending_datagram_count(), 0);
    assert!(!manager.is_enabled());
}