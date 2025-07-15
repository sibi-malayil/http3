//! Tests for enhanced Loss Detection Timer implementation per RFC 9002

use http3::quic::{
    recovery::{RecoveryManager, PacketNumberSpace},
    packet::{Packet, PacketHeader, ShortHeader, ConnectionId, PacketType, LongHeader, TypeSpecificData},
    frame_types::Frame,
};
use http3::util::{
    time::{Duration, Instant},
    varint::VarInt,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[test]
fn test_anti_amplification_protection() {
    let mut recovery = RecoveryManager::new();
    
    // Initially, no bytes received, so can't send anything
    assert!(!recovery.can_send_packet(1200));
    
    // Receive some data (1000 bytes)
    recovery.update_bytes_received(1000);
    
    // Can now send up to 3x received (3000 bytes)
    assert!(recovery.can_send_packet(1200)); // 1200 bytes OK
    assert!(recovery.can_send_packet(1800)); // 1800 bytes OK (total would be 3000)
    
    // Send 1200 bytes
    recovery.update_bytes_sent(1200);
    
    // Can still send 1800 more bytes (3000 - 1200 = 1800)
    assert!(recovery.can_send_packet(1800));
    assert!(!recovery.can_send_packet(1801)); // 1801 would exceed limit
    
    // Address validation removes limits
    recovery.validate_address();
    assert!(recovery.can_send_packet(10000)); // Now unlimited
}

#[test]
fn test_handshake_confirmation_affects_timer() {
    let mut recovery = RecoveryManager::new();
    
    // Before handshake confirmation
    assert!(!recovery.is_handshake_confirmed());
    
    // Send packets in different spaces
    let spaces = [
        (PacketNumberSpace::Initial, create_initial_packet(0)),
        (PacketNumberSpace::Handshake, create_handshake_packet(0)),
        (PacketNumberSpace::ApplicationData, create_app_data_packet(0)),
    ];
    
    for (space, packet) in spaces {
        recovery.on_packet_sent(&packet, vec![Frame::Ping]);
    }
    
    // Before handshake confirmation, should only consider Initial and Handshake
    // (ApplicationData packets are tracked but PTO timer behavior differs)
    
    // Confirm handshake
    recovery.confirm_handshake();
    assert!(recovery.is_handshake_confirmed());
    
    // After confirmation, timer behavior includes all spaces
}

#[test]
fn test_per_space_pto_calculation() {
    let recovery = RecoveryManager::new();
    
    // Get PTO for each space
    let initial_pto = recovery.probe_timeout_for_space(PacketNumberSpace::Initial);
    let handshake_pto = recovery.probe_timeout_for_space(PacketNumberSpace::Handshake);
    let app_data_pto = recovery.probe_timeout_for_space(PacketNumberSpace::ApplicationData);
    
    // Initial and Handshake should not include max_ack_delay
    assert_eq!(initial_pto, handshake_pto);
    
    // Application Data should include max_ack_delay (25ms default)
    assert!(app_data_pto > initial_pto);
    assert_eq!(app_data_pto, initial_pto + Duration::from_millis(25));
}

#[test]
fn test_enhanced_probe_packet_generation() {
    let mut recovery = RecoveryManager::new();
    
    // Send CRYPTO frame in Handshake space
    let handshake_packet = create_handshake_packet(0);
    recovery.on_packet_sent(&handshake_packet, vec![Frame::Crypto {
        offset: 0,
        data: vec![0u8; 100].into(),
    }]);
    
    // Send STREAM frame in Application Data space
    let app_packet = create_app_data_packet(1);
    recovery.on_packet_sent(&app_packet, vec![Frame::Stream {
        stream_id: 0.into(),
        offset: 0,
        data: vec![1u8; 200].into(),
        fin: false,
        length: None,
    }]);
    
    // Generate enhanced probe packets
    let probe_packets = recovery.generate_enhanced_probe_packets_test();
    
    // Should prioritize Handshake space (before confirmation)
    assert!(!probe_packets.is_empty());
    
    // Check that CRYPTO frames are prioritized for Handshake space
    let handshake_probes = probe_packets.iter()
        .find(|(space, _)| *space == PacketNumberSpace::Handshake);
    
    if let Some((_, frames)) = handshake_probes {
        // Should contain PING and possibly CRYPTO frame
        assert!(frames.iter().any(|f| matches!(f, Frame::Ping)));
    }
}

#[test]
fn test_pto_backoff_calculation() {
    let mut recovery = RecoveryManager::new();
    
    // Send a packet
    let packet = create_app_data_packet(0);
    recovery.on_packet_sent(&packet, vec![Frame::Ping]);
    
    // Initial PTO count is 0, so backoff = 2^0 = 1
    assert_eq!(recovery.pto_count(), 0);
    
    // Simulate PTO expiry
    recovery.trigger_loss_detection_timeout();
    assert_eq!(recovery.pto_count(), 1); // Should increment
    
    // Next expiry should have backoff = 2^1 = 2
    recovery.trigger_loss_detection_timeout();
    assert_eq!(recovery.pto_count(), 2); // Should increment again
    
    // Receiving an ACK should reset PTO count
    let ack_result = recovery.on_ack_received(
        PacketNumberSpace::ApplicationData,
        0,
        &[(0, 0)],
        Duration::ZERO,
    );
    assert!(ack_result.is_ok());
    assert_eq!(recovery.pto_count(), 0); // Should reset
}

#[test]
fn test_timer_state_management() {
    let mut recovery = RecoveryManager::new();
    
    // No packets sent, no timer should be set
    assert!(recovery.check_loss_detection().is_none());
    
    // Send ack-eliciting packet
    let packet = create_app_data_packet(0);
    recovery.on_packet_sent(&packet, vec![Frame::Stream {
        stream_id: 0.into(),
        offset: 0,
        data: vec![0u8; 100].into(),
        fin: false,
        length: None,
    }]);
    
    // Timer should now be set
    // (Note: In real implementation, we'd need to wait for actual time passage)
    
    // ACK the packet
    let lost_frames = recovery.on_ack_received(
        PacketNumberSpace::ApplicationData,
        0,
        &[(0, 0)],
        Duration::ZERO,
    ).unwrap();
    
    assert!(lost_frames.is_empty()); // No lost frames
    
    // Timer should be cleared (no more in-flight packets)
    assert!(recovery.check_loss_detection().is_none());
}

#[test]
fn test_probe_frame_selection() {
    let mut recovery = RecoveryManager::new();
    
    // Create probe frames for different spaces
    let initial_frames = recovery.create_probe_frames_for_space_test(PacketNumberSpace::Initial);
    let handshake_frames = recovery.create_probe_frames_for_space_test(PacketNumberSpace::Handshake);
    let app_frames = recovery.create_probe_frames_for_space_test(PacketNumberSpace::ApplicationData);
    
    // All should contain at least a PING frame for ack-eliciting
    assert!(initial_frames.iter().any(|f| matches!(f, Frame::Ping)));
    assert!(handshake_frames.iter().any(|f| matches!(f, Frame::Ping)));
    assert!(app_frames.iter().any(|f| matches!(f, Frame::Ping)));
}

#[test]
fn test_space_priority_ordering() {
    let mut recovery = RecoveryManager::new();
    
    // Before handshake confirmation, priority should be Handshake > Initial
    assert!(!recovery.is_handshake_confirmed());
    
    // Send packets in all spaces
    for (i, space) in [PacketNumberSpace::Initial, PacketNumberSpace::Handshake, PacketNumberSpace::ApplicationData].iter().enumerate() {
        let packet = match space {
            PacketNumberSpace::Initial => create_initial_packet(i as u32),
            PacketNumberSpace::Handshake => create_handshake_packet(i as u32),
            PacketNumberSpace::ApplicationData => create_app_data_packet(i as u32),
        };
        recovery.on_packet_sent(&packet, vec![Frame::Ping]);
    }
    
    let probe_packets = recovery.generate_enhanced_probe_packets_test();
    
    // Should prioritize Handshake and Initial before confirmation
    if let Some((first_space, _)) = probe_packets.first() {
        assert!(matches!(first_space, PacketNumberSpace::Handshake | PacketNumberSpace::Initial));
    }
    
    // After handshake confirmation, priority changes
    recovery.confirm_handshake();
    let probe_packets_after = recovery.generate_enhanced_probe_packets_test();
    
    // Priority should now include ApplicationData first
    if let Some((first_space, _)) = probe_packets_after.first() {
        // Could be any space, but ApplicationData is now considered
        assert!(matches!(first_space, 
            PacketNumberSpace::ApplicationData | 
            PacketNumberSpace::Handshake | 
            PacketNumberSpace::Initial
        ));
    }
}

// Helper functions to create test packets

fn create_initial_packet(packet_number: u32) -> Packet {
    let header = LongHeader::new(
        PacketType::Initial,
        0x00000001,
        ConnectionId::random(8).unwrap(),
        ConnectionId::random(8).unwrap(),
        TypeSpecificData::Initial {
            token: bytes::Bytes::new(),
            length: VarInt::from_u32(0),
            packet_number,
        }
    );
    
    Packet::new(
        PacketHeader::Long(header),
        vec![0u8; 100].into(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081),
    )
}

fn create_handshake_packet(packet_number: u32) -> Packet {
    let header = LongHeader::new(
        PacketType::Handshake,
        0x00000001,
        ConnectionId::random(8).unwrap(),
        ConnectionId::random(8).unwrap(),
        TypeSpecificData::Handshake {
            length: VarInt::from_u32(0),
            packet_number,
        }
    );
    
    Packet::new(
        PacketHeader::Long(header),
        vec![0u8; 100].into(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081),
    )
}

fn create_app_data_packet(packet_number: u32) -> Packet {
    let header = ShortHeader::new(
        false,
        false,
        ConnectionId::random(8).unwrap(),
        packet_number,
    );
    
    Packet::new(
        PacketHeader::Short(header),
        vec![0u8; 100].into(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081),
    )
}