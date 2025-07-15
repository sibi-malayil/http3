//! Simple tests for enhanced Loss Detection Timer implementation per RFC 9002

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
fn test_handshake_confirmation() {
    let mut recovery = RecoveryManager::new();
    
    // Before handshake confirmation
    assert!(!recovery.is_handshake_confirmed());
    
    // Confirm handshake
    recovery.confirm_handshake();
    assert!(recovery.is_handshake_confirmed());
}

#[test]
fn test_basic_timer_functionality() {
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
fn test_probe_timeout_calculation() {
    let recovery = RecoveryManager::new();
    
    // Test that PTO calculation works
    let pto = recovery.probe_timeout();
    
    // Should be reasonable values
    assert!(pto > Duration::ZERO);
    assert!(pto < Duration::from_secs(5)); // Reasonable upper bound
}

#[test] 
fn test_loss_detection_with_multiple_spaces() {
    let mut recovery = RecoveryManager::new();
    
    // Send packets in multiple spaces
    let initial_packet = create_initial_packet(0);
    recovery.on_packet_sent(&initial_packet, vec![Frame::Ping]);
    
    let handshake_packet = create_handshake_packet(1);
    recovery.on_packet_sent(&handshake_packet, vec![Frame::Crypto {
        offset: 0,
        data: vec![0u8; 100].into(),
    }]);
    
    let app_packet = create_app_data_packet(2);
    recovery.on_packet_sent(&app_packet, vec![Frame::Stream {
        stream_id: 0.into(),
        offset: 0,
        data: vec![0u8; 100].into(),
        fin: false,
        length: None,
    }]);
    
    // ACK only the application data packet
    let lost_frames = recovery.on_ack_received(
        PacketNumberSpace::ApplicationData,
        2,
        &[(2, 2)],
        Duration::ZERO,
    ).unwrap();
    
    // Should not lose any frames yet (packet threshold not reached)
    assert!(lost_frames.is_empty());
    
    // Bytes in flight should be reduced
    assert!(recovery.bytes_in_flight() < 300); // Less than all 3 packets
}

#[test]
fn test_ack_delay_parameter_setting() {
    let mut recovery = RecoveryManager::new();
    
    // Set ACK delay parameters
    recovery.set_ack_delay_exponent(4); // 2^4 = 16 microseconds
    recovery.set_max_ack_delay(Duration::from_millis(50));
    
    // Parameters should be applied (test basic functionality)
    let pto = recovery.probe_timeout();
    assert!(pto > Duration::ZERO);
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