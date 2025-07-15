//! Tests for RFC 9002 compliant loss recovery implementation

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
fn test_packet_number_space_tracking() {
    let mut recovery = RecoveryManager::new();
    
    // Create test packet for Initial space
    let initial_header = LongHeader::new(
        PacketType::Initial,
        0x00000001,
        ConnectionId::random(8).unwrap(),
        ConnectionId::random(8).unwrap(),
        TypeSpecificData::Initial {
            token: bytes::Bytes::new(),
            length: VarInt::from_u32(0),
            packet_number: 0,
        }
    );
    
    let initial_packet = Packet::new(
        PacketHeader::Long(initial_header),
        vec![0u8; 100].into(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081),
    );
    
    // Track packet in Initial space
    recovery.on_packet_sent(&initial_packet, vec![Frame::Ping]);
    
    // Verify packet is tracked
    assert_eq!(recovery.packets_sent(), 1);
    assert_eq!(recovery.bytes_in_flight(), 100);
}

#[test]
fn test_rtt_estimation_rfc_compliance() {
    let mut recovery = RecoveryManager::new();
    
    // Initial RTT should be 333ms per RFC 9002
    assert_eq!(recovery.rtt(), Duration::from_millis(333));
    
    // Create and send a packet
    let header = ShortHeader::new(
        false,
        false,
        ConnectionId::random(8).unwrap(),
        0,
    );
    
    let packet = Packet::new(
        PacketHeader::Short(header),
        vec![0u8; 100].into(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081),
    );
    
    recovery.on_packet_sent(&packet, vec![Frame::Stream {
        stream_id: 0.into(),
        offset: 0,
        data: vec![0u8; 100].into(),
        fin: false,
        length: None,
    }]);
    
    // Simulate ACK after 100ms
    std::thread::sleep(std::time::Duration::from_millis(100));
    
    let result = recovery.on_ack_received(
        PacketNumberSpace::ApplicationData,
        0,
        &[(0, 0)],
        Duration::from_millis(10), // 10ms ACK delay
    );
    
    assert!(result.is_ok());
    
    // RTT should be updated from initial 333ms
    let new_rtt = recovery.rtt();
    assert!(new_rtt < Duration::from_millis(333));
}

#[test]
fn test_loss_detection_packet_threshold() {
    let mut recovery = RecoveryManager::new();
    
    // Send 5 packets
    for i in 0..5 {
        let header = ShortHeader::new(
            false,
            false,
            ConnectionId::random(8).unwrap(),
            i,
        );
        
        let packet = Packet::new(
            PacketHeader::Short(header),
            vec![0u8; 100].into(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081),
        );
        
        recovery.on_packet_sent(&packet, vec![Frame::Stream {
            stream_id: 0.into(),
            offset: (i * 100) as u64,
            data: vec![0u8; 100].into(),
            fin: false,
            length: None,
        }]);
    }
    
    // ACK packets 3 and 4, which should trigger loss detection for 0-1
    let lost_frames = recovery.on_ack_received(
        PacketNumberSpace::ApplicationData,
        4,
        &[(3, 4)],
        Duration::ZERO,
    ).unwrap();
    
    // Should detect packets 0-1 as lost (packet threshold = 3)
    assert!(!lost_frames.is_empty());
}

#[test]
fn test_probe_timeout_calculation() {
    let recovery = RecoveryManager::new();
    
    // PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
    // Initial: 333ms + max(4*166ms, 1ms) + 25ms = 333 + 664 + 25 = 1022ms
    let pto = recovery.probe_timeout();
    
    // Should be approximately 1022ms
    assert!(pto >= Duration::from_millis(1000));
    assert!(pto <= Duration::from_millis(1100));
}

#[test]
fn test_owasp_security_validation() {
    let mut recovery = RecoveryManager::new();
    
    // Test 1: Too many ACK ranges (DoS protection)
    let mut large_ranges = Vec::new();
    for i in 0..100 {
        large_ranges.push((i * 2, i * 2));
    }
    
    let result = recovery.on_ack_received(
        PacketNumberSpace::ApplicationData,
        200,
        &large_ranges,
        Duration::ZERO,
    );
    
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Too many ACK ranges"));
    
    // Test 2: Invalid ACK range (start > end)
    let result = recovery.on_ack_received(
        PacketNumberSpace::ApplicationData,
        10,
        &[(5, 3)], // Invalid: start > end
        Duration::ZERO,
    );
    
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("Invalid ACK range"));
    
    // Test 3: ACK ranges not in descending order
    let result = recovery.on_ack_received(
        PacketNumberSpace::ApplicationData,
        10,
        &[(5, 6), (7, 8)], // Invalid: not descending
        Duration::ZERO,
    );
    
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not in descending order"));
}

#[test]
fn test_packet_number_space_separation() {
    let mut recovery = RecoveryManager::new();
    
    // Send packets in different spaces
    let spaces = [
        (PacketType::Initial, PacketNumberSpace::Initial),
        (PacketType::Handshake, PacketNumberSpace::Handshake),
        (PacketType::OneRtt, PacketNumberSpace::ApplicationData),
    ];
    
    for (packet_type, pn_space) in spaces {
        let header = if packet_type == PacketType::OneRtt {
            PacketHeader::Short(ShortHeader::new(
                false,
                false,
                ConnectionId::random(8).unwrap(),
                0,
            ))
        } else {
            let type_specific = match packet_type {
                PacketType::Initial => TypeSpecificData::Initial {
                    token: bytes::Bytes::new(),
                    length: VarInt::from_u32(0),
                    packet_number: 0,
                },
                PacketType::Handshake => TypeSpecificData::Handshake {
                    length: VarInt::from_u32(0),
                    packet_number: 0,
                },
                _ => unreachable!(),
            };
            
            PacketHeader::Long(LongHeader::new(
                packet_type,
                0x00000001,
                ConnectionId::random(8).unwrap(),
                ConnectionId::random(8).unwrap(),
                type_specific,
            ))
        };
        
        let packet = Packet::new(
            header,
            vec![0u8; 100].into(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081),
        );
        
        recovery.on_packet_sent(&packet, vec![Frame::Ping]);
        
        // ACK in specific space should only affect that space
        let result = recovery.on_ack_received(
            pn_space,
            0,
            &[(0, 0)],
            Duration::ZERO,
        );
        
        assert!(result.is_ok());
    }
    
    // Should have sent 3 packets total
    assert_eq!(recovery.packets_sent(), 3);
}

#[test]
fn test_ack_delay_handling() {
    let mut recovery = RecoveryManager::new();
    
    // Set ACK delay parameters from transport parameters
    recovery.set_ack_delay_exponent(3); // 2^3 = 8 microseconds
    recovery.set_max_ack_delay(Duration::from_millis(100));
    
    // Send a packet
    let header = ShortHeader::new(
        false,
        false,
        ConnectionId::random(8).unwrap(),
        0,
    );
    
    let packet = Packet::new(
        PacketHeader::Short(header),
        vec![0u8; 100].into(),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081),
    );
    
    recovery.on_packet_sent(&packet, vec![Frame::Stream {
        stream_id: 0.into(),
        offset: 0,
        data: vec![0u8; 100].into(),
        fin: false,
        length: None,
    }]);
    
    // Simulate ACK with delay
    std::thread::sleep(std::time::Duration::from_millis(50));
    
    let result = recovery.on_ack_received(
        PacketNumberSpace::ApplicationData,
        0,
        &[(0, 0)],
        Duration::from_millis(20), // 20ms encoded ACK delay
    );
    
    assert!(result.is_ok());
}