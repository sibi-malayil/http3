//! Integration tests for QUIC version negotiation
//!
//! Tests version negotiation between client and server per RFC 9000 Section 6

use http3::{
    quic::{
        connection::{Connection, ConnectionRole},
        packet::ConnectionId,
        version::{VersionNegotiationPacket, VersionConfig, VersionNegotiator, VERSION_NEGOTIATION},
        transport::TransportParameters,
        VERSION_1,
    },
    error::Error,
};
use bytes::BytesMut;
use std::net::SocketAddr;
use tokio::sync::mpsc;

/// Create test transport parameters
fn test_transport_params() -> TransportParameters {
    use http3::util::varint::VarInt;
    
    TransportParameters {
        initial_max_stream_data_bidi_local: Some(VarInt::from_u32(65536)),
        initial_max_stream_data_bidi_remote: Some(VarInt::from_u32(65536)),
        initial_max_stream_data_uni: Some(VarInt::from_u32(65536)),
        initial_max_data: Some(VarInt::from_u32(1048576)),
        initial_max_streams_bidi: Some(VarInt::from_u32(100)),
        initial_max_streams_uni: Some(VarInt::from_u32(100)),
        max_idle_timeout: Some(VarInt::from_u32(30000)),
        ..Default::default()
    }
}

#[tokio::test]
async fn test_version_negotiation_packet_encoding() {
    let dst_cid = ConnectionId::from_slice(b"client");
    let src_cid = ConnectionId::from_slice(b"server");
    let supported_versions = vec![VERSION_1, 0x6b3343cf, 0xff00001d];
    
    let packet = VersionNegotiationPacket::new(
        dst_cid.clone(),
        src_cid.clone(),
        supported_versions.clone(),
    );
    
    let mut buf = BytesMut::new();
    packet.encode(&mut buf).unwrap();
    
    // Verify packet structure
    assert!(buf.len() > 0);
    assert_eq!(buf[0] & 0x80, 0x80); // Fixed bit set
    assert_eq!(&buf[1..5], &[0, 0, 0, 0]); // Version field is 0
    
    // Decode and verify
    let decoded = VersionNegotiationPacket::decode(&buf).unwrap();
    assert_eq!(decoded.dst_cid, dst_cid);
    assert_eq!(decoded.src_cid, src_cid);
    assert_eq!(decoded.supported_versions, supported_versions);
}

#[tokio::test]
async fn test_version_negotiator_selection() {
    let config = VersionConfig {
        supported_versions: vec![VERSION_1, 0x6b3343cf],
        enable_version_negotiation: true,
        enable_compatible_negotiation: true,
        preferred_version: VERSION_1,
    };
    
    let negotiator = VersionNegotiator::new(config);
    
    // Test supported version
    assert!(negotiator.is_supported(VERSION_1));
    assert!(negotiator.is_supported(0x6b3343cf));
    assert!(!negotiator.is_supported(0x12345678));
    
    // Test version selection
    assert_eq!(negotiator.select_version(VERSION_1), Some(VERSION_1));
    assert_eq!(negotiator.select_version(0x6b3343cf), Some(0x6b3343cf));
    assert_eq!(negotiator.select_version(0x12345678), None);
    
    // Test draft version mapping
    assert_eq!(negotiator.select_version(0xff00001d), Some(VERSION_1)); // draft-29
}

#[tokio::test]
async fn test_server_sends_version_negotiation() {
    let local_cid = ConnectionId::random();
    let remote_cid = ConnectionId::random();
    let remote_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    
    let mut server = Connection::new(
        ConnectionRole::Server,
        local_cid.clone(),
        remote_cid.clone(),
        remote_addr,
        test_transport_params(),
    ).unwrap();
    
    // Create channel for packet transmission
    let (tx, mut rx) = mpsc::unbounded_channel();
    server.set_packet_sender(tx);
    
    // Test unsupported version
    let unsupported_version = 0x12345678;
    assert!(server.needs_version_negotiation(unsupported_version));
    
    // Create version negotiation packet
    let vn_packet = server.create_version_negotiation_packet(
        remote_cid.clone(),
        local_cid.clone(),
    );
    
    // Encode and verify
    let mut buf = BytesMut::new();
    vn_packet.encode(&mut buf).unwrap();
    
    assert_eq!(&buf[1..5], &[0, 0, 0, 0]); // Version field
    assert!(vn_packet.supported_versions.contains(&VERSION_1));
}

#[tokio::test]
async fn test_client_handles_version_negotiation() {
    let local_cid = ConnectionId::random();
    let remote_cid = ConnectionId::random();
    let remote_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    
    let mut client = Connection::new(
        ConnectionRole::Client,
        local_cid.clone(),
        remote_cid.clone(),
        remote_addr,
        test_transport_params(),
    ).unwrap();
    
    // Create version negotiation packet from server
    let vn_packet = VersionNegotiationPacket::new(
        local_cid.clone(),
        remote_cid.clone(),
        vec![VERSION_1, 0x6b3343cf],
    );
    
    // Initial version
    let initial_version = client.quic_version();
    
    // Handle version negotiation
    client.handle_version_negotiation(&vn_packet).await.unwrap();
    
    // Version should remain the same if already supported
    if initial_version == VERSION_1 {
        assert_eq!(client.quic_version(), VERSION_1);
    }
}

#[tokio::test]
async fn test_version_negotiation_with_unknown_versions() {
    let dst_cid = ConnectionId::from_slice(b"client");
    let src_cid = ConnectionId::from_slice(b"server");
    
    // Server supports only unknown versions
    let vn_packet = VersionNegotiationPacket::new(
        dst_cid,
        src_cid,
        vec![0xaaaaaaaa, 0xbbbbbbbb],
    );
    
    let config = VersionConfig::default();
    let negotiator = VersionNegotiator::new(config);
    
    // Should fail to find compatible version
    let result = negotiator.handle_version_negotiation(&vn_packet);
    assert!(matches!(result, Err(Error::VersionNegotiation)));
}

#[tokio::test]
async fn test_compatible_version_negotiation() {
    use http3::quic::version::CompatibleVersions;
    
    let compat = CompatibleVersions {
        chosen_version: VERSION_1,
        other_versions: vec![0x6b3343cf, 0x709a50c4],
    };
    
    let mut buf = BytesMut::new();
    compat.encode(&mut buf).unwrap();
    
    let decoded = CompatibleVersions::decode(&buf).unwrap();
    assert_eq!(decoded.chosen_version, VERSION_1);
    assert_eq!(decoded.other_versions.len(), 2);
    assert_eq!(decoded.other_versions[0], 0x6b3343cf);
    assert_eq!(decoded.other_versions[1], 0x709a50c4);
}

#[tokio::test]
async fn test_version_negotiation_in_packet_processing() {
    let local_cid = ConnectionId::random();
    let remote_cid = ConnectionId::random();
    let remote_addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    
    let mut client = Connection::new(
        ConnectionRole::Client,
        local_cid.clone(),
        remote_cid.clone(),
        remote_addr,
        test_transport_params(),
    ).unwrap();
    
    // Create version negotiation packet
    let vn_packet = VersionNegotiationPacket::new(
        local_cid.clone(),
        remote_cid.clone(),
        vec![VERSION_1],
    );
    
    let mut packet_data = BytesMut::new();
    vn_packet.encode(&mut packet_data).unwrap();
    
    // Process the version negotiation packet
    let result = client.process_packet(&packet_data).await;
    assert!(result.is_ok());
}

#[test]
fn test_version_constants() {
    assert_eq!(VERSION_1, 0x00000001);
    assert_eq!(VERSION_NEGOTIATION, 0x00000000);
    
    // Check supported versions include v1
    let config = VersionConfig::default();
    assert!(config.supported_versions.contains(&VERSION_1));
    assert_eq!(config.preferred_version, VERSION_1);
}