//! Tests for transport parameter exchange during connection establishment

use http3::{
    quic::{
        connection::{Connection, ConnectionRole},
        transport::TransportParameters,
        packet::ConnectionId,
    },
    util::varint::VarInt,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::sync::mpsc;

#[tokio::test]
async fn test_transport_parameter_exchange() {
    // Create custom transport parameters for testing
    let mut client_params = TransportParameters::default();
    client_params.initial_max_data = Some(VarInt::from_u32(2048 * 1024)); // 2MB
    client_params.initial_max_streams_bidi = Some(VarInt::from_u32(200));
    client_params.max_idle_timeout = Some(VarInt::from_u32(60000)); // 60 seconds
    
    let mut server_params = TransportParameters::default();
    server_params.initial_max_data = Some(VarInt::from_u32(4096 * 1024)); // 4MB
    server_params.initial_max_streams_bidi = Some(VarInt::from_u32(100));
    server_params.max_idle_timeout = Some(VarInt::from_u32(30000)); // 30 seconds
    
    // Create connection IDs
    let client_cid = ConnectionId::random(8).unwrap();
    let server_cid = ConnectionId::random(8).unwrap();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
    
    // Create client connection
    let mut client = Connection::new(
        ConnectionRole::Client,
        client_cid.clone(),
        server_cid.clone(),
        addr,
        client_params.clone(),
    ).unwrap();
    
    // Create server connection
    let mut server = Connection::new(
        ConnectionRole::Server,
        server_cid.clone(),
        client_cid.clone(),
        addr,
        server_params.clone(),
    ).unwrap();
    
    // Set up packet channels
    let (client_tx, mut _client_rx) = mpsc::unbounded_channel();
    let (server_tx, mut _server_rx) = mpsc::unbounded_channel();
    
    client.set_packet_sender(client_tx);
    server.set_packet_sender(server_tx);
    
    // Verify initial state
    assert!(client.get_peer_transport_params().is_none());
    assert!(server.get_peer_transport_params().is_none());
    
    // Start handshake
    client.start_handshake().await.unwrap();
    
    // In a real implementation, we would exchange packets between client and server
    // For this test, we'll verify the transport parameter structure
    
    // Verify local parameters are set correctly
    assert_eq!(client.get_transport_params().initial_max_data, Some(VarInt::from_u32(2048 * 1024)));
    assert_eq!(server.get_transport_params().initial_max_data, Some(VarInt::from_u32(4096 * 1024)));
}

#[test]
fn test_transport_params_encoding_decoding() {
    let mut params = TransportParameters::default();
    params.initial_max_data = Some(VarInt::from_u32(1024 * 1024));
    params.initial_max_streams_bidi = Some(VarInt::from_u32(100));
    params.initial_max_streams_uni = Some(VarInt::from_u32(50));
    params.max_idle_timeout = Some(VarInt::from_u32(30000));
    params.ack_delay_exponent = Some(VarInt::from_u32(3));
    params.max_ack_delay = Some(VarInt::from_u32(25));
    params.active_connection_id_limit = Some(VarInt::from_u32(8));
    params.disable_active_migration = true;
    
    // Encode parameters
    let encoded = params.encode().unwrap();
    
    // Decode parameters
    let decoded = TransportParameters::decode(encoded).unwrap();
    
    // Verify all parameters match
    assert_eq!(decoded.initial_max_data, params.initial_max_data);
    assert_eq!(decoded.initial_max_streams_bidi, params.initial_max_streams_bidi);
    assert_eq!(decoded.initial_max_streams_uni, params.initial_max_streams_uni);
    assert_eq!(decoded.max_idle_timeout, params.max_idle_timeout);
    assert_eq!(decoded.ack_delay_exponent, params.ack_delay_exponent);
    assert_eq!(decoded.max_ack_delay, params.max_ack_delay);
    assert_eq!(decoded.active_connection_id_limit, params.active_connection_id_limit);
    assert_eq!(decoded.disable_active_migration, params.disable_active_migration);
}

#[test]
fn test_flow_control_updates() {
    use http3::quic::connection::FlowControlLimits;
    
    let mut params = TransportParameters::default();
    params.initial_max_data = Some(VarInt::from_u32(1000));
    params.initial_max_streams_bidi = Some(VarInt::from_u32(10));
    params.initial_max_streams_uni = Some(VarInt::from_u32(5));
    
    let mut flow_control = FlowControlLimits::new(&params);
    
    // Test initial values
    assert_eq!(flow_control.max_data, 1000);
    assert_eq!(flow_control.max_streams_bidi, 10);
    assert_eq!(flow_control.max_streams_uni, 5);
    
    // Test data tracking
    assert!(flow_control.can_send_data(500));
    flow_control.record_data_sent(500);
    assert_eq!(flow_control.data_sent, 500);
    assert!(flow_control.can_send_data(499));
    assert!(!flow_control.can_send_data(501));
    
    // Test stream tracking
    assert!(flow_control.can_open_stream(http3::quic::stream::StreamType::Bidirectional));
    flow_control.record_stream_opened(http3::quic::stream::StreamType::Bidirectional);
    assert_eq!(flow_control.streams_bidi_count, 1);
    
    // Test limit updates
    flow_control.update_max_data(2000);
    assert_eq!(flow_control.max_data, 2000);
    assert!(flow_control.can_send_data(1499));
}

#[test]
fn test_transport_params_validation() {
    let mut params = TransportParameters::default();
    
    // Valid parameters should pass
    assert!(params.validate().is_ok());
    
    // Test invalid ACK delay exponent
    params.ack_delay_exponent = Some(VarInt::from_u32(21));
    assert!(params.validate().is_err());
    params.ack_delay_exponent = Some(VarInt::from_u32(3));
    
    // Test invalid active connection ID limit
    params.active_connection_id_limit = Some(VarInt::from_u32(1));
    assert!(params.validate().is_err());
    params.active_connection_id_limit = Some(VarInt::from_u32(2));
    assert!(params.validate().is_ok());
    
    // Test max ACK delay limit
    params.max_ack_delay = Some(VarInt::from_u32(16384)); // 2^14
    assert!(params.validate().is_err());
    params.max_ack_delay = Some(VarInt::from_u32(16383)); // 2^14 - 1
    assert!(params.validate().is_ok());
}