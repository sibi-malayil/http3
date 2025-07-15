//! QUIC Handshake Integration Tests

use http3::{
    quic::{
        connection::{Connection, ConnectionRole},
        packet::ConnectionId,
        transport::TransportParameters,
    },
};
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use tokio::sync::mpsc;

#[tokio::test]
async fn test_basic_handshake() {
    // Create connection IDs
    let client_cid = ConnectionId::random(8).unwrap();
    let server_cid = ConnectionId::random(8).unwrap();
    
    // Create addresses
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
    let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8081);
    
    // Create transport parameters
    let transport_params = TransportParameters::default();
    
    // Create client connection
    let mut client = Connection::new(
        ConnectionRole::Client,
        client_cid.clone(),
        server_cid.clone(),
        server_addr,
        transport_params.clone(),
    ).unwrap();
    
    // Create server connection
    let mut server = Connection::new(
        ConnectionRole::Server,
        server_cid.clone(),
        client_cid.clone(),
        client_addr,
        transport_params.clone(),
    ).unwrap();
    
    // Create channels for packet exchange
    let (client_tx, mut server_rx) = mpsc::unbounded_channel();
    let (server_tx, mut client_rx) = mpsc::unbounded_channel();
    
    client.set_packet_sender(client_tx);
    server.set_packet_sender(server_tx);
    
    // Start client handshake
    client.start_handshake().await.unwrap();
    
    // Exchange packets until handshake completes
    let mut handshake_complete = false;
    let mut iterations = 0;
    
    while !handshake_complete && iterations < 10 {
        iterations += 1;
        
        // Process client->server packets
        while let Ok((packet_data, _addr)) = server_rx.try_recv() {
            server.process_packet(&packet_data).await.unwrap();
        }
        
        // Process server->client packets  
        while let Ok((packet_data, _addr)) = client_rx.try_recv() {
            client.process_packet(&packet_data).await.unwrap();
        }
        
        // Check if handshake is complete
        let client_state = client.state();
        let server_state = server.state();
        
        handshake_complete = matches!(client_state, http3::quic::connection::ConnectionState::Established) &&
                           matches!(server_state, http3::quic::connection::ConnectionState::Established);
        
        // Give some time for async operations
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
    
    assert!(handshake_complete, "Handshake should complete within reasonable iterations");
}

#[tokio::test]
async fn test_connection_state_transitions() {
    let client_cid = ConnectionId::random(8).unwrap();
    let server_cid = ConnectionId::random(8).unwrap();
    let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
    let transport_params = TransportParameters::default();
    
    let mut connection = Connection::new(
        ConnectionRole::Client,
        client_cid,
        server_cid,
        server_addr,
        transport_params,
    ).unwrap();
    
    // Initial state should be Initial
    assert!(matches!(
        connection.state(),
        http3::quic::connection::ConnectionState::Initial
    ));
    
    // After starting handshake, should be Handshaking
    let (tx, _rx) = mpsc::unbounded_channel();
    connection.set_packet_sender(tx);
    connection.start_handshake().await.unwrap();
    
    assert!(matches!(
        connection.state(),
        http3::quic::connection::ConnectionState::Handshaking
    ));
}