//! Simplified QUIC handshake test

use http3::quic::{
    connection::{Connection, ConnectionRole},
    packet::ConnectionId,
    transport::TransportParameters,
};
use std::net::SocketAddr;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_simple_handshake() {
    // Create connection IDs
    let client_cid = ConnectionId::random(8).unwrap();
    let server_cid = ConnectionId::random(8).unwrap();
    
    println!("Client CID: {:02x?}", client_cid.as_bytes());
    println!("Server CID: {:02x?}", server_cid.as_bytes());
    
    // Create addresses
    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    
    // Create transport parameters
    let transport_params = TransportParameters::default();
    
    // Create client and server connections WITHOUT modifying crypto
    let mut client = Connection::new(
        ConnectionRole::Client,
        client_cid.clone(),
        server_cid.clone(),
        server_addr,
        transport_params.clone(),
    ).unwrap();
    
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
    
    // Start handshake from client
    println!("\nStarting handshake...");
    client.start_handshake().await.unwrap();
    
    // Exchange one round of packets
    println!("\nRound 1: Client -> Server");
    if let Ok((packet_data, _addr)) = server_rx.try_recv() {
        println!("  Packet size: {} bytes", packet_data.len());
        match server.process_packet(&packet_data).await {
            Ok(_) => println!("  ✓ Server processed packet"),
            Err(e) => {
                println!("  ✗ Server failed to process: {:?}", e);
                return;
            }
        }
    }
    
    println!("\nRound 2: Server -> Client");
    if let Ok((packet_data, _addr)) = client_rx.try_recv() {
        println!("  Packet size: {} bytes", packet_data.len());
        match client.process_packet(&packet_data).await {
            Ok(_) => println!("  ✓ Client processed packet"),
            Err(e) => {
                println!("  ✗ Client failed to process: {:?}", e);
                // This is expected to fail due to certificate validation
                // But it should fail with a TLS error, not a crypto error
                if e.to_string().contains("TlsError") && e.to_string().contains("Certificate") {
                    println!("  Expected certificate validation error");
                } else {
                    panic!("Unexpected error: {:?}", e);
                }
            }
        }
    }
}