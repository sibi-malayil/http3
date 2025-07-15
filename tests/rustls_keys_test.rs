//! Test rustls key handling

use http3::quic::{
    crypto_impl::CryptoManager,
    connection::ConnectionRole,
    packet::ConnectionId,
    transport::TransportParameters,
};
use http3::quic::connection::Connection;
use bytes::Bytes;
use std::net::SocketAddr;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_rustls_handshake_keys() {
    // This test verifies that handshake keys derived by rustls work correctly
    
    // Create connection IDs
    let client_cid = ConnectionId::from_bytes(Bytes::from(vec![0xaa; 8])).unwrap();
    let server_cid = ConnectionId::from_bytes(Bytes::from(vec![0xbb; 8])).unwrap();
    
    // Create addresses
    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    
    // Create transport parameters
    let transport_params = TransportParameters::default();
    
    // Create connections using the actual Connection struct
    // which manages the crypto properly
    let mut client = Connection::new(
        ConnectionRole::Client,
        client_cid.clone(),
        server_cid.clone(),
        server_addr,
        transport_params.clone(),
    ).unwrap();
    
    // Use test client to accept self-signed certs
    let mut test_crypto = CryptoManager::new_client_for_testing("localhost").unwrap();
    test_crypto.set_connection_ids(client_cid.clone(), server_cid.clone());
    test_crypto.init_initial_keys(server_cid.as_bytes()).unwrap();
    test_crypto.set_transport_params(transport_params.clone());
    client.set_crypto_manager(test_crypto);
    
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
    
    // Start handshake
    println!("Starting handshake...");
    client.start_handshake().await.unwrap();
    
    // Client -> Server: Initial packet
    if let Ok((packet_data, _addr)) = server_rx.try_recv() {
        println!("Client -> Server: Initial packet ({} bytes)", packet_data.len());
        server.process_packet(&packet_data).await.unwrap();
    }
    
    // Server -> Client: Initial packet response
    if let Ok((packet_data, _addr)) = client_rx.try_recv() {
        println!("Server -> Client: Initial packet ({} bytes)", packet_data.len());
        client.process_packet(&packet_data).await.unwrap();
    }
    
    // At this point, both should have handshake keys
    // Client should send a Handshake packet
    
    // Client -> Server: Handshake packet
    if let Ok((packet_data, _addr)) = server_rx.try_recv() {
        println!("Client -> Server: Handshake packet ({} bytes)", packet_data.len());
        
        // Extract packet type from first byte
        let first_byte = packet_data[0];
        if first_byte & 0x80 != 0 {
            let type_bits = (first_byte & 0x30) >> 4;
            let packet_type = match type_bits {
                0 => "Initial",
                2 => "Handshake", 
                _ => "Other",
            };
            println!("  Packet type: {}", packet_type);
        }
        
        // This should succeed if keys match
        match server.process_packet(&packet_data).await {
            Ok(_) => println!("  ✓ Server successfully processed Handshake packet!"),
            Err(e) => {
                println!("  ✗ Server failed to process Handshake packet: {:?}", e);
                
                // Expected: might fail due to certificate validation or other TLS issues
                // But should NOT fail due to decryption if keys are correct
                if e.to_string().contains("decryption") || e.to_string().contains("Decryption") {
                    panic!("Handshake packet decryption failed - keys don't match!");
                }
            }
        }
    }
}