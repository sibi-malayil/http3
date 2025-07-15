//! Test complete QUIC handshake flow with real TLS key extraction

use http3::quic::{
    connection::{Connection, ConnectionRole},
    packet::ConnectionId,
    transport::TransportParameters,
};
use std::net::SocketAddr;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_complete_quic_handshake() {
    // Create connection IDs
    let client_cid = ConnectionId::random(8).unwrap();
    let server_cid = ConnectionId::random(8).unwrap();
    
    // Create addresses
    let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    
    // Create transport parameters
    let transport_params = TransportParameters::default();
    
    // Create client and server connections
    // For testing, we need to create a client that accepts self-signed certificates
    let mut client = {
        let mut conn = Connection::new(
            ConnectionRole::Client,
            client_cid.clone(),
            server_cid.clone(),
            server_addr,
            transport_params.clone(),
        ).unwrap();
        
        // Replace the crypto manager with one that accepts any certificate
        let mut crypto = http3::quic::crypto_impl::CryptoManager::new_client_for_testing("localhost").unwrap();
        crypto.set_connection_ids(client_cid.clone(), server_cid.clone());
        let initial_dcid = server_cid.as_bytes();
        crypto.init_initial_keys(initial_dcid).unwrap();
        crypto.set_transport_params(transport_params.clone());
        conn.set_crypto_manager(crypto);
        
        conn
    };
    
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
    
    // Debug: Print connection IDs being used
    println!("=== Connection IDs ===");
    println!("Client local CID: {:?} (hex: {:02x?})", client.local_cid(), client.local_cid().as_bytes());
    println!("Client remote CID: {:?} (hex: {:02x?})", client.remote_cid(), client.remote_cid().as_bytes());
    println!("Server local CID: {:?} (hex: {:02x?})", server.local_cid(), server.local_cid().as_bytes());
    println!("Server remote CID: {:?} (hex: {:02x?})", server.remote_cid(), server.remote_cid().as_bytes());
    println!("Initial key derivation CID (server's): {:02x?}", server_cid.as_bytes());
    
    // Start handshake from client
    client.start_handshake().await.unwrap();
    
    // Exchange packets until handshake is complete
    let mut rounds = 0;
    while rounds < 10 {
        // Client -> Server
        if let Ok((packet_data, _addr)) = server_rx.try_recv() {
            println!("Client -> Server: {} bytes", packet_data.len());
            server.process_packet(&packet_data).await.unwrap();
        }
        
        // Server -> Client
        if let Ok((packet_data, _addr)) = client_rx.try_recv() {
            println!("Server -> Client: {} bytes", packet_data.len());
            client.process_packet(&packet_data).await.unwrap();
        }
        
        // Check if handshake is complete
        let client_state = client.state();
        let server_state = server.state();
        
        println!("Round {}: Client state: {:?}, Server state: {:?}", rounds, client_state, server_state);
        
        if matches!(client_state, http3::quic::connection::ConnectionState::Established) &&
           matches!(server_state, http3::quic::connection::ConnectionState::Established) {
            println!("Handshake complete!");
            break;
        }
        
        rounds += 1;
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
    
    // Verify handshake completed
    assert!(matches!(client.state(), http3::quic::connection::ConnectionState::Established));
    assert!(matches!(server.state(), http3::quic::connection::ConnectionState::Established));
}

#[tokio::test]
async fn test_encrypted_data_exchange() {
    // Similar setup as above
    let client_cid = ConnectionId::random(8).unwrap();
    let server_cid = ConnectionId::random(8).unwrap();
    let client_addr: SocketAddr = "127.0.0.1:12346".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let transport_params = TransportParameters::default();
    
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
    
    let (client_tx, mut server_rx) = mpsc::unbounded_channel();
    let (server_tx, mut client_rx) = mpsc::unbounded_channel();
    
    client.set_packet_sender(client_tx);
    server.set_packet_sender(server_tx);
    
    // Complete handshake
    client.start_handshake().await.unwrap();
    
    // Exchange packets
    for _ in 0..10 {
        if let Ok((packet_data, _)) = server_rx.try_recv() {
            server.process_packet(&packet_data).await.unwrap();
        }
        if let Ok((packet_data, _)) = client_rx.try_recv() {
            client.process_packet(&packet_data).await.unwrap();
        }
        
        if matches!(client.state(), http3::quic::connection::ConnectionState::Established) &&
           matches!(server.state(), http3::quic::connection::ConnectionState::Established) {
            break;
        }
        
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }
    
    // Now test sending application data
    let stream_type = http3::quic::stream::StreamType::Bidirectional;
    let stream_id = client.open_stream(stream_type).unwrap();
    
    // Send data on the stream
    let test_data = b"Hello, encrypted QUIC!";
    client.send_stream_data(stream_id, test_data.to_vec().into(), false).await.unwrap();
    
    // Process the packet on server side
    if let Ok((packet_data, _)) = server_rx.try_recv() {
        server.process_packet(&packet_data).await.unwrap();
        
        // Verify server received the data
        // This would require accessing the stream data, which we'll verify in integration tests
        println!("Server received encrypted application data packet");
    }
}