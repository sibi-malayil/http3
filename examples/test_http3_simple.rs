//! Simple HTTP/3 test that bypasses certificate validation

use http3::{
    quic::{
        connection::{Connection, ConnectionRole},
        packet::ConnectionId,
        transport::TransportParameters,
        crypto_impl::CryptoManager,
    },
    error::Result,
};
use std::net::SocketAddr;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<()> {
    println!("\n=== Simple HTTP/3 Test ===\n");
    
    // Create connection IDs
    let client_cid = ConnectionId::random(8)?;
    let server_cid = ConnectionId::random(8)?;
    
    // Create addresses
    let client_addr: SocketAddr = "127.0.0.1:54321".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    
    // Create transport parameters
    let transport_params = TransportParameters::default();
    
    // Create connections with custom crypto managers
    println!("Creating client connection...");
    let mut client = {
        let mut conn = Connection::new(
            ConnectionRole::Client,
            client_cid.clone(),
            server_cid.clone(),
            server_addr,
            transport_params.clone(),
        )?;
        
        // Replace crypto manager with testing version
        let mut crypto = CryptoManager::new_client_for_testing("localhost")?;
        // Set connection IDs
        crypto.set_connection_ids(client_cid.clone(), server_cid.clone());
        // Re-initialize initial keys after replacing crypto manager
        crypto.init_initial_keys(server_cid.as_bytes())?;
        conn.set_crypto_manager(crypto);
        conn
    };
    
    println!("Creating server connection...");
    let mut server = Connection::new(
        ConnectionRole::Server,
        server_cid.clone(),
        client_cid.clone(),
        client_addr,
        transport_params.clone(),
    )?;
    
    // Create channels for packet exchange
    let (client_tx, mut server_rx) = mpsc::unbounded_channel();
    let (server_tx, mut client_rx) = mpsc::unbounded_channel();
    
    client.set_packet_sender(client_tx);
    server.set_packet_sender(server_tx);
    
    println!("\nStarting handshake...");
    client.start_handshake().await?;
    
    // Exchange packets until handshake completes
    let mut round = 0;
    loop {
        round += 1;
        if round > 20 {
            println!("\n✗ Handshake timeout");
            break;
        }
        
        let mut progress = false;
        
        // Process client -> server
        while let Ok((packet_data, _)) = server_rx.try_recv() {
            println!("→ Client to Server: {} bytes", packet_data.len());
            if let Err(e) = server.process_packet(&packet_data).await {
                println!("Server error processing packet: {}", e);
                // Don't return immediately - this might be expected during handshake
                // return Err(e);
            }
            progress = true;
        }
        
        // Process server -> client
        while let Ok((packet_data, _)) = client_rx.try_recv() {
            println!("← Server to Client: {} bytes", packet_data.len());
            if let Err(e) = client.process_packet(&packet_data).await {
                println!("Client error processing packet: {}", e);
                // Don't return immediately - this might be expected during handshake
                // return Err(e);
            }
            progress = true;
        }
        
        // Check if both are established
        if client.is_established() && server.is_established() {
            println!("\n✓ Handshake complete!");
            break;
        }
        
        if !progress {
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
    }
    
    // Now test sending data
    if client.is_established() {
        println!("\nTesting stream creation...");
        
        // Open a bidirectional stream
        let stream_id = client.create_stream(http3::quic::stream::StreamType::Bidirectional)?;
        println!("Created stream: {:?}", stream_id);
        
        // Send some data
        let test_data = b"Hello, HTTP/3!";
        println!("Sending data: {:?}", std::str::from_utf8(test_data).unwrap());
        client.stream_send(stream_id, test_data.to_vec().into(), false).await?;
        
        // Process the packet
        while let Ok((packet_data, _)) = server_rx.try_recv() {
            println!("→ Data packet: {} bytes", packet_data.len());
            server.process_packet(&packet_data).await?;
        }
        
        println!("\n✓ Data sent successfully!");
    }
    
    Ok(())
}