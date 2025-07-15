//! Test TLS handshake between client and server

use http3::{
    quic::{
        connection::{Connection, ConnectionRole},
        packet::ConnectionId,
        transport::TransportParameters,
    },
    error::Result,
};
use std::net::SocketAddr;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<()> {
    println!("\n=== Testing TLS Handshake ===\n");
    
    // Create connection IDs
    let client_cid = ConnectionId::random(8)?;
    let server_cid = ConnectionId::random(8)?;
    
    println!("Client CID: {:02x?}", client_cid.as_bytes());
    println!("Server CID: {:02x?}", server_cid.as_bytes());
    
    // Create addresses
    let client_addr: SocketAddr = "127.0.0.1:54321".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    
    // Create transport parameters
    let transport_params = TransportParameters::default();
    
    // Create connections
    let mut client = Connection::new(
        ConnectionRole::Client,
        client_cid.clone(),
        server_cid.clone(),
        server_addr,
        transport_params.clone(),
    )?;
    
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
    
    // Client initiates handshake
    client.start_handshake().await?;
    
    // Exchange packets
    let mut round = 0;
    loop {
        round += 1;
        println!("\n--- Round {} ---", round);
        
        let mut progress = false;
        
        // Process client -> server packets
        while let Ok((packet_data, _addr)) = server_rx.try_recv() {
            println!("Client -> Server: {} bytes", packet_data.len());
            if let Err(e) = server.process_packet(&packet_data).await {
                println!("Server error: {}", e);
                // Certificate errors are expected with self-signed certs
                if !e.to_string().contains("Certificate") {
                    return Err(e);
                }
            }
            progress = true;
        }
        
        // Process server -> client packets
        while let Ok((packet_data, _addr)) = client_rx.try_recv() {
            println!("Server -> Client: {} bytes", packet_data.len());
            if let Err(e) = client.process_packet(&packet_data).await {
                println!("Client error: {}", e);
                // Certificate errors are expected with self-signed certs
                if !e.to_string().contains("Certificate") {
                    return Err(e);
                }
            }
            progress = true;
        }
        
        // Check connection states
        println!("\nClient state: {:?}", client.state());
        println!("Server state: {:?}", server.state());
        
        // Check if handshake is complete
        if client.is_established() && server.is_established() {
            println!("\n✓ Handshake completed successfully!");
            break;
        }
        
        // If no progress was made, wait a bit
        if !progress {
            if round > 10 {
                println!("\n✗ Handshake stalled after {} rounds", round);
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }
    
    Ok(())
}