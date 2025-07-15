//! Debug handshake to see what's happening

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
    println!("=== Debug Handshake ===\n");
    
    // Simple setup
    let client_cid = ConnectionId::random(8)?;
    let server_cid = ConnectionId::random(8)?;
    let addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let params = TransportParameters::default();
    
    // Create client
    let mut client = Connection::new(
        ConnectionRole::Client,
        client_cid,
        server_cid,
        addr,
        params,
    )?;
    
    // Set up packet sender
    let (tx, mut rx) = mpsc::unbounded_channel();
    client.set_packet_sender(tx);
    
    println!("Starting handshake...");
    client.start_handshake().await?;
    
    // Check for packets
    println!("\nChecking for packets...");
    let mut count = 0;
    while let Ok((packet_data, _)) = rx.try_recv() {
        count += 1;
        println!("Packet {}: {} bytes", count, packet_data.len());
        
        // Show first few bytes
        if packet_data.len() >= 10 {
            println!("  First 10 bytes: {:02x?}", &packet_data[..10]);
        }
    }
    
    if count == 0 {
        println!("No packets generated!");
    } else {
        println!("\nTotal packets: {}", count);
    }
    
    println!("\nClient state: {:?}", client.state());
    
    Ok(())
}