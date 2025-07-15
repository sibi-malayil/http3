use http3::{
    quic::{
        connection::{Connection, ConnectionRole},
        packet::ConnectionId,
        transport::TransportParameters,
        crypto_impl::CryptoManager,
    },
    error::Result,
};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    unsafe {
        std::env::set_var("RUST_LOG", "debug");
    }
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_target(true)
        .init();

    println!("Starting handshake debug test...");

    // Create channels for packet exchange
    let (client_to_server_tx, mut client_to_server_rx) = mpsc::unbounded_channel();
    let (server_to_client_tx, mut server_to_client_rx) = mpsc::unbounded_channel();

    // Create server connection
    let server_cid = ConnectionId::random(8)?;
    let client_cid = ConnectionId::random(8)?;
    
    println!("Creating server connection...");
    let mut server_conn = Connection::new(
        ConnectionRole::Server,
        server_cid.clone(),
        client_cid.clone(),
        "127.0.0.1:12345".parse().unwrap(),
        TransportParameters::default(),
    )?;
    
    // Use test crypto for server
    let mut server_crypto = CryptoManager::new_server_self_signed()?;
    server_crypto.set_connection_ids(server_cid.clone(), client_cid.clone());
    server_crypto.init_initial_keys(server_cid.as_bytes())?;
    server_conn.set_crypto_manager(server_crypto);
    server_conn.set_packet_sender(server_to_client_tx.clone());

    // Create client connection
    println!("Creating client connection...");
    let mut client_conn = Connection::new(
        ConnectionRole::Client,
        client_cid.clone(),
        server_cid.clone(),
        "127.0.0.1:4433".parse().unwrap(),
        TransportParameters::default(),
    )?;
    
    // Use test crypto for client
    let mut client_crypto = CryptoManager::new_client_for_testing("localhost")?;
    client_crypto.set_connection_ids(client_cid.clone(), server_cid.clone());
    client_crypto.init_initial_keys(server_cid.as_bytes())?;
    client_conn.set_crypto_manager(client_crypto);
    client_conn.set_packet_sender(client_to_server_tx);

    // Start handshake on client
    println!("Starting client handshake...");
    client_conn.start_handshake().await?;

    // Exchange packets with detailed logging
    let server_conn = Arc::new(Mutex::new(server_conn));
    let client_conn = Arc::new(Mutex::new(client_conn));
    
    let mut server_established = false;
    let mut client_established = false;
    let mut round = 0;
    
    // Process packets for up to 10 rounds
    while round < 10 && (!server_established || !client_established) {
        round += 1;
        println!("\n=== Round {} ===", round);
        
        // Server processes client packets
        let mut packets_processed = 0;
        while let Ok((packet_data, _addr)) = client_to_server_rx.try_recv() {
            println!("Server received packet: {} bytes", packet_data.len());
            let mut conn = server_conn.lock().await;
            let prev_state = conn.state();
            let was_handshaking = matches!(prev_state, http3::quic::connection::ConnectionState::Handshaking);
            
            if let Err(e) = conn.process_packet(&packet_data).await {
                eprintln!("Server error processing packet: {}", e);
            }
            
            let is_established = conn.is_established();
            if !was_handshaking && matches!(conn.state(), http3::quic::connection::ConnectionState::Handshaking) {
                println!(">>> Server transitioned from {:?} to Handshaking", prev_state);
            }
            if was_handshaking && is_established {
                println!(">>> Server just transitioned to Established!");
                // The HANDSHAKE_DONE frame should be sent automatically
            }
            
            server_established = is_established;
            packets_processed += 1;
        }
        if packets_processed > 0 {
            println!("Server processed {} packets, state: {:?}", packets_processed, {
                let conn = server_conn.lock().await;
                conn.state()
            });
        }
        
        // Give server time to send packets
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        // Client processes server packets
        packets_processed = 0;
        while let Ok((packet_data, _addr)) = server_to_client_rx.try_recv() {
            println!("Client received packet: {} bytes", packet_data.len());
            let mut conn = client_conn.lock().await;
            
            if let Err(e) = conn.process_packet(&packet_data).await {
                eprintln!("Client error processing packet: {}", e);
            }
            
            client_established = conn.is_established();
            packets_processed += 1;
        }
        if packets_processed > 0 {
            println!("Client processed {} packets, state: {:?}", packets_processed, {
                let conn = client_conn.lock().await;
                conn.state()
            });
        }
        
        // Give client time to send packets
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    
    // Final check
    println!("\n=== Final Status ===");
    {
        let server = server_conn.lock().await;
        let client = client_conn.lock().await;
        
        println!("Server state: {:?}, established: {}", server.state(), server.is_established());
        println!("Client state: {:?}, established: {}", client.state(), client.is_established());
        
        if server.is_established() && client.is_established() {
            println!("\n✅ Handshake completed successfully!");
        } else {
            println!("\n❌ Handshake did not complete");
        }
    }

    Ok(())
}