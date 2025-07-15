use http3::{
    network::{NetworkEndpoint},
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

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(false)
        .init();

    println!("Starting basic handshake test with test crypto...");

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
    
    // Use test crypto for server (self-signed certificate)
    let mut server_crypto = CryptoManager::new_server_self_signed()?;
    server_crypto.set_connection_ids(server_cid.clone(), client_cid.clone());
    server_crypto.init_initial_keys(server_cid.as_bytes())?;
    server_conn.set_crypto_manager(server_crypto);
    server_conn.set_packet_sender(server_to_client_tx);

    // Create client connection
    println!("Creating client connection...");
    let mut client_conn = Connection::new(
        ConnectionRole::Client,
        client_cid.clone(),
        server_cid.clone(),
        "127.0.0.1:4433".parse().unwrap(),
        TransportParameters::default(),
    )?;
    
    // Use test crypto for client (accepts any certificate)
    let mut client_crypto = CryptoManager::new_client_for_testing("localhost")?;
    client_crypto.set_connection_ids(client_cid.clone(), server_cid.clone());
    client_crypto.init_initial_keys(server_cid.as_bytes())?;
    client_conn.set_crypto_manager(client_crypto);
    client_conn.set_packet_sender(client_to_server_tx);

    // Start handshake on client
    println!("Starting client handshake...");
    client_conn.start_handshake().await?;

    // Exchange packets
    let server_conn = Arc::new(Mutex::new(server_conn));
    let client_conn = Arc::new(Mutex::new(client_conn));
    
    // Process packets in both directions
    let server_conn_clone = server_conn.clone();
    let server_handle = tokio::spawn(async move {
        while let Some((packet_data, _addr)) = client_to_server_rx.recv().await {
            println!("Server received packet: {} bytes", packet_data.len());
            let mut conn = server_conn_clone.lock().await;
            if let Err(e) = conn.process_packet(&packet_data).await {
                eprintln!("Server error processing packet: {}", e);
            }
            if conn.is_established() {
                println!("Server: Connection established!");
                break;
            }
        }
    });

    let client_conn_clone = client_conn.clone();
    let client_handle = tokio::spawn(async move {
        while let Some((packet_data, _addr)) = server_to_client_rx.recv().await {
            println!("Client received packet: {} bytes", packet_data.len());
            let mut conn = client_conn_clone.lock().await;
            if let Err(e) = conn.process_packet(&packet_data).await {
                eprintln!("Client error processing packet: {}", e);
            }
            if conn.is_established() {
                println!("Client: Connection established!");
                break;
            }
        }
    });

    // Wait for handshake to complete or timeout
    let timeout = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        futures::future::join(server_handle, client_handle)
    ).await;

    match timeout {
        Ok(_) => {
            println!("Handshake completed!");
            
            // Check final states
            let server = server_conn.lock().await;
            let client = client_conn.lock().await;
            
            println!("Server established: {}", server.is_established());
            println!("Client established: {}", client.is_established());
        }
        Err(_) => {
            println!("Handshake timed out after 5 seconds");
            
            // Check states
            let server = server_conn.lock().await;
            let client = client_conn.lock().await;
            
            println!("Server state: {:?}", server.state());
            println!("Client state: {:?}", client.state());
        }
    }

    Ok(())
}