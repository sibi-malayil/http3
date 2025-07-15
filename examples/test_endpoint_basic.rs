use http3::{
    network::{NetworkEndpoint, create_client_endpoint, create_server_endpoint},
    quic::connection::ConnectionRole,
    error::Result,
};
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(false)
        .init();

    println!("Starting basic endpoint test...");

    // Create server endpoint
    let server_endpoint = Arc::new(create_server_endpoint(4433).await?);
    println!("Server endpoint created on port 4433");

    // Start server endpoint event loop
    let server_endpoint_clone = server_endpoint.clone();
    let server_handle = tokio::spawn(async move {
        println!("Server endpoint starting event loop...");
        if let Err(e) = server_endpoint_clone.run().await {
            eprintln!("Server endpoint error: {}", e);
        }
    });

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Create client endpoint
    let client_endpoint = Arc::new(create_client_endpoint().await?);
    println!("Client endpoint created");

    // Start client endpoint event loop
    let client_endpoint_clone = client_endpoint.clone();
    let client_handle = tokio::spawn(async move {
        println!("Client endpoint starting event loop...");
        if let Err(e) = client_endpoint_clone.run().await {
            eprintln!("Client endpoint error: {}", e);
        }
    });

    // Give client endpoint time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Try to connect
    println!("Client connecting to server...");
    let server_addr = "127.0.0.1:4433".parse().unwrap();
    let client_conn = client_endpoint.connect(server_addr).await?;
    
    println!("Client connection created, waiting for handshake...");
    
    // Check connection state
    for i in 0..50 {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let conn = client_conn.lock().await;
        if conn.is_established() {
            println!("Connection established after {} ms!", (i + 1) * 100);
            break;
        }
        if i == 49 {
            println!("Connection failed to establish after 5 seconds");
        }
    }

    // Give some time to see if packets are being exchanged
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Shutdown
    println!("Shutting down...");
    server_handle.abort();
    client_handle.abort();

    Ok(())
}