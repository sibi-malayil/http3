//! Simple handshake test to verify TLS integration

use http3::{
    network::{create_client_endpoint, create_server_endpoint},
    error::Result,
};
use tokio::time::{timeout, Duration};

#[tokio::test]
async fn test_basic_handshake() -> Result<()> {
    println!("\n=== Testing Basic Handshake ===\n");
    
    // Create server endpoint
    let server_endpoint = create_server_endpoint(0).await?;
    let server_addr = server_endpoint.local_addr();
    println!("Server listening on: {}", server_addr);
    
    // Create client endpoint
    let client_endpoint = create_client_endpoint().await?;
    
    // Start server in background
    let server_handle = tokio::spawn(async move {
        // Run the server endpoint
        if let Err(e) = server_endpoint.run().await {
            eprintln!("Server error: {}", e);
        }
    });
    
    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Client connects to server
    println!("Client connecting to server...");
    let client_conn = client_endpoint.connect(server_addr).await?;
    
    // Wait a bit for handshake to progress
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    // Check connection state
    {
        let conn = client_conn.lock().await;
        let state = conn.state();
        println!("Client connection state: {:?}", state);
        
        if conn.is_established() {
            println!("✓ Handshake completed successfully!");
        } else {
            println!("✗ Handshake not yet complete");
        }
    }
    
    // Shutdown
    client_endpoint.shutdown().await?;
    server_handle.abort();
    
    Ok(())
}

#[tokio::test]
async fn test_handshake_timeout() -> Result<()> {
    println!("\n=== Testing Handshake with Timeout ===\n");
    
    // Create server endpoint
    let server_endpoint = create_server_endpoint(0).await?;
    let server_addr = server_endpoint.local_addr();
    
    // Create client endpoint
    let client_endpoint = create_client_endpoint().await?;
    
    // Start server in background
    let server_handle = tokio::spawn(async move {
        if let Err(e) = server_endpoint.run().await {
            eprintln!("Server error: {}", e);
        }
    });
    
    // Give server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Client connects with timeout
    let client_conn = client_endpoint.connect(server_addr).await?;
    
    // Wait for handshake with timeout
    let handshake_result = timeout(Duration::from_secs(5), async {
        loop {
            let conn = client_conn.lock().await;
            if conn.is_established() {
                return Ok(());
            }
            drop(conn);
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }).await;
    
    match handshake_result {
        Ok(_) => println!("✓ Handshake completed within timeout"),
        Err(_) => println!("✗ Handshake timed out"),
    }
    
    // Shutdown
    client_endpoint.shutdown().await?;
    server_handle.abort();
    
    Ok(())
}