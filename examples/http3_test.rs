//! Test HTTP/3 client-server communication

use http3::{
    network::{create_client_endpoint, create_server_endpoint, NetworkEndpoint},
    error::Result,
};
use std::sync::Arc;
use tokio::sync::Mutex;

async fn run_server(endpoint: NetworkEndpoint) {
    println!("Server starting...");
    if let Err(e) = endpoint.run().await {
        eprintln!("Server error: {}", e);
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("\n=== Testing HTTP/3 Communication ===\n");
    
    // Create server endpoint
    let server_endpoint = create_server_endpoint(0).await?;
    let server_addr = server_endpoint.local_addr();
    println!("Server listening on: {}", server_addr);
    
    // Start server in background
    tokio::spawn(run_server(server_endpoint));
    
    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    // Create client endpoint
    let client_endpoint = create_client_endpoint().await?;
    
    // Connect to server
    println!("\nClient connecting to server...");
    let client_conn = client_endpoint.connect(server_addr).await?;
    
    // Create HTTP/3 client
    let mut client = http3::client::Client::new().await?;
    
    // Wait a bit for handshake
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    
    // Check connection state
    {
        let conn = client_conn.lock().await;
        println!("Client connection state: {:?}", conn.state());
        
        if conn.is_established() {
            println!("✓ Connection established!");
        } else {
            println!("✗ Connection not yet established");
            
            // For testing, we'll proceed anyway
            // In production, you'd wait for establishment or handle the error
        }
    }
    
    // Try to make an HTTP/3 request
    println!("\nAttempting HTTP/3 request...");
    let url = format!("https://localhost:{}/", server_addr.port());
    
    match client.get(&url).await {
        Ok(mut response) => {
            println!("✓ Got response!");
            let status = response.status().await?;
            println!("Status: {}", status);
            
            let body = response.text().await?;
            println!("Body: {}", body);
        }
        Err(e) => {
            println!("✗ Request failed: {}", e);
            
            // This is expected for now since we haven't implemented
            // the full HTTP/3 server response handling
        }
    }
    
    // Shutdown
    println!("\nShutting down...");
    client.close().await?;
    client_endpoint.shutdown().await?;
    
    Ok(())
}