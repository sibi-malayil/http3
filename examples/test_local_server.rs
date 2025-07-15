//! Test client for local HTTP/3 server

use http3::client::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    #[cfg(feature = "logging")]
    tracing_subscriber::fmt::init();

    println!("HTTP/3 Test Client");
    println!("==================");

    // Create a new HTTP/3 client
    let mut client = Client::new().await?;

    // Connect to local server
    let url = "https://127.0.0.1:8443/";

    println!("Connecting to local server at {}...", url);

    // Make a GET request
    match client.get(url).await {
        Ok(mut response) => {
            println!("Response received!");
            
            // Check status
            if response.is_success().await? {
                println!("Status: Success");
                
                // Read response body
                let body = response.text().await?;
                println!("Body: {}", body);
            } else {
                let status = response.status().await?;
                println!("Error status: {}", status);
            }
        }
        Err(e) => {
            println!("Request failed: {}", e);
        }
    }

    // Close the client
    client.close().await?;

    Ok(())
}