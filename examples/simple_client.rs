//! Simple HTTP/3 client example

use http3::client::Client;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    #[cfg(feature = "logging")]
    tracing_subscriber::fmt::init();

    println!("HTTP/3 Client Example");
    println!("====================");

    // Create a new HTTP/3 client
    let mut client = Client::new().await?;

    // Example URL (would connect to a real HTTP/3 server)
    let url = "https://example.com/";

    println!("Connecting to {}...", url);

    // Make a GET request
    match client.get(url).await {
        Ok(mut response) => {
            println!("Response received!");
            
            // Get status
            let status = response.status().await?;
            println!("Status: {}", status);
            
            // Read response body
            let body = response.text().await?;
            println!("Body: {}", body);
        }
        Err(e) => {
            println!("Request failed: {}", e);
        }
    }

    // Close the client
    client.close().await?;

    Ok(())
}