use http3::{
    client::Client,
    server::Server,
    error::Result,
    certs,
    http3::{Request, Response},
};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(false)
        .init();

    println!("Starting HTTP/3 test with real certificates for cloud-computing.co");

    // Start server in background
    let server_handle = tokio::spawn(async move {
        run_server().await
    });

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Run client
    match run_client().await {
        Ok(_) => println!("Client test completed successfully"),
        Err(e) => eprintln!("Client test failed: {}", e),
    }

    // Shutdown server
    server_handle.abort();

    Ok(())
}

async fn run_server() -> Result<()> {
    println!("Starting server with cloud-computing.co certificates...");

    // Load server certificates
    let cert_path = "certs/server_chain.pem";
    let key_path = "certs/server_pkcs8.key";
    
    let certs = certs::load_certs(cert_path)?;
    let key = certs::load_private_key(key_path)?;
    
    println!("Loaded {} certificates", certs.len());
    println!("Loaded private key");

    // Create server with certificates
    let server = Server::builder()
        .with_certificate(certs, key)?
        .bind("127.0.0.1:4433")
        .await?;

    println!("Server listening on 127.0.0.1:4433");

    // The server needs to start its event loop
    // Since we're using Server directly, we need to run it
    // For now, just keep the server alive
    tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

    Ok(())
}

async fn run_client() -> Result<()> {
    println!("Starting client test...");

    // For testing with self-signed certificates, we need to configure the client
    // to accept them. In production, you would use proper CA-signed certificates.
    
    // Load the server's certificate to use as a custom root
    let cert_path = "certs/server.crt";
    let server_cert = certs::load_certs(cert_path)?;
    
    println!("Loaded server certificate for custom root");

    // Create client with custom certificate validation
    let client = Client::builder()
        .with_custom_roots(server_cert)?
        .build()
        .await?;

    // Connect to server
    println!("Connecting to https://127.0.0.1:4433/");
    let mut conn = client.connect("https://127.0.0.1:4433/").await?;
    
    println!("Client: Connected successfully!");

    // Send request
    let request = Request::builder()
        .method("GET")
        .uri("/")
        .header("host", "cloud-computing.co")
        .body(Vec::new())
        .build()
        .unwrap();

    println!("Client: Sending GET request...");
    let mut response = conn.send_request(request).await?;
    
    println!("Client: Received response:");
    
    // Get headers first
    let headers = response.headers().await?;
    
    // Find status code in headers
    let status = headers.iter()
        .find(|h| h.name.as_bytes() == b":status")
        .map(|h| h.value.as_str().unwrap_or("<binary>"))
        .unwrap_or("Unknown");
    
    println!("  Status: {}", status);
    
    for header in &headers {
        if !header.name.as_bytes().starts_with(b":") {
            println!("  Header: {}: {}", 
                header.name.as_str(),
                header.value.as_str().unwrap_or("<binary>")
            );
        }
    }
    
    // Read body
    let body = response.read_body().await?;
    if !body.is_empty() {
        let body_str = String::from_utf8_lossy(&body);
        println!("  Body: {}", body_str);
    }

    Ok(())
}