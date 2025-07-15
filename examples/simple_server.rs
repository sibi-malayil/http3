//! Simple HTTP/3 server example

use http3::server::{Server, Request, Response, RequestHandler};
use std::sync::Arc;

/// Simple echo handler
struct EchoHandler;

#[async_trait::async_trait]
impl RequestHandler for EchoHandler {
    async fn handle(&self, request: Request) -> http3::Result<Response> {
        println!("Request: {} {}", request.method, request.path);
        
        match request.path.as_str() {
            "/" => Ok(Response::ok()
                .with_header("content-type", "text/html")
                .with_body(bytes::Bytes::from_static(b"<h1>Welcome to HTTP/3!</h1>"))),
            
            "/echo" => {
                if let Some(body) = request.body {
                    Ok(Response::ok()
                        .with_header("content-type", "text/plain")
                        .with_body(body))
                } else {
                    Ok(Response::ok()
                        .with_body(bytes::Bytes::from_static(b"No body to echo")))
                }
            }
            
            "/status" => Ok(Response::ok()
                .with_header("content-type", "application/json")
                .with_body(bytes::Bytes::from_static(br#"{"status": "running", "protocol": "HTTP/3"}"#))),
            
            _ => Ok(Response::not_found()),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    #[cfg(feature = "logging")]
    tracing_subscriber::fmt::init();

    println!("HTTP/3 Server Example");
    println!("====================");

    // Create server
    let mut server = Server::bind("127.0.0.1:8443").await?;
    println!("Server listening on https://127.0.0.1:8443");

    // Set the request handler
    server.set_handler(EchoHandler);

    println!("Routes:");
    println!("  GET  /       - Welcome page");
    println!("  POST /echo   - Echo request body");
    println!("  GET  /status - Server status");
    println!();
    println!("Press Ctrl+C to stop the server");

    // Run the server
    server.run().await?;

    Ok(())
}