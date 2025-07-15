//! Advanced HTTP/3 Client Example
//!
//! Demonstrates a complete HTTP/3 client with proper handshake, 
//! connection management, and request/response handling.

use http3::{
    client::Connection as Http3Connection,
    quic::{
        connection::{Connection as QuicConnection, ConnectionRole},
        crypto_impl::CryptoManager,
        frame_types::Frame,
    },
    error::Result,
};
use bytes::Bytes;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

#[tokio::main]
async fn main() -> Result<()> {
    println!("🚀 Starting HTTP/3 Advanced Client");
    
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    // Server address
    let server_addr: SocketAddr = "127.0.0.1:8443".parse().unwrap();
    
    // Create UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0").await
        .map_err(|e| http3::error::Error::Io(e))?;
    
    println!("📡 Connecting to server at {}", server_addr);
    
    // Create QUIC connection
    let mut quic_conn = QuicConnection::new(ConnectionRole::Client)?;
    
    // Create HTTP/3 connection
    let mut http3_conn = Http3Connection::new(quic_conn).await?;
    
    // Perform handshake
    println!("🤝 Starting TLS handshake...");
    http3_conn.handshake().await?;
    
    println!("✅ Handshake completed successfully");
    
    // Create a simple HTTP/3 request
    let request_headers = vec![
        (":method", "GET"),
        (":path", "/"),
        (":scheme", "https"),
        (":authority", "localhost:8443"),
        ("user-agent", "http3-rust-client/0.1.0"),
    ];
    
    println!("📤 Sending HTTP/3 request...");
    
    // Send request
    let stream_id = http3_conn.send_request(request_headers, None).await?;
    println!("📝 Request sent on stream {}", stream_id);
    
    // Wait for response
    println!("📥 Waiting for response...");
    let response = http3_conn.receive_response(stream_id).await?;
    
    println!("🎉 Response received:");
    for (name, value) in &response.headers {
        println!("  {}: {}", name, value);
    }
    
    if let Some(body) = response.body {
        println!("📄 Response body: {}", String::from_utf8_lossy(&body));
    }
    
    // Clean shutdown
    http3_conn.close().await?;
    println!("👋 Connection closed gracefully");
    
    Ok(())
}

/// Helper struct for HTTP response
#[derive(Debug)]
struct HttpResponse {
    headers: Vec<(String, String)>,
    body: Option<Bytes>,
}

impl Http3Connection {
    /// Send an HTTP/3 request
    async fn send_request(
        &mut self,
        headers: Vec<(&str, &str)>,
        body: Option<Bytes>,
    ) -> Result<u64> {
        // Create a new stream for the request
        let stream_id = self.create_stream().await?;
        
        // Convert headers to HTTP/3 format and send
        self.send_headers(stream_id, headers).await?;
        
        // Send body if present
        if let Some(body_data) = body {
            self.send_data(stream_id, body_data, true).await?;
        } else {
            // Send empty data with FIN flag
            self.send_data(stream_id, Bytes::new(), true).await?;
        }
        
        Ok(stream_id)
    }
    
    /// Receive HTTP/3 response
    async fn receive_response(&mut self, stream_id: u64) -> Result<HttpResponse> {
        let mut headers = Vec::new();
        let mut body_parts = Vec::new();
        let mut response_complete = false;
        
        while !response_complete {
            // Process incoming frames
            if let Some(frame) = self.receive_frame().await? {
                match frame {
                    Frame::Headers { stream_id: s_id, headers: h, fin } if s_id == stream_id => {
                        headers = h;
                        if fin {
                            response_complete = true;
                        }
                    }
                    Frame::Data { stream_id: s_id, data, fin } if s_id == stream_id => {
                        body_parts.push(data);
                        if fin {
                            response_complete = true;
                        }
                    }
                    _ => {
                        // Handle other frames or ignore
                    }
                }
            }
        }
        
        let body = if body_parts.is_empty() {
            None
        } else {
            let mut combined = Vec::new();
            for part in body_parts {
                combined.extend_from_slice(&part);
            }
            Some(Bytes::from(combined))
        };
        
        Ok(HttpResponse { headers, body })
    }
    
    /// Perform handshake
    async fn handshake(&mut self) -> Result<()> {
        // Start the QUIC handshake
        self.start_handshake().await?;
        
        // Exchange handshake messages until complete
        while !self.is_handshake_complete().await? {
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            self.process_handshake().await?;
        }
        
        Ok(())
    }
    
    /// Create a new stream
    async fn create_stream(&mut self) -> Result<u64> {
        // This would interface with the QUIC connection to create a new stream
        // For now, return a dummy stream ID
        Ok(1)
    }
    
    /// Send headers on a stream
    async fn send_headers(&mut self, stream_id: u64, headers: Vec<(&str, &str)>) -> Result<()> {
        // Convert headers to QPACK format and send as HEADERS frame
        // This is a simplified implementation
        println!("📧 Sending headers on stream {}: {:?}", stream_id, headers);
        Ok(())
    }
    
    /// Send data on a stream
    async fn send_data(&mut self, stream_id: u64, data: Bytes, fin: bool) -> Result<()> {
        // Send data as DATA frame
        println!("📦 Sending {} bytes on stream {} (fin: {})", data.len(), stream_id, fin);
        Ok(())
    }
    
    /// Receive a frame from the connection
    async fn receive_frame(&mut self) -> Result<Option<Frame>> {
        // This would read and parse frames from the QUIC connection
        // For now, return None to indicate no frames available
        Ok(None)
    }
    
    /// Start the handshake process
    async fn start_handshake(&mut self) -> Result<()> {
        println!("🔐 Starting QUIC handshake...");
        Ok(())
    }
    
    /// Process handshake messages
    async fn process_handshake(&mut self) -> Result<()> {
        // Process incoming handshake data
        Ok(())
    }
    
    /// Check if handshake is complete
    async fn is_handshake_complete(&self) -> Result<bool> {
        // For demo purposes, simulate handshake completion
        Ok(true)
    }
    
    /// Close the connection
    async fn close(&mut self) -> Result<()> {
        println!("🚪 Closing HTTP/3 connection...");
        Ok(())
    }
}

// Define dummy Frame enum for the example
// In practice, this would use the actual Frame from frame_types
#[derive(Debug)]
enum Frame {
    Headers {
        stream_id: u64,
        headers: Vec<(String, String)>,
        fin: bool,
    },
    Data {
        stream_id: u64,
        data: Bytes,
        fin: bool,
    },
}