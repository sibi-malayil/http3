//! HTTP/3 client implementation
//!
//! Provides high-level HTTP/3 client API for making requests.

pub use crate::{
    error::{Error, Result},
    network::NetworkEndpoint,
    qpack::{encoder::Encoder as QpackEncoder, field::{HeaderField, HeaderName, HeaderValue}},
    quic::{
        connection::Connection,
        stream::StreamId,
    },
};
use bytes::Bytes;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
};
use tokio::sync::Mutex;
use url::Url;

pub mod connection;
pub mod builder;

/// HTTP/3 client for making requests
pub struct Client {
    /// Network endpoint for QUIC connections
    endpoint: NetworkEndpoint,
    /// QPACK encoder for header compression
    qpack_encoder: QpackEncoder,
    /// Active HTTP/3 connections to servers
    h3_connections: HashMap<String, Arc<Mutex<connection::ClientConnection>>>,
}

impl Client {
    /// Create a new HTTP/3 client
    /// 
    /// # Errors
    /// 
    /// Returns an error if the network endpoint creation fails.
    pub async fn new() -> Result<Self> {
        let endpoint = crate::network::create_client_endpoint().await?;
        
        Ok(Self {
            endpoint,
            qpack_encoder: QpackEncoder::new(crate::qpack::Config {
                max_table_capacity: 4096,
                max_blocked_streams: 16,
                use_huffman: true,
            }),
            h3_connections: HashMap::new(),
        })
    }

    /// Connect to a server and make an HTTP/3 request
    /// 
    /// # Errors
    /// 
    /// Returns an error if URL parsing fails, connection creation fails,
    /// header encoding fails, or stream operations fail.
    pub async fn request(&mut self, method: &str, url: &str) -> Result<connection::Response> {
        let url = Url::parse(url)
            .map_err(|_| Error::ProtocolViolation("Invalid URL".to_string()))?;

        // Get or create HTTP/3 connection to the server
        let client_conn = self.get_or_create_h3_connection(&url).await?;

        // Make the request through the HTTP/3 connection
        match method.to_uppercase().as_str() {
            "GET" => {
                let conn = client_conn.lock().await;
                conn.get(url.path()).await
            },
            "POST" => {
                let conn = client_conn.lock().await;
                conn.post(url.path(), bytes::Bytes::new()).await
            },
            _ => Err(Error::ProtocolViolation(format!("Unsupported method: {}", method))),
        }
    }

    /// GET request helper
    /// 
    /// # Errors
    /// 
    /// Returns an error if the underlying request fails.
    pub async fn get(&mut self, url: &str) -> Result<connection::Response> {
        self.request("GET", url).await
    }

    /// POST request helper
    /// 
    /// # Errors
    /// 
    /// Returns an error if the underlying request fails or body sending fails.
    pub async fn post(&mut self, url: &str, body: impl Into<Bytes>) -> Result<connection::Response> {
        let body_bytes = body.into();
        let url_parsed = Url::parse(url)
            .map_err(|_| Error::ProtocolViolation("Invalid URL".to_string()))?;

        // Get or create HTTP/3 connection to the server
        let client_conn = self.get_or_create_h3_connection(&url_parsed).await?;
        
        // Send POST request with body
        let conn = client_conn.lock().await;
        conn.post(url_parsed.path(), body_bytes).await
    }

    /// Get or create an HTTP/3 connection to the server
    async fn get_or_create_h3_connection(&mut self, url: &Url) -> Result<Arc<Mutex<connection::ClientConnection>>> {
        let host = url.host_str()
            .ok_or_else(|| Error::ProtocolViolation("Missing host in URL".to_string()))?;
        
        let port = url.port().unwrap_or(443); // Default HTTPS port
        let server_key = format!("{host}:{port}");

        if let Some(connection) = self.h3_connections.get(&server_key) {
            return Ok(connection.clone());
        }

        // Create new QUIC connection
        let server_addr: SocketAddr = format!("{host}:{port}").parse()
            .map_err(|_| Error::ProtocolViolation("Invalid server address".to_string()))?;

        let quic_conn = self.endpoint.connect(server_addr).await?;
        
        // Wait for QUIC handshake to complete
        {
            let conn = quic_conn.lock().await;
            while !conn.is_established() {
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }
        }
        
        // Create HTTP/3 connection
        let client_conn = connection::ClientConnection::new(quic_conn, url.clone()).await?;
        let client_conn = Arc::new(Mutex::new(client_conn));
        
        self.h3_connections.insert(server_key, client_conn.clone());

        Ok(client_conn)
    }

    /// Create HTTP request headers
    /// 
    /// # Errors
    /// 
    /// Returns an error if header field creation fails.
    fn create_request_headers(&self, method: &str, url: &Url) -> Vec<HeaderField> {
        let mut headers = Vec::new();

        // Required pseudo-headers for HTTP/3
        headers.push(HeaderField::new(
            HeaderName::from(":method"),
            HeaderValue::from(method.to_uppercase()),
        ));

        headers.push(HeaderField::new(
            HeaderName::from(":scheme"),
            HeaderValue::from(url.scheme()),
        ));

        headers.push(HeaderField::new(
            HeaderName::from(":authority"),
            HeaderValue::from(url.host_str().unwrap_or("localhost")),
        ));

        let path = if url.query().is_some() {
            format!("{}?{}", url.path(), url.query().unwrap())
        } else {
            url.path().to_string()
        };

        headers.push(HeaderField::new(
            HeaderName::from(":path"),
            HeaderValue::from(path),
        ));

        // Standard headers
        headers.push(HeaderField::new(
            HeaderName::from("user-agent"),
            HeaderValue::from(format!("http3-rust/{}", env!("CARGO_PKG_VERSION"))),
        ));

        headers
    }

    /// Close all connections
    /// 
    /// # Errors
    /// 
    /// Returns an error if endpoint shutdown fails.
    pub async fn close(&mut self) -> Result<()> {
        self.h3_connections.clear();
        self.endpoint.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn client_creation() {
        let client = Client::new().await.unwrap();
        assert_eq!(client.h3_connections.len(), 0);
    }

    #[tokio::test]
    async fn request_headers_creation() {
        // Create a mock client for testing
        let endpoint = crate::network::create_client_endpoint().await.unwrap();
        let client = Client {
            endpoint,
            qpack_encoder: QpackEncoder::new(crate::qpack::Config {
                max_table_capacity: 4096,
                max_blocked_streams: 16,
                use_huffman: true,
            }),
            h3_connections: HashMap::new(),
        };

        let url = Url::parse("https://example.com/path?query=value").unwrap();
        let headers = client.create_request_headers("GET", &url);

        assert!(headers.iter().any(|h| h.name.as_str() == ":method"));
        assert!(headers.iter().any(|h| h.name.as_str() == ":scheme"));
        assert!(headers.iter().any(|h| h.name.as_str() == ":authority"));
        assert!(headers.iter().any(|h| h.name.as_str() == ":path"));
    }

    #[tokio::test]
    async fn response_status_parsing() {
        // This test would require a mock connection, skipping for now
        // In a real implementation, we'd test with mock streams
    }
}