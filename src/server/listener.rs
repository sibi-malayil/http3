//! HTTP/3 server listener
//!
//! Implements HTTP/3 server functionality for handling incoming connections.

use crate::{
    error::{Error, Result},
    http3::connection::Connection as Http3Connection,
    network::NetworkEndpoint,
    qpack::field::{HeaderField, HeaderName, HeaderValue},
    quic::connection::Connection as QuicConnection,
};
use bytes::Bytes;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
};
use tokio::sync::{mpsc, broadcast, Mutex, RwLock};

/// HTTP/3 request handler trait
#[async_trait::async_trait]
pub trait RequestHandler: Send + Sync {
    /// Handle an HTTP request
    async fn handle(&self, request: Request) -> Result<Response>;
}

/// Default request handler that returns 404
pub(crate) struct DefaultHandler;

#[async_trait::async_trait]
impl RequestHandler for DefaultHandler {
    async fn handle(&self, _request: Request) -> Result<Response> {
        Ok(Response::not_found())
    }
}

/// HTTP/3 server
pub struct Server {
    /// Network endpoint
    endpoint: Arc<NetworkEndpoint>,
    /// Request handler
    handler: Arc<dyn RequestHandler>,
    /// Active connections
    connections: Arc<RwLock<HashMap<SocketAddr, Arc<Mutex<Http3Connection>>>>>,
    /// Shutdown signal
    shutdown: broadcast::Sender<()>,
    /// Channel for receiving new connections from endpoint
    pub(crate) connection_rx: Option<mpsc::UnboundedReceiver<(Arc<Mutex<QuicConnection>>, SocketAddr)>>,
    /// Channel for sending new connections to server
    connection_tx: mpsc::UnboundedSender<(Arc<Mutex<QuicConnection>>, SocketAddr)>,
}

impl Server {
    /// Create a new HTTP/3 server
    pub async fn new(bind_addr: SocketAddr) -> Result<Self> {
        let (endpoint, connection_rx) = NetworkEndpoint::new_accepting(bind_addr).await?;
        let (shutdown_tx, _shutdown_rx) = broadcast::channel(1);
        // Create a dummy channel for connection_tx since we don't need it anymore
        let (connection_tx, _) = mpsc::unbounded_channel();
        
        Ok(Self {
            endpoint: Arc::new(endpoint),
            handler: Arc::new(DefaultHandler),
            connections: Arc::new(RwLock::new(HashMap::new())),
            shutdown: shutdown_tx,
            connection_rx: Some(connection_rx),
            connection_tx,
        })
    }

    /// Create a server from components (internal use)
    pub(crate) fn from_parts(
        endpoint: Arc<NetworkEndpoint>,
        handler: Arc<dyn RequestHandler>,
        connection_rx: mpsc::UnboundedReceiver<(Arc<Mutex<QuicConnection>>, SocketAddr)>,
    ) -> Self {
        let (shutdown_tx, _shutdown_rx) = broadcast::channel(1);
        let (connection_tx, _) = mpsc::unbounded_channel();
        
        Self {
            endpoint,
            handler,
            connections: Arc::new(RwLock::new(HashMap::new())),
            shutdown: shutdown_tx,
            connection_rx: Some(connection_rx),
            connection_tx,
        }
    }

    /// Bind to an address and create a server
    /// 
    /// # Errors
    /// 
    /// Returns an error if the address parsing fails or server creation fails.
    pub async fn bind(addr: &str) -> Result<Self> {
        let bind_addr: SocketAddr = addr.parse()
            .map_err(|_| Error::ProtocolViolation("Invalid bind address".to_string()))?;
        Self::new(bind_addr).await
    }

    /// Set the request handler
    pub fn set_handler<H: RequestHandler + 'static>(&mut self, handler: H) {
        self.handler = Arc::new(handler);
    }

    /// Run the server
    /// 
    /// # Errors
    /// 
    /// Returns an error if connection acceptance or handling fails.
    pub async fn run(mut self) -> Result<()> {
        let handler = self.handler.clone();
        let connections = self.connections.clone();
        
        // Start the endpoint event loop in background
        let endpoint = self.endpoint.clone();
        tokio::spawn(async move {
            if let Err(e) = endpoint.run().await {
                tracing::error!("Endpoint error: {}", e);
            }
        });
        
        // Get the connection receiver
        let mut connection_rx = self.connection_rx.take()
            .ok_or_else(|| Error::Internal("No connection receiver".to_string()))?;
        
        let mut shutdown_rx = self.shutdown.subscribe();
        
        // Accept loop
        loop {
            tokio::select! {
                // Handle new connections
                result = connection_rx.recv() => {
                    match result {
                        Some((quic_conn, peer_addr)) => {
                            // Spawn connection handler
                            let handler = handler.clone();
                            let connections = connections.clone();
                            
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_connection(
                                    quic_conn,
                                    peer_addr,
                                    handler,
                                    connections
                                ).await {
                                    tracing::error!("Connection error: {}", e);
                                }
                            });
                        }
                        None => {
                            tracing::error!("Connection channel closed");
                            break;
                        }
                    }
                }
                
                // Shutdown signal
                _ = shutdown_rx.recv() => {
                    break;
                }
            }
        }
        
        // Shutdown endpoint
        self.endpoint.shutdown().await
    }


    /// Handle a connection
    async fn handle_connection(
        quic_conn: Arc<Mutex<QuicConnection>>,
        peer_addr: SocketAddr,
        _handler: Arc<dyn RequestHandler>,
        connections: Arc<RwLock<HashMap<SocketAddr, Arc<Mutex<Http3Connection>>>>>,
    ) -> Result<()> {
        // Create HTTP/3 connection
        let mut h3_conn = Http3Connection::new(quic_conn)?;
        h3_conn.initialize().await?;
        
        let h3_conn = Arc::new(Mutex::new(h3_conn));
        
        // Store connection
        {
            let mut conns = connections.write().await;
            conns.insert(peer_addr, h3_conn.clone());
        }
        
        // Process connection events
        loop {
            let mut h3_conn_lock = h3_conn.lock().await;
            
            // Process events
            if let Err(e) = h3_conn_lock.process_events().await {
                tracing::error!("Event processing error: {}", e);
                break;
            }
            
            // Check if connection is closed
            if h3_conn_lock.is_closed() {
                break;
            }
            
            drop(h3_conn_lock);
            
            // Small delay to prevent busy loop
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
        
        // Remove connection
        let mut conns = connections.write().await;
        conns.remove(&peer_addr);
        
        Ok(())
    }

    /// Shutdown the server
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(());
    }
}

/// HTTP request
pub struct Request {
    /// Request method
    pub method: String,
    /// Request path
    pub path: String,
    /// Request headers
    pub headers: Vec<HeaderField>,
    /// Request body
    pub body: Option<Bytes>,
    /// Peer address
    pub peer_addr: SocketAddr,
}

impl Request {
    /// Create a new request
    pub fn new(
        method: String,
        path: String,
        headers: Vec<HeaderField>,
        peer_addr: SocketAddr,
    ) -> Self {
        Self {
            method,
            path,
            headers,
            body: None,
            peer_addr,
        }
    }

    /// Get a header value
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter()
            .find(|h| h.name.as_str() == name)
            .and_then(|h| h.value.as_str().ok())
    }

    /// Check if the request has a body
    pub fn has_body(&self) -> bool {
        self.body.is_some()
    }
}

/// HTTP response
pub struct Response {
    /// Response status code
    pub status: u16,
    /// Response headers
    pub headers: Vec<HeaderField>,
    /// Response body
    pub body: Option<Bytes>,
}

impl Response {
    /// Create a new response
    pub fn new(status: u16) -> Self {
        Self {
            status,
            headers: vec![],
            body: None,
        }
    }

    /// Create a 200 OK response
    pub fn ok() -> Self {
        Self::new(200)
    }

    /// Create a 404 Not Found response
    pub fn not_found() -> Self {
        Self::new(404)
            .with_body(Bytes::from_static(b"Not Found"))
    }

    /// Create a 500 Internal Server Error response
    pub fn internal_error() -> Self {
        Self::new(500)
            .with_body(Bytes::from_static(b"Internal Server Error"))
    }

    /// Add a header
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push(HeaderField::new(
            HeaderName::from(name.into()),
            HeaderValue::from(value.into()),
        ));
        self
    }

    /// Set the response body
    pub fn with_body(mut self, body: Bytes) -> Self {
        self.body = Some(body);
        self
    }

    /// Set JSON body
    #[cfg(feature = "json")]
    pub fn with_json<T: serde::Serialize>(self, data: &T) -> Result<Self> {
        let json = serde_json::to_vec(data)
            .map_err(|e| Error::Internal(format!("JSON serialization error: {}", e)))?;
        Ok(self
            .with_header("content-type", "application/json")
            .with_body(Bytes::from(json)))
    }

    /// Convert to headers for sending
    pub fn to_headers(&self) -> Vec<HeaderField> {
        let mut headers = vec![
            HeaderField::new(
                HeaderName::from(":status"),
                HeaderValue::from(self.status.to_string()),
            ),
        ];
        
        headers.extend(self.headers.clone());
        
        // Add content-length if body is present
        if let Some(body) = &self.body {
            headers.push(HeaderField::new(
                HeaderName::from("content-length"),
                HeaderValue::from(body.len().to_string()),
            ));
        }
        
        headers
    }
}

/// Simple file server handler
pub struct FileServerHandler {
    root: std::path::PathBuf,
}

impl FileServerHandler {
    /// Create a new file server handler
    pub fn new(root: impl Into<std::path::PathBuf>) -> Self {
        Self {
            root: root.into(),
        }
    }
}

#[async_trait::async_trait]
impl RequestHandler for FileServerHandler {
    async fn handle(&self, request: Request) -> Result<Response> {
        // Simple security check
        if request.path.contains("..") {
            return Ok(Response::new(400).with_body(Bytes::from_static(b"Bad Request")));
        }
        
        let mut path = self.root.clone();
        path.push(request.path.trim_start_matches('/'));
        
        // Read file
        match tokio::fs::read(&path).await {
            Ok(content) => {
                let mime_type = mime_guess::from_path(&path)
                    .first_or_octet_stream()
                    .to_string();
                
                Ok(Response::ok()
                    .with_header("content-type", mime_type)
                    .with_body(content.into()))
            }
            Err(_) => Ok(Response::not_found()),
        }
    }
}