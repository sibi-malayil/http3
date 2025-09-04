/// Server builder for configuring HTTP/3 servers

use crate::{
    error::{Error, Result},
    network::NetworkEndpoint,
};
use rustls::{ServerConfig, pki_types::{CertificateDer, PrivateKeyDer}};
use std::{
    net::SocketAddr,
    sync::Arc,
};

use super::{Server, RequestHandler};
use crate::server::listener::DefaultHandler;

/// Builder for configuring HTTP/3 servers
pub struct ServerBuilder {
    /// Server certificates
    certificates: Option<Vec<CertificateDer<'static>>>,
    /// Server private key
    private_key: Option<PrivateKeyDer<'static>>,
    /// Custom TLS configuration
    tls_config: Option<Arc<ServerConfig>>,
    /// Request handler
    handler: Option<Arc<dyn RequestHandler>>,
}

impl ServerBuilder {
    /// Create a new server builder
    pub fn new() -> Self {
        Self {
            certificates: None,
            private_key: None,
            tls_config: None,
            handler: None,
        }
    }

    /// Set server certificate and private key
    pub fn with_certificate(
        mut self,
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self> {
        self.certificates = Some(certs);
        self.private_key = Some(key);
        Ok(self)
    }

    /// Set custom TLS configuration
    pub fn with_tls_config(mut self, config: Arc<ServerConfig>) -> Self {
        self.tls_config = Some(config);
        self
    }

    /// Set request handler
    pub fn with_handler<H: RequestHandler + 'static>(mut self, handler: H) -> Self {
        self.handler = Some(Arc::new(handler));
        self
    }

    /// Bind to an address and build the server
    pub async fn bind(self, addr: impl AsRef<str>) -> Result<Server> {
        let bind_addr: SocketAddr = addr.as_ref().parse()
            .map_err(|_| Error::ProtocolViolation("Invalid bind address".to_string()))?;

        // Create TLS configuration
        let tls_config = if let Some(config) = self.tls_config {
            config
        } else if let (Some(certs), Some(key)) = (self.certificates, self.private_key) {
            // Build TLS configuration from certificates
            Arc::new(
                ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .map_err(|e| Error::Config(format!("Failed to create TLS config: {}", e)))?
            )
        } else {
            return Err(Error::Config("No TLS configuration or certificates provided".to_string()));
        };

        // Create network endpoint with TLS config
        let (endpoint, connection_rx) = NetworkEndpoint::new_accepting_with_config(bind_addr, tls_config).await?;
        
        Ok(Server::from_parts(
            Arc::new(endpoint),
            self.handler.unwrap_or_else(|| Arc::new(DefaultHandler)),
            connection_rx,
        ))
    }
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    /// Create a new server builder
    pub fn builder() -> ServerBuilder {
        ServerBuilder::new()
    }

    /// Accept a new connection
    pub async fn accept(&mut self) -> Result<super::connection::ServerConnection> {
        // Get the connection receiver
        let mut connection_rx = self.connection_rx.take()
            .ok_or_else(|| Error::ProtocolViolation("Connection receiver already taken".to_string()))?;

        // Wait for a new connection
        let (quic_conn, peer_addr) = connection_rx.recv().await
            .ok_or_else(|| Error::ProtocolViolation("Connection channel closed".to_string()))?;

        // Put the receiver back
        self.connection_rx = Some(connection_rx);

        // Create HTTP/3 connection
        super::connection::ServerConnection::new(quic_conn, peer_addr)
    }
}