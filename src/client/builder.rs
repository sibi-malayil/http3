/// Client builder for configuring HTTP/3 clients
use crate::{
    error::{Error, Result},
    qpack::{encoder::Encoder as QpackEncoder},
    debug,
};
use rustls::{ClientConfig, RootCertStore, pki_types::CertificateDer};
use std::{
    collections::HashMap,
    sync::Arc,
};

use super::Client;

/// Builder for configuring HTTP/3 clients
pub struct ClientBuilder {
    /// Custom root certificates
    custom_roots: Option<Vec<CertificateDer<'static>>>,
    /// QPACK configuration
    qpack_config: crate::qpack::Config,
    /// Custom TLS configuration
    tls_config: Option<Arc<ClientConfig>>,
}

impl ClientBuilder {
    /// Create a new client builder
    pub fn new() -> Self {
        Self {
            custom_roots: None,
            qpack_config: crate::qpack::Config {
                max_table_capacity: 4096,
                max_blocked_streams: 16,
                use_huffman: true,
            },
            tls_config: None,
        }
    }

    /// Add custom root certificates
    pub fn with_custom_roots(mut self, certs: Vec<CertificateDer<'static>>) -> Result<Self> {
        self.custom_roots = Some(certs);
        Ok(self)
    }

    /// Set custom TLS configuration
    pub fn with_tls_config(mut self, config: Arc<ClientConfig>) -> Self {
        self.tls_config = Some(config);
        self
    }

    /// Set QPACK configuration
    pub fn with_qpack_config(mut self, config: crate::qpack::Config) -> Self {
        self.qpack_config = config;
        self
    }

    /// Build the client
    pub async fn build(self) -> Result<Client> {
        // Create TLS configuration
        let tls_config = if let Some(config) = self.tls_config {
            config
        } else {
            // Build default TLS configuration
            let mut root_store = RootCertStore::empty();
            
            if let Some(custom_roots) = self.custom_roots {
                // Add custom root certificates
                for cert in custom_roots {
                    root_store.add(cert)
                        .map_err(|e| Error::Config(format!("Failed to add custom root certificate: {:?}", e)))?;
                }
            } else {
                // Use system root certificates
                let native_certs = rustls_native_certs::load_native_certs();
                
                for cert in native_certs.certs {
                    root_store.add(cert)
                        .map_err(|e| Error::Config(format!("Failed to add native certificate: {:?}", e)))?;
                }
            }

            Arc::new(
                ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth()
            )
        };

        // Create network endpoint with custom TLS config
        let endpoint = crate::network::create_client_endpoint_with_config(tls_config).await?;
        
        Ok(Client {
            endpoint,
            qpack_encoder: QpackEncoder::new(self.qpack_config),
            h3_connections: HashMap::new(),
        })
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    /// Create a new client builder
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Connect to a URL
    pub async fn connect(self, url: &str) -> Result<super::connection::ClientConnection> {
        let url = url::Url::parse(url)
            .map_err(|_| Error::ProtocolViolation("Invalid URL".to_string()))?;
        
        let host = url.host_str()
            .ok_or_else(|| Error::ProtocolViolation("Missing host in URL".to_string()))?;
        
        let port = url.port().unwrap_or(443);
        let server_key = format!("{host}:{port}");

        // Log connection attempt
        debug!("Connecting to server: {}", server_key);

        // Create new QUIC connection
        let server_addr: std::net::SocketAddr = format!("{host}:{port}").parse()
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
        super::connection::ClientConnection::new(quic_conn, url).await
    }
}