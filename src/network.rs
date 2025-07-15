//! UDP networking layer for QUIC transport
//!
//! Provides UDP socket handling and packet processing for QUIC connections.

use crate::{
    error::{Error, Result},
    quic::{
        connection::{Connection, ConnectionRole, ConnectionStats},
        packet::{ConnectionId, Packet, PacketHeader},
        transport::TransportParameters,
    },
    whathappened::{Level, EventKind},
    {debug, info, warn, error, net_event, span},
};
use bytes::Bytes;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, RwLock, Mutex},
    time::interval,
};

/// UDP packet with source address
#[derive(Debug, Clone)]
pub struct UdpPacket {
    /// The packet data payload
    pub data: Bytes,
    /// The source address of the packet
    pub source: SocketAddr,
}

/// Network endpoint managing UDP socket and QUIC connections
pub struct NetworkEndpoint {
    /// UDP socket for sending/receiving packets
    socket: Arc<UdpSocket>,
    /// Active QUIC connections indexed by connection ID
    connections: Arc<RwLock<HashMap<ConnectionId, Arc<Mutex<Connection>>>>>,
    /// Channel for incoming packets
    packet_rx: Option<mpsc::UnboundedReceiver<UdpPacket>>,
    /// Channel for outgoing packets
    packet_tx: mpsc::UnboundedSender<(Bytes, SocketAddr)>,
    /// Local socket address
    local_addr: SocketAddr,
    /// Default transport parameters
    transport_params: TransportParameters,
    /// Connection timeout
    connection_timeout: Duration,
    /// Channel for notifying about new incoming connections
    new_connection_tx: Option<mpsc::UnboundedSender<(Arc<Mutex<Connection>>, SocketAddr)>>,
}

impl NetworkEndpoint {
    /// Create a new network endpoint
    pub async fn new(bind_addr: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await
            .map_err(|e| Error::Io(e))?;
        
        let local_addr = socket.local_addr()
            .map_err(|e| Error::Io(e))?;
        
        let socket = Arc::new(socket);
        let (packet_tx, mut packet_rx) = mpsc::unbounded_channel::<(Bytes, SocketAddr)>();
        let (_udp_packet_tx, udp_packet_rx) = mpsc::unbounded_channel::<UdpPacket>();
        
        let endpoint = Self {
            socket: socket.clone(),
            connections: Arc::new(RwLock::new(HashMap::new())),
            packet_rx: Some(udp_packet_rx),
            packet_tx,
            local_addr,
            transport_params: TransportParameters::default(),
            connection_timeout: Duration::from_secs(30),
            new_connection_tx: None,
        };

        // Start packet sender task
        tokio::spawn(async move {
            while let Some((data, addr)) = packet_rx.recv().await {
                if let Err(e) = socket.send_to(&data, addr).await {
                    net_event!(
                        Level::Warn,
                        "Failed to send packet";
                        "addr" => addr,
                        "error" => e
                    );
                }
            }
        });
        
        Ok(endpoint)
    }

    /// Get the local socket address
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }


    /// Start the endpoint event loop
    pub async fn run(&self) -> Result<()> {
        let mut interval = interval(Duration::from_millis(10));
        let mut buffer = vec![0u8; 65536]; // Max UDP packet size
        
        loop {
            tokio::select! {
                // Handle incoming UDP packets
                result = self.socket.recv_from(&mut buffer) => {
                    match result {
                        Ok((len, source)) => {
                            let data = Bytes::copy_from_slice(&buffer[..len]);
                            if let Err(e) = self.handle_incoming_packet(data, source).await {
                                net_event!(
                                    Level::Warn,
                                    "Error handling packet";
                                    "source" => source,
                                    "error" => e
                                );
                            }
                        }
                        Err(e) => {
                            net_event!(
                                Level::Error,
                                "UDP receive error";
                                "error" => e
                            );
                            return Err(Error::Io(e));
                        }
                    }
                }
                
                // Periodic maintenance
                _ = interval.tick() => {
                    if let Err(e) = self.maintain_connections().await {
                        net_event!(
                            Level::Warn,
                            "Connection maintenance error";
                            "error" => e
                        );
                    }
                }
            }
        }
    }

    /// Handle an incoming UDP packet
    async fn handle_incoming_packet(&self, data: Bytes, source: SocketAddr) -> Result<()> {
        let _span = span!(Level::Debug, "handle_incoming_packet", source = source, data_len = data.len());
        
        // Parse the packet to extract connection ID
        let packet = match Packet::decode(data.clone(), source, self.local_addr) {
            Ok(packet) => {
                net_event!(
                    Level::Debug,
                    "Packet decoded successfully";
                    "source" => source,
                    "data_len" => data.len()
                );
                packet
            },
            Err(e) => {
                debug!("Failed to parse packet from {}: {}", source, e);
                return Ok(()); // Ignore malformed packets
            }
        };

        // Extract destination connection ID
        let dest_cid = packet.header.destination_cid();
        
        // Find or create connection
        let connection = {
            let connections = self.connections.read().await;
            connections.get(dest_cid).cloned()
        };

        if let Some(connection) = connection {
            // Process packet with existing connection
            net_event!(
                Level::Debug,
                "Processing packet with existing connection";
                "dest_cid" => dest_cid,
                "source" => source
            );
            let mut conn = connection.lock().await;
            conn.process_packet(&data).await?;
        } else {
            // Handle new connection attempt
            net_event!(
                Level::Info,
                "Handling new connection attempt";
                "dest_cid" => dest_cid,
                "source" => source
            );
            self.handle_new_connection(packet, &data, source).await?;
        }

        Ok(())
    }

    /// Handle a new connection attempt
    async fn handle_new_connection(&self, packet: Packet, packet_data: &[u8], source: SocketAddr) -> Result<()> {
        let _span = span!(Level::Info, "handle_new_connection", source = source);
        
        // Only accept Initial packets for new connections
        if !matches!(packet.header, PacketHeader::Long(ref long_header) if long_header.packet_type == crate::quic::packet::PacketType::Initial) {
            net_event!(
                Level::Debug,
                "Ignoring non-Initial packet for new connection";
                "source" => source
            );
            return Ok(()); // Ignore non-Initial packets for unknown connections
        }

        // Extract connection IDs
        let dest_cid = packet.header.destination_cid().clone();
        let source_cid = packet.header.source_cid().cloned()
            .ok_or_else(|| Error::ProtocolViolation("Missing source connection ID".to_string()))?;

        // Create new server connection
        net_event!(
            Level::Info,
            "Creating new server connection";
            "dest_cid" => dest_cid,
            "source_cid" => source_cid,
            "source" => source
        );
        
        let mut connection = Connection::new(
            ConnectionRole::Server,
            dest_cid.clone(),
            source_cid,
            source,
            self.transport_params.clone(),
        )?;

        // Set up packet sender
        connection.set_packet_sender(self.packet_tx.clone());

        // Process the initial packet
        connection.process_packet(packet_data).await?;

        // Add to connections map
        let connection = Arc::new(Mutex::new(connection));
        let mut connections = self.connections.write().await;
        connections.insert(dest_cid.clone(), connection.clone());
        
        // Notify about new connection
        if let Some(ref tx) = self.new_connection_tx {
            if let Err(_) = tx.send((connection, source)) {
                net_event!(
                    Level::Warn,
                    "Failed to notify about new connection";
                    "dest_cid" => dest_cid,
                    "source" => source
                );
            }
        }
        
        net_event!(
            Level::Info,
            "Server connection established";
            "dest_cid" => dest_cid,
            "source" => source
        );

        Ok(())
    }

    /// Create a new client connection
    pub async fn connect(&self, remote_addr: SocketAddr) -> Result<Arc<Mutex<Connection>>> {
        let _span = span!(Level::Info, "connect", remote_addr = remote_addr);
        
        let local_cid = ConnectionId::random(8)?;  // RFC 9000 recommends 8 bytes
        let remote_cid = ConnectionId::random(8)?;
        
        net_event!(
            Level::Info,
            "Creating new client connection";
            "local_cid" => local_cid,
            "remote_cid" => remote_cid,
            "remote_addr" => remote_addr
        );

        let mut connection = Connection::new(
            ConnectionRole::Client,
            local_cid.clone(),
            remote_cid,
            remote_addr,
            self.transport_params.clone(),
        )?;

        // Set up packet sender
        connection.set_packet_sender(self.packet_tx.clone());

        // Start handshake
        connection.start_handshake().await?;

        // Add to connections map
        let connection = Arc::new(Mutex::new(connection));
        let mut connections = self.connections.write().await;
        connections.insert(local_cid.clone(), connection.clone());
        
        net_event!(
            Level::Info,
            "Client connection established";
            "local_cid" => local_cid,
            "remote_addr" => remote_addr
        );

        Ok(connection)
    }

    /// Perform periodic maintenance on all connections
    async fn maintain_connections(&self) -> Result<()> {
        let _span = span!(Level::Debug, "maintain_connections");
        
        let connections = {
            let connections = self.connections.read().await;
            connections.values().cloned().collect::<Vec<_>>()
        };
        
        debug!("Maintaining {} connections", connections.len());

        let mut expired_connections = Vec::new();

        for connection_arc in connections {
            let mut connection = connection_arc.lock().await;
            
            // Perform connection maintenance
            connection.maintain().await?;
            
            // Check if connection should be removed
            if connection.state().is_closed() {
                expired_connections.push(connection.local_cid().clone());
            }
        }

        // Remove expired connections
        if !expired_connections.is_empty() {
            let mut connections = self.connections.write().await;
            for cid in expired_connections {
                connections.remove(&cid);
                debug!("Removed expired connection: {:?}", cid);
            }
        }

        Ok(())
    }

    /// Get statistics for all connections
    pub async fn get_connections_stats(&self) -> Vec<(ConnectionId, ConnectionStats)> {
        let connections = self.connections.read().await;
        let mut stats = Vec::new();

        for (cid, connection_arc) in connections.iter() {
            let connection = connection_arc.lock().await;
            stats.push((cid.clone(), connection.stats()));
        }

        stats
    }

    /// Get the number of active connections
    pub async fn connection_count(&self) -> usize {
        let connections = self.connections.read().await;
        connections.len()
    }

    /// Close all connections gracefully
    pub async fn shutdown(&self) -> Result<()> {
        let connections = {
            let connections = self.connections.read().await;
            connections.values().cloned().collect::<Vec<_>>()
        };

        // Close all connections
        for connection_arc in connections {
            let mut connection = connection_arc.lock().await;
            connection.close(
                crate::error::ConnectionErrorCode::NoError,
                "Endpoint shutdown".to_string()
            ).await?;
        }

        // Give time for close frames to be sent
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Clear connections map
        let mut connections = self.connections.write().await;
        connections.clear();

        Ok(())
    }

    /// Set transport parameters
    pub fn set_transport_params(&mut self, params: TransportParameters) {
        self.transport_params = params;
    }

    /// Set connection timeout
    pub fn set_connection_timeout(&mut self, timeout: Duration) {
        self.connection_timeout = timeout;
    }

    /// Set up new connection notifications
    pub fn set_new_connection_notifier(&mut self, tx: mpsc::UnboundedSender<(Arc<Mutex<Connection>>, SocketAddr)>) {
        self.new_connection_tx = Some(tx);
    }

    /// Create an accepting endpoint that notifies about new connections
    pub async fn new_accepting(bind_addr: SocketAddr) -> Result<(Self, mpsc::UnboundedReceiver<(Arc<Mutex<Connection>>, SocketAddr)>)> {
        let mut endpoint = Self::new(bind_addr).await?;
        let (tx, rx) = mpsc::unbounded_channel();
        endpoint.set_new_connection_notifier(tx);
        Ok((endpoint, rx))
    }

    /// Create an accepting endpoint with custom TLS configuration
    pub async fn new_accepting_with_config(
        bind_addr: SocketAddr,
        tls_config: Arc<rustls::ServerConfig>,
    ) -> Result<(Self, mpsc::UnboundedReceiver<(Arc<Mutex<Connection>>, SocketAddr)>)> {
        // TODO: Integrate TLS configuration into endpoint
        // For now, just create a standard accepting endpoint
        Self::new_accepting(bind_addr).await
    }
}

/// Helper function to create a client endpoint
pub async fn create_client_endpoint() -> Result<NetworkEndpoint> {
    NetworkEndpoint::new("0.0.0.0:0".parse().unwrap()).await
}

/// Helper function to create a client endpoint with custom TLS configuration
pub async fn create_client_endpoint_with_config(tls_config: Arc<rustls::ClientConfig>) -> Result<NetworkEndpoint> {
    // TODO: Integrate TLS configuration into endpoint
    // For now, just create a standard endpoint
    NetworkEndpoint::new("0.0.0.0:0".parse().unwrap()).await
}

/// Helper function to create a server endpoint
pub async fn create_server_endpoint(port: u16) -> Result<NetworkEndpoint> {
    let bind_addr = format!("0.0.0.0:{}", port).parse().unwrap();
    NetworkEndpoint::new(bind_addr).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn endpoint_creation() {
        let endpoint = create_client_endpoint().await.unwrap();
        assert!(endpoint.local_addr().port() > 0);
        assert_eq!(endpoint.connection_count().await, 0);
    }

    #[tokio::test]
    async fn server_endpoint_binding() {
        let endpoint = create_server_endpoint(0).await.unwrap(); // Random port
        assert!(endpoint.local_addr().port() > 0);
    }

    #[tokio::test]
    async fn connection_creation() {
        let client = create_client_endpoint().await.unwrap();
        let server = create_server_endpoint(0).await.unwrap();
        
        let server_addr = server.local_addr();
        
        // This would fail in real usage without a running server,
        // but tests the connection creation code path
        let result = client.connect(server_addr).await;
        assert!(result.is_ok());
        
        assert_eq!(client.connection_count().await, 1);
    }

    #[tokio::test]
    async fn endpoint_shutdown() {
        let endpoint = create_client_endpoint().await.unwrap();
        
        // Create a connection
        let server_addr = "127.0.0.1:8080".parse().unwrap();
        let _connection = endpoint.connect(server_addr).await.unwrap();
        
        assert_eq!(endpoint.connection_count().await, 1);
        
        // Shutdown
        endpoint.shutdown().await.unwrap();
        assert_eq!(endpoint.connection_count().await, 0);
    }

    #[tokio::test]
    async fn connection_stats() {
        let endpoint = create_client_endpoint().await.unwrap();
        let stats = endpoint.get_connections_stats().await;
        assert!(stats.is_empty());
    }
}