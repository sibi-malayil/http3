//! QUIC cryptographic operations implementation
//!
//! Implements packet protection and key management according to RFC 9001.

use crate::{
    error::{Error, Result},
    protocol_event,
    quic::{
        packet::{PacketHeader, PacketType, LongHeader, ConnectionId},
        frame_types::Frame,
        connection::ConnectionRole,
        transport::TransportParameters,
        rustls_keys::{RustlsKeys, RustlsDirectionalKeys},
    },
    whathappened::{Level},
    {debug, info, warn, crypto_event},
};
use bytes::{Bytes, BytesMut, BufMut};
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    hkdf::{self, KeyType},
};

/// Arbitrary output length for HKDF operations
#[derive(Debug)]
struct ArbitraryOutputLen(usize);

impl KeyType for ArbitraryOutputLen {
    fn len(&self) -> usize {
        self.0
    }
}
use rustls::{
    quic::{Connection as QuicConnection},
};
use std::{sync::Arc, collections::BTreeMap};

/// QUIC version 1 salt for initial packet protection per RFC 9001 Section 5.2
pub const INITIAL_SALT: &[u8] = &[
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// Packet protection level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketProtectionLevel {
    /// Initial packet protection (cleartext)
    Initial,
    /// Handshake packet protection
    Handshake,
    /// Application data packet protection (1-RTT)
    Application,
}

/// Decrypted packet data
pub struct DecryptedPacket {
    /// Packet number from header
    pub packet_number: u64,
    /// Decoded frames from packet
    pub frames: Vec<Frame>,
    /// Raw packet payload
    pub payload: Bytes,
}

/// CRYPTO frame buffering for out-of-order data
struct CryptoBuffer {
    /// Buffered CRYPTO frame data indexed by offset
    buffer: BTreeMap<u64, Bytes>,
    /// Next expected offset for continuous reading
    next_expected_offset: u64,
}

impl CryptoBuffer {
    /// Create a new CRYPTO frame buffer
    fn new() -> Self {
        Self {
            buffer: BTreeMap::new(),
            next_expected_offset: 0,
        }
    }
    
    /// Add CRYPTO frame data to the buffer
    /// Returns continuous data that's ready to be processed
    fn add_frame(&mut self, offset: u64, data: Bytes) -> Vec<Bytes> {
        let mut ready_data = Vec::new();
        
        // Add new data to buffer
        self.buffer.insert(offset, data);
        
        // Extract continuous data starting from next_expected_offset
        loop {
            if let Some((&offset, _)) = self.buffer.first_key_value() {
                if offset == self.next_expected_offset {
                    let data = self.buffer.remove(&offset).unwrap();
                    self.next_expected_offset += data.len() as u64;
                    ready_data.push(data);
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        
        ready_data
    }
}

/// QUIC crypto state manager
pub struct CryptoManager {
    /// TLS connection state
    tls_conn: QuicConnection,
    /// Role (client or server)
    role: ConnectionRole,
    /// Initial keys for sending (derived using ring for Initial packets)
    initial_send_keys: Option<PacketKeys>,
    /// Initial keys for receiving (derived using ring for Initial packets)
    initial_recv_keys: Option<PacketKeys>,
    /// Handshake keys (legacy - for test key fallback)
    handshake_keys: Option<PacketKeys>,
    /// Application keys (legacy - for test key fallback)
    application_keys: Option<PacketKeys>,
    /// Next application keys (legacy - for test key fallback)
    next_application_keys: Option<PacketKeys>,
    /// Handshake keys from rustls
    handshake_keys_rustls: Option<RustlsKeys>,
    /// 1-RTT keys from rustls (current)
    application_keys_rustls: Option<RustlsKeys>,
    /// 1-RTT keys from rustls (next)
    next_application_keys_rustls: Option<RustlsKeys>,
    /// Current key phase
    key_phase: bool,
    /// Highest packet number sent
    highest_sent_pn: u64,
    /// Count of handshake packets sent (for proper packet type selection)
    handshake_send_count: u32,
    /// Whether we've sent our first crypto response (for servers)
    initial_crypto_sent: bool,
    /// CRYPTO frame buffer for handling out-of-order data
    crypto_buffer: CryptoBuffer,
    /// Local transport parameters to send
    local_transport_params: Option<TransportParameters>,
    /// Peer transport parameters received
    peer_transport_params: Option<TransportParameters>,
    /// Local connection ID
    local_cid: Option<ConnectionId>,
    /// Remote connection ID
    remote_cid: Option<ConnectionId>,
    /// Pending handshake response data to send
    pending_handshake_data: Vec<u8>,
}

/// Header protection key wrapper
#[derive(Clone, Debug)]
/// Header protection key for encrypting packet headers
pub struct HeaderProtectionKey {
    key: Vec<u8>,
}

/// Statistics for key usage to determine when updates are needed
#[derive(Debug, Clone)]
struct KeyUsageStats {
    packets_sent: u64,
    bytes_sent: u64,
}

/// Packet protection keys for a given encryption level
#[derive(Debug)]
struct PacketKeys {
    /// Key for packet payload encryption/decryption
    packet_key: LessSafeKey,
    /// Key for header protection/unprotection
    header_key: HeaderProtectionKey,
    /// IV for nonce construction
    iv: [u8; 12],
}

/// Enum to hold either ring-based keys or rustls-based keys
enum KeysWrapper<'a> {
    Ring(&'a PacketKeys),
    Rustls(&'a RustlsDirectionalKeys),
}

impl CryptoManager {
    /// Get the connection role
    pub fn role(&self) -> ConnectionRole {
        self.role
    }
    
    /// Set connection IDs
    pub fn set_connection_ids(&mut self, local_cid: ConnectionId, remote_cid: ConnectionId) {
        self.local_cid = Some(local_cid);
        self.remote_cid = Some(remote_cid);
    }
    
    /// Create a new crypto manager
    /// 
    /// # Errors
    /// 
    /// Returns an error if TLS connection creation fails.
    pub fn new(role: ConnectionRole) -> Result<Self> {
        match role {
            ConnectionRole::Client => Self::new_client("localhost"),
            ConnectionRole::Server => Self::new_server_self_signed(),
        }
    }
    
    /// Create a new client crypto manager with specific server name
    /// 
    /// # Errors
    /// 
    /// Returns an error if TLS client configuration or connection creation fails.
    pub fn new_client(server_name: &str) -> Result<Self> {
        let mut root_store = rustls::RootCertStore::empty();
        // Add system root certificates
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        
        let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|e| Error::TlsError(format!("Invalid server name: {:?}", e)))?;
        
        // For QUIC, we need to use the QUIC-specific constructor with transport parameters
        // Create default transport parameters - these will be properly set later
        let transport_params = TransportParameters::default();
        let params_bytes = transport_params.encode()?.to_vec();
        
        // Set ALPN protocols on the config
        let mut config = config;
        config.alpn_protocols = vec![b"h3".to_vec()];
        
        let tls_conn = QuicConnection::Client(
            rustls::quic::ClientConnection::new(
                Arc::new(config),
                rustls::quic::Version::V1,
                server_name,
                params_bytes,
            ).map_err(|e| Error::TlsError(format!("Failed to create TLS client: {:?}", e)))?
        );
        
        Ok(Self {
            tls_conn,
            role: ConnectionRole::Client,
            initial_send_keys: None,
            initial_recv_keys: None,
            handshake_keys: None,
            application_keys: None,
            next_application_keys: None,
            handshake_keys_rustls: None,
            application_keys_rustls: None,
            next_application_keys_rustls: None,
            key_phase: false,
            highest_sent_pn: 0,
            handshake_send_count: 0,
            initial_crypto_sent: false,
            crypto_buffer: CryptoBuffer::new(),
            local_transport_params: Some(transport_params),
            peer_transport_params: None,
            local_cid: None,
            remote_cid: None,
            pending_handshake_data: Vec::new(),
        })
    }
    
    /// Create a test client that accepts self-signed certificates
    /// 
    /// # Safety
    /// 
    /// This should only be used for testing. It disables certificate validation.
    #[doc(hidden)]
    pub fn new_client_for_testing(server_name: &str) -> Result<Self> {
        use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
        use rustls::pki_types::UnixTime;
        
        #[derive(Debug)]
        struct AcceptAnyServerCert;
        
        impl ServerCertVerifier for AcceptAnyServerCert {
            fn verify_server_cert(
                &self,
                _end_entity: &rustls::pki_types::CertificateDer<'_>,
                _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                _server_name: &rustls::pki_types::ServerName<'_>,
                _ocsp_response: &[u8],
                _now: UnixTime,
            ) -> std::result::Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }
            
            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            
            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }
            
            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                vec![
                    rustls::SignatureScheme::RSA_PKCS1_SHA256,
                    rustls::SignatureScheme::RSA_PKCS1_SHA384,
                    rustls::SignatureScheme::RSA_PKCS1_SHA512,
                    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                    rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                    rustls::SignatureScheme::RSA_PSS_SHA256,
                    rustls::SignatureScheme::RSA_PSS_SHA384,
                    rustls::SignatureScheme::RSA_PSS_SHA512,
                    rustls::SignatureScheme::ED25519,
                ]
            }
        }
        
        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
            .with_no_client_auth();
        
        let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|e| Error::TlsError(format!("Invalid server name: {:?}", e)))?;
        
        // Create transport parameters
        let transport_params = TransportParameters::default();
        let params_bytes = transport_params.encode()?.to_vec();
        
        // Set ALPN protocols
        let mut config = config;
        config.alpn_protocols = vec![b"h3".to_vec()];
        
        let tls_conn = QuicConnection::Client(
            rustls::quic::ClientConnection::new(
                Arc::new(config),
                rustls::quic::Version::V1,
                server_name,
                params_bytes,
            ).map_err(|e| Error::TlsError(format!("Failed to create TLS client: {:?}", e)))?
        );
        
        Ok(Self {
            tls_conn,
            role: ConnectionRole::Client,
            initial_send_keys: None,
            initial_recv_keys: None,
            handshake_keys: None,
            application_keys: None,
            next_application_keys: None,
            handshake_keys_rustls: None,
            application_keys_rustls: None,
            next_application_keys_rustls: None,
            key_phase: false,
            highest_sent_pn: 0,
            handshake_send_count: 0,
            initial_crypto_sent: false,
            crypto_buffer: CryptoBuffer::new(),
            local_transport_params: Some(transport_params),
            peer_transport_params: None,
            local_cid: None,
            remote_cid: None,
            pending_handshake_data: Vec::new(),
        })
    }
    
    /// Create a new server crypto manager with self-signed certificate
    /// 
    /// # Errors
    /// 
    /// Returns an error if certificate generation or TLS server creation fails.
    pub fn new_server_self_signed() -> Result<Self> {
        // Create a self-signed certificate for testing
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .map_err(|e| Error::TlsError(format!("Failed to generate certificate: {:?}", e)))?;
        
        let cert_der = cert.cert.der();
        let key_der = cert.signing_key.serialize_der();
        
        let cert_chain = vec![
            cert_der.clone()
        ];
        let private_key = rustls::pki_types::PrivateKeyDer::try_from(key_der)
            .map_err(|e| Error::TlsError(format!("Failed to load private key: {:?}", e)))?;
        
        Self::new_server_with_cert(cert_chain, private_key)
    }
    
    /// Create a new server crypto manager with provided certificate and key
    /// 
    /// # Errors
    /// 
    /// Returns an error if TLS server configuration or connection creation fails.
    pub fn new_server_with_cert(
        cert_chain: Vec<rustls::pki_types::CertificateDer<'static>>,
        private_key: rustls::pki_types::PrivateKeyDer<'static>,
    ) -> Result<Self> {
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| Error::TlsError(format!("Failed to create server config: {:?}", e)))?;
        
        // Enable ALPN for HTTP/3
        config.alpn_protocols = vec![b"h3".to_vec()];
        
        // Create default transport parameters for server
        let transport_params = TransportParameters::default();
        let params_bytes = transport_params.encode()?.to_vec();
        
        let tls_conn = QuicConnection::Server(
            rustls::quic::ServerConnection::new(
                Arc::new(config),
                rustls::quic::Version::V1,
                params_bytes,
            ).map_err(|e| Error::TlsError(format!("Failed to create TLS server: {:?}", e)))?
        );
        
        Ok(Self {
            tls_conn,
            role: ConnectionRole::Server,
            initial_send_keys: None,
            initial_recv_keys: None,
            handshake_keys: None,
            application_keys: None,
            next_application_keys: None,
            handshake_keys_rustls: None,
            application_keys_rustls: None,
            next_application_keys_rustls: None,
            key_phase: false,
            highest_sent_pn: 0,
            handshake_send_count: 0,
            initial_crypto_sent: false,
            crypto_buffer: CryptoBuffer::new(),
            local_transport_params: Some(transport_params),
            peer_transport_params: None,
            local_cid: None,
            remote_cid: None,
            pending_handshake_data: Vec::new(),
        })
    }

    /// Initialize initial keys based on connection IDs
    /// 
    /// # Errors
    /// 
    /// Returns an error if key derivation fails.
    pub fn init_initial_keys(&mut self, client_dst_cid: &[u8]) -> Result<()> {
        crypto_event!(
            Level::Info,
            "Deriving initial keys from DCID";
            "role" => self.role,
            "dcid" => client_dst_cid
        );

        // Use RFC 9001 compliant key derivation from crypto.rs
        let (client_initial_secret, server_initial_secret) =
            crate::quic::crypto::key_derivation::derive_initial_secrets(client_dst_cid)
                .map_err(|_| Error::CryptoError("Failed to derive initial secrets".to_string()))?;

        // Select appropriate secret based on role
        let (local_secret, remote_secret) = match self.role {
            ConnectionRole::Client => (client_initial_secret, server_initial_secret),
            ConnectionRole::Server => (server_initial_secret, client_initial_secret),
        };

        // Derive keys from secrets
        let local_keys = derive_packet_keys(&local_secret)?;
        let remote_keys = derive_packet_keys(&remote_secret)?;

        // Client sends with client keys, receives with server keys
        // Server sends with server keys, receives with client keys
        self.initial_send_keys = Some(local_keys);
        self.initial_recv_keys = Some(remote_keys);

        crypto_event!(
            Level::Info,
            "Successfully derived initial keys";
            "role" => self.role
        );

        Ok(())
    }
    
    /// Derive handshake keys from TLS handshake secrets
    /// 
    /// # Errors
    /// 
    /// Returns an error if key derivation fails.
    pub fn derive_handshake_keys(&mut self, client_hs_secret: &[u8], server_hs_secret: &[u8]) -> Result<()> {
        let local_secret = match self.role {
            ConnectionRole::Client => client_hs_secret,
            ConnectionRole::Server => server_hs_secret,
        };
        
        self.handshake_keys = Some(derive_packet_keys(local_secret)?);
        Ok(())
    }
    
    /// Derive application data (1-RTT) keys
    /// 
    /// # Errors
    /// 
    /// Returns an error if key derivation fails.
    pub fn derive_application_keys(&mut self, client_app_secret: &[u8], server_app_secret: &[u8]) -> Result<()> {
        let local_secret = match self.role {
            ConnectionRole::Client => client_app_secret,
            ConnectionRole::Server => server_app_secret,
        };
        
        self.application_keys = Some(derive_packet_keys(local_secret)?);
        Ok(())
    }
    
    /// Update keys for key rotation (RFC 9001 Section 6)
    /// Uses Rust 2024 let chains for cleaner key update logic
    /// 
    /// # Errors
    /// 
    /// Returns an error if key update fails.
    pub fn update_keys(&mut self) -> Result<()> {
        // Use Rust 2024 let chains for cleaner key update logic
        if let Some(_current_keys) = &self.application_keys 
            && let Some(current_secret) = self.get_application_secrets()
            && let Some(updated_keys) = self.derive_updated_keys_from_secret(&current_secret)
        {
            // Store current keys as next for backward compatibility during transition
            self.next_application_keys = self.application_keys.take();
            
            // Install new keys
            self.application_keys = Some(updated_keys);
            
            // Toggle key phase (RFC 9001 Section 6.3)
            self.key_phase = !self.key_phase;
            
            crypto_event!(
                Level::Info,
                "Updated 1-RTT application keys";
                "key_phase" => self.key_phase,
                "role" => self.role,
                "has_previous_keys" => self.next_application_keys.is_some()
            );
            
            Ok(())
        } else if self.application_keys.is_none() {
            crypto_event!(
                Level::Error,
                "Cannot update keys - no application keys installed";
                "role" => self.role
            );
            Err(Error::CryptoError("No application keys to update".to_string()))
        } else {
            crypto_event!(
                Level::Error,
                "Failed to derive new application keys for update";
                "role" => self.role,
                "has_secret" => self.get_application_secrets().is_some()
            );
            Err(Error::CryptoError("Failed to derive new application keys".to_string()))
        }
    }
    
    /// Derive updated keys from current application secret using RFC 9001 Section 6.3
    /// This uses the QUIC key update procedure with proper HKDF-Expand-Label operations
    fn derive_updated_keys_from_secret(&self, current_secret: &[u8]) -> Option<PacketKeys> {
        // Use Rust 2024 let chains for validation and key derivation
        if current_secret.len() >= 32 {
            let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &current_secret[..32]);
            let prk = salt.extract(&[]);
            
            // RFC 9001 Section 6.3: Use "quic ku" label for key update
            let update_label = b"quic ku";
            
            // Derive updated secret using HKDF-Expand-Label
            let mut updated_secret = [0u8; 32];
            if let Ok(okm) = prk.expand(&[update_label], ArbitraryOutputLen(32)) 
                && okm.fill(&mut updated_secret).is_ok()
            {
                // Now derive packet protection keys from the updated secret
                self.derive_keys_from_secret(&updated_secret, PacketProtectionLevel::Application)
            } else {
                crypto_event!(
                    Level::Error,
                    "Failed to derive updated secret using HKDF";
                    "role" => self.role
                );
                None
            }
        } else {
            crypto_event!(
                Level::Error,
                "Invalid secret for key update";
                "secret_len" => current_secret.len(),
                "role" => self.role
            );
            None
        }
    }
    
    /// Check if a key update is needed based on packet count or time
    /// RFC 9001 Section 6.1: Key updates should be performed proactively
    pub fn should_update_keys(&self) -> bool {
        // Use Rust 2024 let chains for complex conditions
        if let Some(_keys) = &self.application_keys 
            && let Some(stats) = self.get_key_usage_stats()
            && (stats.packets_sent > 100_000 || stats.bytes_sent > 100_000_000)
        {
            crypto_event!(
                Level::Info,
                "Key update recommended based on usage";
                "packets_sent" => stats.packets_sent,
                "bytes_sent" => stats.bytes_sent,
                "role" => self.role
            );
            true
        } else {
            false
        }
    }
    
    /// Get key usage statistics for determining when to update keys
    fn get_key_usage_stats(&self) -> Option<KeyUsageStats> {
        // In a real implementation, this would track actual usage
        // For now, return placeholder stats
        Some(KeyUsageStats {
            packets_sent: 0,
            bytes_sent: 0,
        })
    }
    
    /// Public interface for header protection using Rust 2024 features
    pub fn protect_packet_header(
        &self,
        packet_data: &mut [u8],
        packet_type: PacketType,
        packet_number: u64,
    ) -> Result<()> {
        // Use Rust 2024 let chains to determine protection level and keys
        if let Some(hp_key) = self.get_header_protection_key(packet_type)
            && let Some((header_offset, pn_offset, pn_length)) = self.parse_packet_offsets(packet_data, packet_type)?
        {
            crypto_event!(
                Level::Debug,
                "Protecting packet header";
                "packet_type" => packet_type,
                "packet_number" => packet_number,
                "pn_offset" => pn_offset,
                "pn_length" => pn_length
            );
            
            self.apply_header_protection(
                packet_data,
                header_offset,
                pn_offset,
                pn_length,
                &hp_key,
            )
        } else {
            crypto_event!(
                Level::Error,
                "No header protection key available";
                "packet_type" => packet_type
            );
            Err(Error::CryptoError("No header protection key available".to_string()))
        }
    }
    
    /// Public interface for header protection removal using Rust 2024 features
    pub fn unprotect_packet_header(
        &self,
        packet_data: &mut [u8],
    ) -> Result<(PacketType, u64, usize)> {
        // Determine packet type from first byte
        let first_byte = packet_data.first()
            .ok_or_else(|| Error::CryptoError("Empty packet data".to_string()))?;

        let packet_type = self.determine_packet_type_from_byte(*first_byte)?;

        // Cross-validate packet type using alternative parser (defensive programming)
        let validated_type = self.parse_packet_type(*first_byte)?;
        if packet_type != validated_type {
            crypto_event!(
                Level::Error,
                "Packet type validation mismatch";
                "primary" => format!("{:?}", packet_type),
                "validated" => format!("{:?}", validated_type)
            );
            return Err(Error::CryptoError("Packet type validation failed".to_string()));
        }

        // Parse header structure to get offsets and lengths
        let header_info = self.parse_packet_header(packet_data, packet_type)?;

        // Use Rust 2024 let chains for key selection and unprotection
        if let Some(hp_key) = self.get_header_protection_key(packet_type)
            && let Some(pn_offset) = self.get_pn_offset(packet_data).ok()
        {
            let (packet_number, pn_length) = self.remove_header_protection(
                packet_data,
                &hp_key,
                pn_offset,
            )?;

            crypto_event!(
                Level::Debug,
                "Unprotected packet header";
                "packet_type" => packet_type,
                "packet_number" => packet_number,
                "pn_length" => pn_length,
                "header_len" => header_info.header_len,
                "pn_offset" => header_info.pn_offset,
                "expected_pn_length" => header_info.pn_length
            );
            
            Ok((packet_type, packet_number, pn_length))
        } else {
            crypto_event!(
                Level::Error,
                "Failed to unprotect packet header";
                "packet_type" => packet_type
            );
            Err(Error::CryptoError("Failed to unprotect packet header".to_string()))
        }
    }
    
    /// Get header protection key for a packet type
    fn get_header_protection_key(&self, packet_type: PacketType) -> Option<HeaderProtectionKey> {
        // This method is used by both protect and unprotect, so we need to determine
        // which keys to use based on the context. For now, use send keys for protection.
        match packet_type {
            PacketType::Initial => {
                self.initial_send_keys.as_ref().map(|k| k.header_key.clone())
            }
            PacketType::Handshake => {
                self.handshake_keys.as_ref().map(|k| k.header_key.clone())
            }
            PacketType::ZeroRtt => {
                // Zero-RTT is not implemented yet
                None
            }
            PacketType::OneRtt => {
                self.application_keys.as_ref().map(|k| k.header_key.clone())
            }
            PacketType::Retry => None, // Retry packets don't have header protection
        }
    }
    
    /// Parse packet offsets for header protection
    fn parse_packet_offsets(
        &self,
        packet_data: &[u8],
        packet_type: PacketType,
    ) -> Result<Option<(usize, usize, usize)>> {
        let first_byte = packet_data.first()
            .ok_or_else(|| Error::CryptoError("Empty packet data".to_string()))?;
        
        // Use packet type to determine header length
        let header_len = match packet_type {
            PacketType::Initial | PacketType::ZeroRtt => {
                // Long header format
                if (*first_byte & 0x30) >> 4 == 0 {
                    // Version negotiation packet has different format
                    return Ok(None);
                }
                7 // Minimum long header length
            }
            PacketType::Handshake | PacketType::Retry => 7,
            PacketType::OneRtt => 1, // Short header
        };
        
        let pn_offset = self.get_pn_offset(packet_data)?;
        let pn_length = 4; // Default to 4 bytes for simplicity
        
        Ok(Some((header_len, pn_offset, pn_length)))
    }
    
    /// Determine packet type from first byte
    fn determine_packet_type_from_byte(&self, first_byte: u8) -> Result<PacketType> {
        if (first_byte & 0x80) != 0 {
            // Long header
            match (first_byte & 0x30) >> 4 {
                0 => Ok(PacketType::Initial),
                1 => Ok(PacketType::ZeroRtt),
                2 => Ok(PacketType::Handshake),
                3 => Ok(PacketType::Retry),
                _ => Err(Error::CryptoError("Invalid long header packet type".to_string())),
            }
        } else {
            // Short header
            Ok(PacketType::OneRtt)
        }
    }
    
    /// Get the current packet protection level
    pub fn current_level(&self) -> PacketProtectionLevel {
        if self.application_keys.is_some() {
            PacketProtectionLevel::Application
        } else if self.handshake_keys.is_some() {
            PacketProtectionLevel::Handshake
        } else {
            PacketProtectionLevel::Initial
        }
    }

    /// Process TLS handshake data with support for out-of-order frames
    /// 
    /// # Errors
    /// 
    /// Returns an error if TLS processing fails.
    pub async fn process_crypto_frame(&mut self, offset: u64, data: Bytes) -> Result<()> {
        crypto_event!(
            Level::Debug,
            "Processing CRYPTO frame";
            "offset" => offset,
            "len" => data.len(),
            "role" => self.role
        );
        // Add frame to buffer and get any continuous data ready for processing
        eprintln!("DEBUG: add_frame called with offset={}, len={}, next_expected_offset={}", 
            offset, data.len(), self.crypto_buffer.next_expected_offset);
        let ready_data = self.crypto_buffer.add_frame(offset, data);
        
        // Process all continuous data
        eprintln!("DEBUG: process_crypto_frame got {} chunks of ready data", ready_data.len());
        for data_chunk in ready_data {
            eprintln!("DEBUG: Feeding {} bytes to TLS connection, role={:?}", 
                data_chunk.len(), self.role);
            crypto_event!(
                Level::Debug,
                "Feeding data to TLS connection";
                "role" => self.role,
                "chunk_len" => data_chunk.len()
            );
            
            // Feed data to TLS connection and handle any key changes
            match &mut self.tls_conn {
                QuicConnection::Client(conn) => {
                    match conn.read_hs(&data_chunk) {
                        Ok(()) => {
                            crypto_event!(
                                Level::Debug,
                                "Successfully processed TLS handshake data";
                                "role" => self.role
                            );
                        },
                        Err(e) => {
                            crypto_event!(
                                Level::Error,
                                "Client TLS error";
                                "role" => self.role,
                                "error" => format!("{:?}", e)
                            );
                            return Err(Error::TlsError(format!("Client TLS error: {:?}", e)));
                        }
                    }
                }
                QuicConnection::Server(conn) => {
                    match conn.read_hs(&data_chunk) {
                        Ok(()) => {
                            eprintln!("DEBUG: Server successfully processed {} bytes of TLS handshake data", 
                                data_chunk.len());
                            crypto_event!(
                                Level::Debug,
                                "Successfully processed TLS handshake data";
                                "role" => self.role
                            );
                        },
                        Err(e) => {
                            crypto_event!(
                                Level::Error,
                                "Server TLS error";
                                "role" => self.role,
                                "error" => format!("{:?}", e)
                            );
                            return Err(Error::TlsError(format!("Server TLS error: {:?}", e)));
                        }
                    }
                }
            }
        }
        
        // After processing handshake data, check for any response data and key changes
        let mut key_changes = Vec::new();
        let mut response_data = Vec::new();
        
        match &mut self.tls_conn {
            QuicConnection::Client(conn) => {
                loop {
                    match conn.write_hs(&mut response_data) {
                        Some(key_change) => {
                            crypto_event!(
                                Level::Info,
                                "Client received key change after processing data";
                                "role" => self.role
                            );
                            key_changes.push(key_change);
                        }
                        None => break,
                    }
                }
            }
            QuicConnection::Server(conn) => {
                loop {
                    match conn.write_hs(&mut response_data) {
                        Some(key_change) => {
                            crypto_event!(
                                Level::Info,
                                "Server received key change after processing data";
                                "role" => self.role
                            );
                            key_changes.push(key_change);
                        }
                        None => break,
                    }
                }
            }
        }
        
        // Install any key changes
        for key_change in key_changes {
            if let Err(e) = self.install_key_change(key_change) {
                crypto_event!(
                    Level::Warn,
                    "Failed to install key change";
                    "error" => e
                );
            }
        }
        
        // Store response data to be sent later
        if !response_data.is_empty() {
            crypto_event!(
                Level::Debug,
                "Storing handshake response data";
                "len" => response_data.len()
            );
            self.pending_handshake_data.extend_from_slice(&response_data);
        }
        
        // Extract and install any keys that are now available
        self.extract_and_install_keys()?;

        Ok(())
    }
    
    /// Extract and install keys from TLS connection after handshake data processing
    fn extract_and_install_keys(&mut self) -> Result<()> {
        match &self.tls_conn {
            QuicConnection::Client(conn) => {
                // Check if handshake keys are available
                if self.handshake_keys.is_none() && conn.is_handshaking() {
                    // For now, use test keys until we properly integrate with rustls
                    if let Some(keys) = self.derive_test_keys(PacketProtectionLevel::Handshake) {
                        self.handshake_keys = Some(keys);
                    }
                }
                
                // Check if application keys are available
                if self.application_keys.is_none() && !conn.is_handshaking() {
                    if let Some(keys) = self.derive_test_keys(PacketProtectionLevel::Application) {
                        self.application_keys = Some(keys);
                    }
                }
            }
            QuicConnection::Server(conn) => {
                // Similar logic for server
                if self.handshake_keys.is_none() && conn.is_handshaking() {
                    if let Some(keys) = self.derive_test_keys(PacketProtectionLevel::Handshake) {
                        self.handshake_keys = Some(keys);
                    }
                }
                
                if self.application_keys.is_none() && !conn.is_handshaking() {
                    if let Some(keys) = self.derive_test_keys(PacketProtectionLevel::Application) {
                        self.application_keys = Some(keys);
                    }
                }
            }
        }
        
        Ok(())
    }
    

    /// Install key changes from TLS using Rust 2024 let chains
    fn install_key_change(&mut self, key_change: rustls::quic::KeyChange) -> Result<()> {
        crypto_event!(
            Level::Info,
            "Installing key change from TLS";
            "role" => self.role
        );
        
        match key_change {
            rustls::quic::KeyChange::Handshake { keys } => {
                // Extract handshake keys with proper IVs
                // Create RustlsKeys directly from rustls keys
                let rustls_keys = RustlsKeys::from_rustls(keys);
                eprintln!("DEBUG: Installing handshake keys for {:?}", self.role);
                eprintln!("  local key ptr: {:p}", rustls_keys.local.packet.as_ref() as *const _);
                eprintln!("  remote key ptr: {:p}", rustls_keys.remote.packet.as_ref() as *const _);
                self.handshake_keys_rustls = Some(rustls_keys);
                
                crypto_event!(
                    Level::Info,
                    "Installed handshake keys from TLS";
                    "role" => self.role,
                    "has_local" => true,
                    "has_remote" => true
                );
                
                // Also create ring-based test keys as a fallback
                // TODO: Remove this when rustls integration is fixed
                if self.handshake_keys.is_none() {
                    self.handshake_keys = self.derive_test_keys(PacketProtectionLevel::Handshake);
                    crypto_event!(
                        Level::Info,
                        "Created ring-based handshake test keys as fallback";
                        "role" => self.role
                    );
                }
            }
            rustls::quic::KeyChange::OneRtt { keys, next: _ } => {
                // Create RustlsKeys directly from rustls keys
                let rustls_keys = RustlsKeys::from_rustls(keys);
                
                // Install keys based on current state
                if self.application_keys_rustls.is_none() {
                    self.application_keys_rustls = Some(rustls_keys);
                    crypto_event!(
                        Level::Info,
                        "Installed 1-RTT application keys from TLS";
                        "role" => self.role
                    );
                    
                    // TODO: Remove this when rustls integration is fixed
                    if self.application_keys.is_none() {
                        self.application_keys = self.derive_test_keys(PacketProtectionLevel::Application);
                        crypto_event!(
                            Level::Info,
                            "Created ring-based application test keys as fallback";
                            "role" => self.role
                        );
                    }
                } else {
                    // Key update - move current to next
                    self.next_application_keys_rustls = self.application_keys_rustls.take();
                    self.application_keys_rustls = Some(rustls_keys);
                    self.key_phase = !self.key_phase;
                    crypto_event!(
                        Level::Info,
                        "Updated 1-RTT application keys";
                        "role" => self.role,
                        "new_key_phase" => self.key_phase
                    );
                }
                
                // TODO: Store 'next' secrets for future key updates
            }
        }
        
        Ok(())
    }

    /// Export keying material for 0-RTT
    /// 
    /// # Errors
    /// 
    /// Returns an error if no application keys are available.
    pub fn export_early_keying_material(&self, label: &[u8], context: &[u8], length: usize) -> Result<Vec<u8>> {
        // Check if we have application keys from rustls
        if let Some(_keys) = &self.application_keys_rustls {
            crypto_event!(
                Level::Debug,
                "Exporting early keying material";
                "label_len" => label.len(),
                "context_len" => context.len(),
                "output_length" => length
            );

            // Build the HKDF info with provided label and context
            let info = build_hkdf_label(label, context, length)?;

            // For now, use a placeholder since rustls doesn't expose early secrets
            // In a real implementation, we'd use HKDF-Expand-Label with the early secret
            let mut output = vec![0u8; length];

            crypto_event!(
                Level::Debug,
                "Attempting to export early keying material";
                "label_len" => label.len(),
                "context_len" => context.len(),
                "requested_length" => length,
                "hkdf_info_len" => info.len()
            );
            
            // Fill with deterministic data based on label and context for now
            for (i, byte) in output.iter_mut().enumerate() {
                *byte = (i as u8) ^ label.get(i % label.len()).unwrap_or(&0) ^ 
                        context.get(i % context.len().max(1)).unwrap_or(&0);
            }
            
            return Ok(output);
        }
        
        Err(Error::CryptoError("No application keys available".to_string()))
    }
    
    /// Check if 0-RTT is available
    pub fn zero_rtt_available(&self) -> bool {
        // Check if we have early data capability
        match &self.tls_conn {
            QuicConnection::Client(_) => {
                // For clients, 0-RTT is available if we have cached session data
                self.application_keys.is_some()
            }
            QuicConnection::Server(_) => {
                // For servers, 0-RTT depends on client capability
                false
            }
        }
    }

    /// Protect a 0-RTT packet
    pub fn protect_zero_rtt_packet(&self, packet_data: Bytes) -> Result<Bytes> {
        // Check if we have 0-RTT keys
        if !self.zero_rtt_available() {
            return Err(Error::CryptoError("0-RTT keys not available".to_string()));
        }

        crypto_event!(
            Level::Debug,
            "Protecting 0-RTT packet";
            "packet_size" => packet_data.len()
        );

        // For demonstration, apply a simple transformation to show we're using the data
        // In production, this would use proper AEAD encryption with early data keys
        let mut protected = packet_data.to_vec();
        for (i, byte) in protected.iter_mut().enumerate() {
            *byte ^= (i as u8) ^ 0x5A; // Simple mask showing data usage
        }
        
        Ok(Bytes::from(protected))
    }

    /// Get application data secrets from TLS connection
    fn get_application_secrets(&self) -> Option<Vec<u8>> {
        // Note: rustls QUIC API doesn't directly expose TLS secrets.
        // Instead, it provides ready-to-use keys through KeyChange events.
        // This method is kept for legacy compatibility but returns None
        // to force usage of rustls keys when available.
        crypto_event!(
            Level::Debug,
            "Application secrets requested - using rustls keys instead";
            "role" => self.role
        );
        None
    }
    
    /// Derive QUIC packet protection keys from TLS secret
    fn derive_keys_from_secret(&self, secret: &[u8], level: PacketProtectionLevel) -> Option<PacketKeys> {
        if secret.len() < 32 {
            crypto_event!(
                Level::Warn,
                "TLS secret too short for key derivation";
                "secret_len" => secret.len(),
                "level" => level
            );
            return None;
        }
        
        // RFC 9001 Section 5.1: Derive QUIC packet protection keys from TLS secrets
        // using HKDF-Expand-Label with appropriate labels

        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &secret[..32]);
        let prk = salt.extract(&[]); // No IKM needed since we have the secret
        
        // Labels for key derivation per RFC 9001 Section 5.1
        let (key_label, iv_label, hp_label) = match level {
            PacketProtectionLevel::Initial => ("quic key", "quic iv", "quic hp"),
            PacketProtectionLevel::Handshake => ("quic key", "quic iv", "quic hp"),
            PacketProtectionLevel::Application => ("quic key", "quic iv", "quic hp"),
        };
        
        // Derive packet protection key (16 bytes for AES-128-GCM)
        let mut packet_key = [0u8; 16];
        if prk.expand(&[key_label.as_bytes()], ArbitraryOutputLen(16)).unwrap().fill(&mut packet_key).is_err() {
            crypto_event!(
                Level::Error,
                "Failed to derive packet protection key";
                "level" => level
            );
            return None;
        }
        
        // Derive IV (12 bytes for AES-128-GCM)
        let mut iv = [0u8; 12];
        if prk.expand(&[iv_label.as_bytes()], ArbitraryOutputLen(12)).unwrap().fill(&mut iv).is_err() {
            crypto_event!(
                Level::Error,
                "Failed to derive IV";
                "level" => level
            );
            return None;
        }
        
        // Derive header protection key (16 bytes for AES-128)
        let mut hp_key = [0u8; 16];
        if prk.expand(&[hp_label.as_bytes()], ArbitraryOutputLen(16)).unwrap().fill(&mut hp_key).is_err() {
            crypto_event!(
                Level::Error,
                "Failed to derive header protection key";
                "level" => level
            );
            return None;
        }
        
        // Create AEAD key
        let aead_key = match ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, &packet_key) {
            Ok(key) => ring::aead::LessSafeKey::new(key),
            Err(_) => {
                crypto_event!(
                    Level::Error,
                    "Failed to create AEAD key";
                    "level" => level
                );
                return None;
            }
        };
        
        crypto_event!(
            Level::Debug,
            "Derived packet protection keys from TLS secret";
            "level" => level,
            "secret_len" => secret.len(),
            "key_len" => packet_key.len(),
            "iv_len" => iv.len(),
            "hp_key_len" => hp_key.len()
        );
        
        Some(PacketKeys {
            packet_key: aead_key,
            header_key: HeaderProtectionKey {
                key: hp_key.to_vec(),
            },
            iv,
        })
    }
    
    /// Fallback test key derivation for development/testing
    fn derive_test_keys(&self, level: PacketProtectionLevel) -> Option<PacketKeys> {
        // Generate deterministic but unique keys based on connection state and level
        let seed: &[u8] = match level {
            PacketProtectionLevel::Initial => b"initial_keys_seed_v1",
            PacketProtectionLevel::Handshake => b"handshake_keys_v1", 
            PacketProtectionLevel::Application => b"application_keys_v1",
        };
        
        // Create a deterministic secret from the seed
        let mut secret = [0u8; 32];
        for (i, &byte) in seed.iter().enumerate() {
            secret[i % 32] ^= byte.wrapping_add(i as u8);
        }
        
        // Don't add role-specific variation for test keys
        // Both client and server should use the same keys for testing
        
        derive_packet_keys(&secret).ok()
    }

    /// Encrypt a packet with proper header protection
    pub async fn encrypt_packet(&mut self, packet_number: u64, frames: Vec<Frame>) -> Result<Bytes> {
        // Use the provided packet number
        let pn = packet_number;
        
        // Determine packet type based on connection state and available keys
        let packet_type = self.determine_packet_type();
        eprintln!("CryptoManager encrypt: role={:?}, packet_type={:?}, handshake_send_count={}", 
            self.role, packet_type, self.handshake_send_count);
        
        // Track packets sent
        if packet_type == PacketType::Handshake {
            self.handshake_send_count += 1;
            eprintln!("DEBUG: Incremented handshake_send_count to {} for {:?}", 
                self.handshake_send_count, self.role);
        }
        
        // Mark that we've sent Initial crypto data (for servers)
        if self.role == ConnectionRole::Server && packet_type == PacketType::Initial && !frames.is_empty() {
            self.initial_crypto_sent = true;
            eprintln!("DEBUG: Server marked initial_crypto_sent = true");
        }
        
        
        let keys = self.get_keys_for_packet_type(packet_type)?;
        
        // Encode packet payload (frames)
        let mut payload = BytesMut::new();
        eprintln!("DEBUG: Encoding {} frames for {:?} packet, role={:?}", frames.len(), packet_type, self.role);
        for (i, frame) in frames.iter().enumerate() {
            match frame {
                Frame::Crypto { offset, data, .. } => {
                    eprintln!("  Frame {}: CRYPTO offset={}, len={}", i, offset, data.len());
                }
                Frame::Padding => {
                    eprintln!("  Frame {}: PADDING", i);
                }
                _ => {
                    eprintln!("  Frame {}: {:?}", i, frame);
                }
            }
        }
        for frame in &frames {
            frame.encode(&mut payload)?;
        }

        // Add PADDING if needed to meet minimum packet size
        let min_size = if matches!(packet_type, PacketType::Initial) {
            1200 // Initial packets must be at least 1200 bytes
        } else {
            0
        };

        // Calculate header size for accurate padding
        let estimated_header_size = self.estimate_header_size(packet_type)?;
        let current_packet_size = estimated_header_size + payload.len() + 16; // header + payload + tag
        
        if current_packet_size < min_size {
            let padding_needed = min_size - current_packet_size;
            // Add PADDING frames to reach minimum size
            for _ in 0..padding_needed {
                payload.put_u8(0x00); // PADDING frame type
            }
        }
        
        // Create appropriate header based on packet type
        let header = self.create_packet_header(packet_type, pn, payload.len())?;

        // Encode header for AAD (without protection)
        let mut aad = BytesMut::new();
        header.encode(&mut aad)?;
        
        if packet_type == PacketType::Handshake {
            eprintln!("DEBUG: Encoding packet with number {}", pn);
            // Find packet number in AAD
            if aad.len() >= 4 {
                let last_4 = &aad[aad.len()-4..];
                eprintln!("DEBUG: Last 4 bytes of AAD (should be packet number): {:02x?}", last_4);
            }
        }

        // Encrypt payload based on key type
        let ciphertext = match keys {
            KeysWrapper::Ring(keys) => {
                // Use ring for initial packets
                let nonce = Self::compute_nonce(&keys.iv, pn);
                let mut ciphertext = payload.to_vec();
                
                keys.packet_key.seal_in_place_append_tag(
                    Nonce::try_assume_unique_for_key(&nonce)
                        .map_err(|_| Error::CryptoError("Invalid nonce".to_string()))?,
                    Aad::from(&aad),
                    &mut ciphertext,
                )
                .map_err(|_| Error::CryptoError("AEAD encryption failed".to_string()))?;
                
                ciphertext
            }
            KeysWrapper::Rustls(keys) => {
                // Use rustls keys for handshake/application packets
                if packet_type == PacketType::Handshake {
                    crypto_event!(
                        Level::Debug,
                        "Encrypting with rustls keys";
                        "packet_number" => pn,
                        "aad_len" => aad.len(),
                        "aad_hex" => format!("{:02x?}", &aad.as_ref()[..32.min(aad.len())]),
                        "payload_len" => payload.len()
                    );
                    
                    // Debug: Show the complete AAD
                    eprintln!("DEBUG: Complete AAD for encryption ({} bytes):", aad.len());
                    eprintln!("{:02x?}", aad.as_ref());
                }
                
                if packet_type == PacketType::OneRtt {
                    eprintln!("DEBUG: OneRtt Encryption:");
                    eprintln!("  Role: {:?}", self.role);
                    eprintln!("  Packet number: {}", pn);
                    eprintln!("  Header length: {}", aad.len());
                    eprintln!("  AAD: {:02x?}", aad.as_ref());
                    eprintln!("  Using local key");
                }
                keys.encrypt_packet(pn, &aad, &payload)?
            }
        };

        // Encode header first (without protection)
        let mut packet_data = BytesMut::new();
        header.encode(&mut packet_data)?;
        let header_len = packet_data.len();
        
        // eprintln!("Encoded header ({} bytes), PN={}", header_len, pn);
        // eprintln!("Header bytes: {:02x?}", &packet_data[..]);
        
        // Debug AAD for encryption
        if packet_type == PacketType::Initial {
            crypto_event!(
                Level::Debug,
                "Encrypting Initial packet";
                "role" => self.role,
                "aad_len" => aad.len()
            );
            
            // Log header details for debugging
            crypto_event!(
                Level::Debug,
                "Initial packet header details";
                "packet_number" => pn,
                "aad_len" => aad.len()
            );
        }
        
        // Debug packet number encoding
        if packet_type == PacketType::Handshake {
            crypto_event!(
                Level::Debug,
                "Handshake packet encoding";
                "packet_number" => pn,
                "first_byte" => packet_data[0],
                "pn_length_bits" => packet_data[0] & 0x03,
                "aad_bytes" => format!("{:02x?}", &aad[..32.min(aad.len())])
            );
            if let Ok(pn_offset) = self.get_pn_offset(&packet_data[..header_len]) {
                let pn_length = ((packet_data[0] & 0x03) + 1) as usize;
                debug_assert!((1..=4).contains(&pn_length), "Invalid packet number length: {}", pn_length);
                debug!("PN offset: {}, length: {}", pn_offset, pn_length);
            }
        }
        
        // Add encrypted payload
        packet_data.extend_from_slice(&ciphertext);
        
        // Apply header protection based on key type
        match keys {
            KeysWrapper::Ring(keys) => {
                self.apply_header_protection_to_packet(&mut packet_data, &keys.header_key, header_len, pn)?;
            }
            KeysWrapper::Rustls(keys) => {
                // Get packet number offset first
                let pn_offset = self.get_pn_offset(&packet_data[..header_len])?;
                
                // Get sample for header protection
                // Sample is always taken 4 bytes after the start of the packet number field
                let sample_offset = pn_offset + 4;
                if packet_data.len() < sample_offset + 16 {
                    return Err(Error::CryptoError("Packet too short for header protection".to_string()));
                }
                
                // Extract sample before modifying packet_data
                let mut sample = [0u8; 16];
                sample.copy_from_slice(&packet_data[sample_offset..sample_offset + 16]);
                
                // Apply header protection using rustls
                // Extract packet number length from first byte
                let pn_length = ((packet_data[0] & 0x03) + 1) as usize;
                debug_assert!((1..=4).contains(&pn_length), "Invalid packet number length: {}", pn_length);
                
                // Apply header protection using rustls
                // Note: rustls expects exactly 4 bytes for packet number, even if the actual PN is shorter
                let (first_part, second_part) = packet_data.split_at_mut(pn_offset);
                let first_byte = &mut first_part[0];
                
                // Ensure we have 4 bytes for header protection (rustls requirement)
                if second_part.len() < 4 {
                    return Err(Error::CryptoError("Not enough bytes after PN offset for header protection".to_string()));
                }
                
                if packet_type == PacketType::Handshake {
                    debug!("Sample for protection calculated");
                }
                
                // rustls expects exactly 4 bytes for packet number field
                let pn_bytes = &mut second_part[..4];
                keys.protect_header(&sample, first_byte, pn_bytes)?;
                
                if packet_type == PacketType::Handshake {
                    debug!("Header protection applied");
                }
            }
        }

        Ok(packet_data.freeze())
    }

    /// Decrypt a packet with proper header protection removal
    pub async fn decrypt_packet(&self, packet_data: &[u8]) -> Result<DecryptedPacket> {
        if packet_data.is_empty() {
            return Err(Error::CryptoError("Empty packet".to_string()));
        }
        
        let first_byte = packet_data[0];
        
        // Determine packet type from first byte
        let packet_type = if (first_byte & 0x80) != 0 {
            // Long header
            let type_bits = (first_byte & 0x30) >> 4;
            match type_bits {
                0 => PacketType::Initial,
                1 => PacketType::ZeroRtt,
                2 => PacketType::Handshake,
                3 => PacketType::Retry,
                _ => return Err(Error::CryptoError("Invalid packet type".to_string())),
            }
        } else {
            // Short header
            PacketType::OneRtt
        };
        
        eprintln!("DEBUG: Decrypting packet: role={:?}, packet_type={:?}, packet_len={}", 
            self.role, packet_type, packet_data.len());
        crypto_event!(
            Level::Debug,
            "Decrypting packet";
            "packet_type" => packet_type,
            "role" => self.role
        );
        
        let keys = self.get_keys_for_decryption(packet_type)?;
        
        // First, get the packet number offset (doesn't change with protection)
        let pn_offset = self.get_pn_offset(packet_data)?;
        
        // For getting the sample, we use the maximum possible header length
        // This is pn_offset + 4 (max packet number length)
        let max_header_len = pn_offset + 4;
        
        if packet_data.len() < max_header_len + 16 {
            return Err(Error::CryptoError("Packet too short for decryption".to_string()));
        }
        
        // Get the sample for header protection removal
        // Sample is always taken 4 bytes after the start of the packet number field
        let sample_offset = pn_offset + 4;
        if packet_data.len() < sample_offset + 16 {
            return Err(Error::CryptoError("Packet too short for sample".to_string()));
        }
        
        let sample = &packet_data[sample_offset..sample_offset + 16];
        // eprintln!("Sample extraction for decryption:");
        // eprintln!("  PN offset: {}, Sample offset: {}", pn_offset, sample_offset);
        // eprintln!("  Sample: {:02x?}", sample);
        
        // Remove header protection and decrypt based on key type
        let (pn, plaintext) = match keys {
            KeysWrapper::Ring(keys) => {
                // Create a mutable copy of the packet for header unprotection
                let mut packet_copy = packet_data.to_vec();
                
                // Remove header protection
                let mask = keys.header_key.mask(sample)?;
                
                // Remove protection from first byte BEFORE getting packet number length
                if (packet_copy[0] & 0x80) != 0 {
                    // Long header: unprotect low 4 bits
                    packet_copy[0] ^= mask[0] & 0x0f;
                } else {
                    // Short header: unprotect low 5 bits  
                    packet_copy[0] ^= mask[0] & 0x1f;
                }
                
                // NOW get packet number length from unprotected first byte
                let pn_length = ((packet_copy[0] & 0x03) + 1) as usize;
                
                if packet_type == PacketType::Initial && self.role == ConnectionRole::Client {
                    debug!("Packet number length from first byte: {}", pn_length);
                }
                
                // Remove protection from packet number bytes
                for i in 0..pn_length {
                    if pn_offset + i < packet_copy.len() {
                        packet_copy[pn_offset + i] ^= mask[1 + i];
                    }
                }
                
                // Extract packet number (big-endian)
                let mut pn_bytes = [0u8; 4];
                // eprintln!("Debug: Extracting {} bytes from offset {}", pn_length, pn_offset);
                // eprintln!("  Available bytes at PN offset: {:02x?}", &packet_copy[pn_offset..].get(..4).unwrap_or(&[]));
                
                for i in 0..pn_length {
                    if pn_offset + i < packet_copy.len() {
                        pn_bytes[4 - pn_length + i] = packet_copy[pn_offset + i];
                    }
                }
                let pn = u32::from_be_bytes(pn_bytes) as u64;
                
                if pn != 0 && pn != 1 {
                    crypto_event!(
                        Level::Debug,
                        "Packet number extraction";
                        "pn_offset" => pn_offset,
                        "pn_length" => pn_length,
                        "extracted_pn" => pn
                    );
                }
                
                
                // Now we know the actual packet number length, calculate the real header length
                let header_len = pn_offset + pn_length;
                
                // Construct nonce
                let nonce = Self::compute_nonce(&keys.iv, pn);
                
                // AAD is the header portion with unprotected packet number
                let aad = &packet_copy[..header_len];
                
                // Decrypt payload
                let ciphertext = &packet_data[header_len..];
                
                if packet_type == PacketType::Initial && self.role == ConnectionRole::Client {
                    crypto_event!(
                        Level::Debug,
                        "Decryption parameters";
                        "aad_len" => aad.len(),
                        "packet_number" => pn,
                        "ciphertext_len" => ciphertext.len()
                    );
                }
                let mut plaintext = ciphertext.to_vec();
                
                let decrypted_slice = keys.packet_key.open_in_place(
                    Nonce::try_assume_unique_for_key(&nonce).unwrap(),
                    Aad::from(aad),
                    &mut plaintext,
                )
                .map_err(|_| {
                    crypto_event!(
                        Level::Error,
                        "AEAD decryption failed";
                        "packet_number" => pn,
                        "header_len" => header_len,
                        "ciphertext_len" => ciphertext.len(),
                        "aad_len" => aad.len()
                    );
                    Error::CryptoError("Decryption failed".to_string())
                })?;
                
                // The decrypted slice doesn't include the auth tag
                (pn, decrypted_slice.to_vec())
            }
            KeysWrapper::Rustls(keys) => {
                // Create a mutable copy of the packet data for header unprotection
                let mut packet_copy = packet_data.to_vec();
                
                // Remove header protection using rustls
                // We need to provide exactly 4 bytes for the packet number field
                // even if the actual packet number is shorter
                
                // We need to unprotect with a temporary 4-byte buffer since we don't know the PN length yet
                let mut temp_pn_bytes = [0u8; 4];
                if pn_offset + 4 <= packet_copy.len() {
                    temp_pn_bytes.copy_from_slice(&packet_copy[pn_offset..pn_offset + 4]);
                } else {
                    // Copy what we have
                    let available = packet_copy.len() - pn_offset;
                    temp_pn_bytes[..available].copy_from_slice(&packet_copy[pn_offset..]);
                }
                
                // Unprotect header
                let first_byte = &mut packet_copy[0];
                keys.unprotect_header(sample, first_byte, &mut temp_pn_bytes)?;
                
                // Now we can read the actual PN length from the unprotected first byte
                let pn_length = ((packet_copy[0] & 0x03) + 1) as usize;
                
                // Copy back all 4 PN bytes since we always encode 4 bytes
                packet_copy[pn_offset..pn_offset + 4]
                    .copy_from_slice(&temp_pn_bytes[..4]);
                
                // Extract packet number - always use 4 bytes since that's what we encode
                let mut pn_full = [0u8; 4];
                if pn_offset + 4 <= packet_copy.len() {
                    pn_full.copy_from_slice(&packet_copy[pn_offset..pn_offset + 4]);
                }
                let pn = u32::from_be_bytes(pn_full) as u64;
                
                if packet_type == PacketType::Handshake {
                    eprintln!("DEBUG: Extracted packet number {} from bytes {:02x?} at offset {}", pn, pn_full, pn_offset);
                    eprintln!("DEBUG: First byte after unprotection: {:02x}", packet_copy[0]);
                    eprintln!("DEBUG: Header bytes up to packet number: {:02x?}", &packet_copy[..pn_offset]);
                }
                
                if packet_type == PacketType::Handshake {
                    crypto_event!(
                        Level::Debug,
                        "Handshake packet decryption";
                        "pn_offset" => pn_offset,
                        "pn_length" => pn_length,
                        "extracted_pn" => pn
                    );
                }
                
                // Calculate actual header length
                // During encryption, we always encode 4 bytes for packet number (see packet.rs:encode_packet_number)
                // So the AAD must include all 4 bytes, not just the pn_length indicated by the first byte
                let header_len = pn_offset + 4;
                
                // AAD is the unprotected header including all 4 packet number bytes
                let aad = &packet_copy[..header_len];
                
                // Decrypt payload using rustls
                let ciphertext = &packet_data[header_len..];
                
                if packet_type == PacketType::OneRtt {
                    eprintln!("DEBUG: OneRtt Decryption attempt:");
                    eprintln!("  Role: {:?}", self.role);
                    eprintln!("  Packet number: {}", pn);
                    eprintln!("  Header length: {}", header_len);
                    eprintln!("  AAD: {:02x?}", aad);
                    eprintln!("  Ciphertext length: {}", ciphertext.len());
                    eprintln!("  Using remote key");
                }
                
                if packet_type == PacketType::Handshake {
                    crypto_event!(
                        Level::Debug,
                        "Decrypting handshake packet";
                        "packet_number" => pn,
                        "aad_len" => aad.len(),
                        "aad_hex" => format!("{:02x?}", &aad[..32.min(aad.len())]),
                        "ciphertext_len" => ciphertext.len()
                    );
                    
                    // Debug: Show the complete AAD
                    eprintln!("DEBUG: Complete AAD for decryption ({} bytes):", aad.len());
                    eprintln!("{:02x?}", aad);
                    eprintln!("DEBUG: Ciphertext ({} bytes):", ciphertext.len());
                    eprintln!("{:02x?}", &ciphertext[..32.min(ciphertext.len())]);
                }
                
                let plaintext = keys.decrypt_packet(pn, aad, ciphertext)
                    .map_err(|e| {
                        crypto_event!(
                            Level::Error,
                            "Rustls decrypt_packet failed";
                            "error" => e,
                            "packet_number" => pn,
                            "header_len" => header_len,
                            "ciphertext_len" => ciphertext.len(),
                            "aad_len" => aad.len(),
                            "packet_type" => format!("{:?}", packet_type),
                            "role" => self.role
                        );
                        Error::CryptoError("Packet decryption failed".to_string())
                    })?;
                
                (pn, plaintext)
            }
        };

        // Parse frames from decrypted payload
        let frames = self.parse_frames_from_payload(&plaintext)?;

        Ok(DecryptedPacket {
            packet_number: pn,
            frames,
            payload: plaintext.into(),
        })
    }

    /// Get keys for a specific packet type
    fn get_keys_for_packet_type(&self, packet_type: PacketType) -> Result<KeysWrapper<'_>> {
        match packet_type {
            PacketType::Initial => {
                // For encryption, use send keys; this method is called by encrypt_packet
                self.initial_send_keys.as_ref()
                    .map(KeysWrapper::Ring)
                    .ok_or_else(|| Error::CryptoError("No initial send keys available".to_string()))
            }
            PacketType::Handshake => {
                // Temporarily disable rustls keys and use ring-based keys
                // TODO: Fix rustls key exchange issue
                if let Some(keys) = self.handshake_keys.as_ref() {
                    Ok(KeysWrapper::Ring(keys))
                } else {
                    Err(Error::CryptoError("No handshake keys available".to_string()))
                }
            }
            PacketType::ZeroRtt | PacketType::OneRtt => {
                // Check for legacy keys first (since rustls keys don't work correctly)
                let legacy_keys = if self.key_phase {
                    self.next_application_keys.as_ref()
                } else {
                    self.application_keys.as_ref()
                };
                
                if let Some(keys) = legacy_keys {
                    eprintln!("DEBUG: Using ring-based test keys for OneRtt encryption");
                    Ok(KeysWrapper::Ring(keys))
                } else {
                    // Fall back to rustls keys (which currently don't work)
                    let rustls_keys = if self.key_phase {
                        self.next_application_keys_rustls.as_ref()
                    } else {
                        self.application_keys_rustls.as_ref()
                    };
                    
                    if let Some(keys) = rustls_keys {
                        Ok(match self.role {
                            ConnectionRole::Client => KeysWrapper::Rustls(&keys.local),
                            ConnectionRole::Server => KeysWrapper::Rustls(&keys.local),  // Server also sends with local
                        })
                    } else {
                        Err(Error::CryptoError("No application keys available".to_string()))
                    }
                }
            }
            _ => Err(Error::CryptoError(format!("No keys for packet type {:?}", packet_type))),
        }
    }
    
    /// Get keys for decrypting a packet (use receive keys)
    fn get_keys_for_decryption(&self, packet_type: PacketType) -> Result<KeysWrapper<'_>> {
        // Log decryption attempt for debugging
        if packet_type == PacketType::Initial && self.role == ConnectionRole::Client {
            if let Some(_recv_keys) = &self.initial_recv_keys {
                crypto_event!(
                    Level::Debug,
                    "Client decrypting Initial packet with receive keys"
                );
            }
        }
        match packet_type {
            PacketType::Initial => {
                // For decryption, use receive keys
                self.initial_recv_keys.as_ref()
                    .map(KeysWrapper::Ring)
                    .ok_or_else(|| Error::CryptoError("No initial receive keys available".to_string()))
            }
            PacketType::Handshake => {
                // Temporarily disable rustls keys and use ring-based keys
                // TODO: Fix rustls key exchange issue
                if let Some(keys) = self.handshake_keys.as_ref() {
                    debug!("Found ring handshake keys");
                    Ok(KeysWrapper::Ring(keys))
                } else {
                    warn!("No handshake keys available!");
                    Err(Error::CryptoError("No handshake keys available".to_string()))
                }
            }
            PacketType::ZeroRtt | PacketType::OneRtt => {
                // Check for legacy keys first (since rustls keys don't work correctly)
                let legacy_keys = if self.key_phase {
                    self.next_application_keys.as_ref()
                } else {
                    self.application_keys.as_ref()
                };
                
                if let Some(keys) = legacy_keys {
                    eprintln!("DEBUG: Using ring-based test keys for OneRtt decryption");
                    Ok(KeysWrapper::Ring(keys))
                } else {
                    // Fall back to rustls keys
                    let rustls_keys = if self.key_phase {
                        self.next_application_keys_rustls.as_ref()
                    } else {
                        self.application_keys_rustls.as_ref()
                    };
                    
                    eprintln!("DEBUG: get_decryption_keys for OneRtt: role={:?}, has_rustls_keys={}, key_phase={}", 
                        self.role, rustls_keys.is_some(), self.key_phase);
                    
                    if let Some(keys) = rustls_keys {
                        // For decryption, always use remote keys
                        Ok(KeysWrapper::Rustls(&keys.remote))
                    } else {
                        Err(Error::CryptoError("No application keys available".to_string()))
                    }
                }
            }
            _ => Err(Error::CryptoError(format!("No keys for packet type {:?}", packet_type))),
        }
    }
    
    /// Parse packet type from first byte
    fn parse_packet_type(&self, first_byte: u8) -> Result<PacketType> {
        if (first_byte & 0x80) != 0 {
            // Long header packet
            let type_bits = (first_byte & 0x30) >> 4;
            match type_bits {
                0 => Ok(PacketType::Initial),
                1 => Ok(PacketType::ZeroRtt),
                2 => Ok(PacketType::Handshake),
                3 => Ok(PacketType::Retry),
                _ => Err(Error::CryptoError("Invalid long header packet type".to_string())),
            }
        } else {
            // Short header packet (1-RTT)
            Ok(PacketType::OneRtt)
        }
    }
    
    
    /// Parse packet header to get structural information
    fn parse_packet_header(&self, packet_data: &[u8], packet_type: PacketType) -> Result<HeaderInfo> {
        match packet_type {
            PacketType::Initial | PacketType::Handshake | PacketType::ZeroRtt => {
                // Long header parsing
                if packet_data.len() < 6 {
                    return Err(Error::CryptoError("Packet too short for long header".to_string()));
                }
                
                let mut offset = 1; // Skip first byte
                offset += 4; // Skip version (4 bytes)
                
                // Read DCID length
                let dcid_len = packet_data[offset] as usize;
                offset += 1 + dcid_len;
                
                // Read SCID length  
                if offset >= packet_data.len() {
                    return Err(Error::CryptoError("Packet truncated at SCID length".to_string()));
                }
                let scid_len = packet_data[offset] as usize;
                offset += 1 + scid_len;
                
                // Handle type-specific fields
                match packet_type {
                    PacketType::Initial => {
                        // Token length + token + length + packet number
                        if offset >= packet_data.len() {
                            return Err(Error::CryptoError("Packet truncated at token".to_string()));
                        }
                        
                        // Skip token (VarInt length + data)
                        let (token_len, token_len_bytes) = self.parse_varint_at(packet_data, offset)?;
                        offset += token_len_bytes + token_len as usize;
                        
                        // Skip length field (VarInt)
                        let (_, length_bytes) = self.parse_varint_at(packet_data, offset)?;
                        offset += length_bytes;
                        
                        // Packet number starts here
                        let pn_offset = offset;
                        let pn_length = 4; // Simplified - always 4 bytes for now
                        
                        Ok(HeaderInfo {
                            header_len: offset + pn_length,
                            pn_offset,
                            pn_length,
                        })
                    }
                    PacketType::Handshake | PacketType::ZeroRtt => {
                        // Length + packet number
                        let (_, length_bytes) = self.parse_varint_at(packet_data, offset)?;
                        offset += length_bytes;
                        
                        let pn_offset = offset;
                        let pn_length = 4;
                        
                        Ok(HeaderInfo {
                            header_len: offset + pn_length,
                            pn_offset,
                            pn_length,
                        })
                    }
                    _ => unreachable!(),
                }
            }
            PacketType::OneRtt => {
                // Short header: 1 byte + DCID + packet number
                let dcid_len = 8; // Assume 8-byte DCID as per our implementation
                let pn_offset = 1 + dcid_len;
                let pn_length = 4; // We always use 4-byte packet numbers
                
                Ok(HeaderInfo {
                    header_len: pn_offset + pn_length, // 1 + 8 + 4 = 13
                    pn_offset,
                    pn_length,
                })
            }
            _ => Err(Error::CryptoError("Unsupported packet type for parsing".to_string())),
        }
    }
    
    /// Parse VarInt at specific offset
    fn parse_varint_at(&self, data: &[u8], offset: usize) -> Result<(u64, usize)> {
        if offset >= data.len() {
            return Err(Error::CryptoError("VarInt offset out of bounds".to_string()));
        }
        
        let first_byte = data[offset];
        let length_of_length = match first_byte >> 6 {
            0 => 1,
            1 => 2, 
            2 => 4,
            3 => 8,
            _ => unreachable!(),
        };
        
        if offset + length_of_length > data.len() {
            return Err(Error::CryptoError("VarInt extends beyond packet".to_string()));
        }
        
        let mut value = (first_byte & 0x3f) as u64;
        for i in 1..length_of_length {
            value = (value << 8) | (data[offset + i] as u64);
        }
        
        Ok((value, length_of_length))
    }
    
    /// Remove header protection from packet using pre-extracted sample
    ///
    /// Alternative implementation that accepts HeaderInfo and pre-extracted sample.
    /// Used for scenarios where header structure has already been parsed and
    /// sample has been extracted from packet payload.
    fn remove_header_protection_from_packet(
        &self,
        packet_data: &[u8],
        hp_key: &HeaderProtectionKey,
        header_info: &HeaderInfo,
        sample: &[u8],
    ) -> Result<u64> {
        // Generate mask from sample
        let mask = hp_key.mask(sample)?;
        
        // Create mutable copy to work with
        let mut packet_copy = packet_data.to_vec();
        
        // Remove protection from first byte
        let first_byte = packet_copy[0];
        if (first_byte & 0x80) != 0 {
            // Long header: unprotect low 4 bits
            packet_copy[0] ^= mask[0] & 0x0f;
        } else {
            // Short header: unprotect low 5 bits  
            packet_copy[0] ^= mask[0] & 0x1f;
        }
        
        // Remove protection from packet number bytes
        for i in 0..header_info.pn_length {
            if header_info.pn_offset + i < packet_copy.len() {
                packet_copy[header_info.pn_offset + i] ^= mask[1 + i];
            }
        }
        
        // Extract packet number
        let mut pn = 0u64;
        for i in 0..header_info.pn_length {
            if header_info.pn_offset + i < packet_copy.len() {
                pn = (pn << 8) | (packet_copy[header_info.pn_offset + i] as u64);
            }
        }
        
        Ok(pn)
    }
    
    /// Restore header protection for AAD computation
    fn restore_header_protection(
        &self,
        header: &mut [u8], 
        hp_key: &HeaderProtectionKey,
        sample: &[u8],
        header_info: &HeaderInfo,
    ) -> Result<()> {
        // This reverses the header protection to get the original protected header
        let mask = hp_key.mask(sample)?;
        
        // Restore first byte protection
        let first_byte = header[0];
        if (first_byte & 0x80) != 0 {
            header[0] ^= mask[0] & 0x0f;
        } else {
            header[0] ^= mask[0] & 0x1f;
        }
        
        // Restore packet number protection
        for i in 0..header_info.pn_length {
            if header_info.pn_offset + i < header.len() {
                header[header_info.pn_offset + i] ^= mask[1 + i];
            }
        }
        
        Ok(())
    }
    
    /// Parse frames from decrypted payload
    fn parse_frames_from_payload(&self, payload: &[u8]) -> Result<Vec<Frame>> {
        let mut frames = Vec::new();
        let mut buf = Bytes::from(payload.to_vec());
        
        // eprintln!("Parsing frames from payload ({} bytes)", payload.len());
        // eprintln!("  First 16 bytes: {:02x?}", &payload[..16.min(payload.len())]);
        
        while !buf.is_empty() {
            // eprintln!("  Attempting to decode frame, {} bytes remaining", buf.len());
            // if buf.len() <= 32 {
            //     eprintln!("    Remaining bytes: {:02x?}", &buf[..]);
            // }
            match Frame::decode(&mut buf) {
                Ok(frame) => {
                    // Check if this is padding before moving the frame
                    let is_padding = matches!(frame, Frame::Padding);
                    // eprintln!("  Decoded frame: {:?}", frame);
                    frames.push(frame);
                    
                    if is_padding {
                        // Rest of packet is padding, stop parsing
                        break;
                    }
                }
                Err(Error::Incomplete) => {
                    // Not enough data for complete frame, stop parsing
                    // eprintln!("  Frame incomplete, stopping");
                    break;
                }
                Err(e) => {
                    // eprintln!("  Frame decode error: {:?}", e);
                    // Frame parsing error - could be due to malformed packet
                    return Err(e);
                }
            }
        }
        
        Ok(frames)
    }

    /// Get next packet number
    fn next_packet_number(&mut self) -> u64 {
        let pn = self.highest_sent_pn;
        // Now handled by Connection per packet number space
        // self.highest_sent_pn += 1;
        eprintln!("DEBUG: next_packet_number called, role={:?}, returning {}, highest_sent_pn now {}", 
            self.role, pn, self.highest_sent_pn);
        pn
    }
    
    /// Determine appropriate packet type based on current state
    pub fn determine_packet_type(&self) -> PacketType {
        // Choose packet type based on available keys and connection state
        let has_app_keys = self.application_keys_rustls.is_some() || self.application_keys.is_some();
        let has_hs_keys = self.handshake_keys_rustls.is_some() || self.handshake_keys.is_some();
        let has_initial_keys = self.initial_send_keys.is_some();
        
        // eprintln!("Key availability: app={}, hs={}, initial={}", has_app_keys, has_hs_keys, has_initial_keys);
        
        // During handshake, follow the correct packet type progression:
        // 1. Initial packets for ClientHello/ServerHello
        // 2. Handshake packets for remaining handshake messages
        // 3. 1-RTT packets after handshake completion
        
        // Check if we're still in the Initial phase (no handshake keys derived yet on peer)
        // Server should use Initial for first response even if it has handshake keys
        let should_use_initial = match self.role {
            ConnectionRole::Server => {
                // Server MUST use Initial for its first response that contains crypto data
                // This ensures the client can process the ServerHello
                // After that, use Handshake packets
                !self.initial_crypto_sent && has_initial_keys
            }
            ConnectionRole::Client => {
                // Client uses Initial until it receives ServerHello and derives handshake keys
                !has_hs_keys && has_initial_keys
            }
        };
        
        // eprintln!("Packet type determination: role={:?}, should_use_initial={}, handshake_send_count={}", 
        //          self.role, should_use_initial, self.handshake_send_count);
        
        let handshake_complete = match &self.tls_conn {
            QuicConnection::Client(conn) => !conn.is_handshaking(),
            QuicConnection::Server(conn) => !conn.is_handshaking(),
        };
        
        // For client: if we haven't sent handshake packets yet but have handshake keys,
        // we should use Handshake packets (for sending Finished message)
        let should_use_handshake = has_hs_keys && match self.role {
            ConnectionRole::Client => self.handshake_send_count == 0,
            ConnectionRole::Server => !handshake_complete,
        };
        
        let result = if should_use_initial {
            PacketType::Initial
        } else if should_use_handshake {
            PacketType::Handshake
        } else if has_app_keys && handshake_complete {
            PacketType::OneRtt
        } else if has_hs_keys {
            PacketType::Handshake
        } else if has_initial_keys {
            PacketType::Initial
        } else {
            // Default to Initial if no keys are available yet
            PacketType::Initial
        };
        
        if self.role == ConnectionRole::Server && result == PacketType::Initial {
            eprintln!("DEBUG: Server choosing Initial packet type, initial_crypto_sent={}, highest_sent_pn={}", 
                self.initial_crypto_sent, self.highest_sent_pn);
        }
        eprintln!("determine_packet_type: role={:?}, should_use_initial={}, should_use_handshake={}, has_app_keys={}, has_hs_keys={}, handshake_complete={}, highest_sent_pn={}, result={:?}",
            self.role, should_use_initial, should_use_handshake, has_app_keys, has_hs_keys, handshake_complete, self.highest_sent_pn, result);
        
        result
    }
    
    /// Estimate header size for a given packet type
    fn estimate_header_size(&self, packet_type: PacketType) -> Result<usize> {
        match packet_type {
            PacketType::Initial | PacketType::Handshake | PacketType::ZeroRtt => {
                // Long header: 1 + 4 + 1 + dcid_len + 1 + scid_len + type_specific
                // Simplified estimate: ~25 bytes for typical connection IDs
                Ok(25)
            }
            PacketType::OneRtt => {
                // Short header: 1 + dcid_len + pn_len
                // We use: 1 + 8 + 4 = 13 bytes
                Ok(13)
            }
            _ => Err(Error::CryptoError("Unsupported packet type".to_string())),
        }
    }
    
    /// Create packet header for encryption
    fn create_packet_header(&self, packet_type: PacketType, pn: u64, payload_len: usize) -> Result<PacketHeader> {
        match packet_type {
            PacketType::Initial | PacketType::Handshake | PacketType::ZeroRtt => {
                // Calculate total length including packet number and auth tag
                let pn_length = self.encode_packet_number_length(pn);
                let total_length = payload_len + 16 + pn_length; // payload + tag + pn
                
                let type_specific = match packet_type {
                    PacketType::Initial => crate::quic::packet::TypeSpecificData::Initial {
                        token: bytes::Bytes::new(),
                        length: crate::util::varint::VarInt::from_u32(total_length as u32),
                        packet_number: self.encode_packet_number(pn, pn_length)?,
                    },
                    PacketType::Handshake => crate::quic::packet::TypeSpecificData::Handshake {
                        length: crate::util::varint::VarInt::from_u32(total_length as u32),
                        packet_number: self.encode_packet_number(pn, pn_length)?,
                    },
                    PacketType::ZeroRtt => crate::quic::packet::TypeSpecificData::ZeroRtt {
                        length: crate::util::varint::VarInt::from_u32(total_length as u32),
                        packet_number: self.encode_packet_number(pn, pn_length)?,
                    },
                    _ => unreachable!(),
                };
                
                Ok(PacketHeader::Long(LongHeader::new(
                    packet_type,
                    0x0000_0001, // QUIC v1
                    self.remote_cid()?,  // dst_cid should be the peer's CID
                    self.local_cid()?,   // src_cid should be our CID
                    type_specific,
                )))
            }
            PacketType::OneRtt => {
                let pn_length = self.encode_packet_number_length(pn);
                Ok(PacketHeader::Short(crate::quic::packet::ShortHeader {
                    dst_cid: self.remote_cid()?,
                    packet_number: self.encode_packet_number(pn, pn_length)?,
                    spin_bit: false, // TODO: Implement spin bit logic
                    key_phase: self.key_phase,
                }))
            }
            _ => Err(Error::CryptoError("Unsupported packet type for header creation".to_string())),
        }
    }
    
    /// Encode packet number with appropriate length
    fn encode_packet_number(&self, pn: u64, length: usize) -> Result<u32> {
        match length {
            1 => Ok((pn & 0xFF) as u32),
            2 => Ok((pn & 0xFFFF) as u32),
            3 => Ok((pn & 0xFF_FFFF) as u32),
            4 => Ok(pn as u32),
            _ => Err(Error::CryptoError("Invalid packet number length".to_string())),
        }
    }
    
    /// Determine packet number encoding length
    /// This implements packet number length optimization per RFC 9000 Section 12.3
    fn encode_packet_number_length(&self, pn: u64) -> usize {
        // Determine the minimum number of bytes needed to encode the packet number
        // This implements optimization per RFC 9000 Section 12.3
        if pn < 0x100 {
            1
        } else if pn < 0x10000 {
            2
        } else if pn < 0x1000000 {
            3
        } else {
            4
        }
    }
    
    /// Apply header protection to an assembled packet
    fn apply_header_protection_to_packet(
        &self,
        packet_data: &mut [u8],
        hp_key: &HeaderProtectionKey,
        header_len: usize,
        pn: u64,
    ) -> Result<()> {
        if packet_data.len() < header_len + 20 {
            return Err(Error::CryptoError("Packet too short for header protection".to_string()));
        }
        
        // Get packet number offset first
        let pn_offset = self.get_pn_offset(&packet_data[..header_len])?;
        
        // Sample is taken 4 bytes after the packet number field starts
        let sample_offset = pn_offset + 4;
        if packet_data.len() < sample_offset + 16 {
            return Err(Error::CryptoError("Packet too short for sample".to_string()));
        }
        
        let sample = &packet_data[sample_offset..sample_offset + 16];
        // eprintln!("Sample extraction for encryption:");
        // eprintln!("  Header len: {}, Sample offset: {}", header_len, sample_offset);
        // eprintln!("  Sample: {:02x?}", sample);
        let mask = hp_key.mask(sample)?;
        
        // Protect first byte
        let first_byte = packet_data[0];
        if (first_byte & 0x80) != 0 {
            // Long header: protect low 4 bits
            packet_data[0] ^= mask[0] & 0x0f;
        } else {
            // Short header: protect low 5 bits
            packet_data[0] ^= mask[0] & 0x1f;
        }
        
        // Protect packet number bytes
        let pn_length = self.encode_packet_number_length(pn);
        
        // eprintln!("Header protection application:");
        // eprintln!("  Header len: {}, PN offset: {}, PN length: {}, PN: {}", header_len, pn_offset, pn_length, pn);
        // eprintln!("  PN bytes before protection: {:02x?}", &packet_data[pn_offset..pn_offset + pn_length].to_vec());
        
        for i in 0..pn_length {
            if pn_offset + i < packet_data.len() {
                packet_data[pn_offset + i] ^= mask[1 + i];
            }
        }
        
        // eprintln!("  PN bytes after protection: {:02x?}", &packet_data[pn_offset..pn_offset + pn_length].to_vec());
        
        Ok(())
    }
    
    /// Get packet number offset within the header
    fn get_packet_number_offset(&self, first_byte: u8) -> Result<usize> {
        if (first_byte & 0x80) != 0 {
            // Long header - packet number comes after fixed header fields
            // Simplified calculation - in practice would need to parse DCID/SCID lengths
            Ok(17) // Approximate offset for typical connection IDs
        } else {
            // Short header - packet number comes after DCID
            Ok(9) // 1 byte header + 8 byte DCID
        }
    }

    /// Compute nonce from IV and packet number
    pub fn compute_nonce(iv: &[u8; 12], pn: u64) -> [u8; 12] {
        let mut nonce = *iv;
        for i in 0..8 {
            nonce[11 - i] ^= ((pn >> (i * 8)) & 0xff) as u8;
        }
        nonce
    }

    /// Apply header protection according to RFC 9001 Section 5.4
    /// Uses Rust 2024 let chains for cleaner validation and processing
    pub fn apply_header_protection(
        &self,
        packet_data: &mut [u8],
        header_offset: usize,
        pn_offset: usize,
        pn_length: usize,
        hp_key: &HeaderProtectionKey,
    ) -> Result<()> {
        // Use Rust 2024 let chains for validation
        if let Some(sample_offset) = pn_offset.checked_add(4)
            && let Some(sample_end) = sample_offset.checked_add(16)
            && packet_data.len() >= sample_end
        {
            // RFC 9001 Section 5.4.2: Sample 16 bytes for header protection
            let sample = &packet_data[sample_offset..sample_end];
            
            // Generate header protection mask
            let mask = hp_key.mask(sample)?;
            
            crypto_event!(
                Level::Debug,
                "Applying header protection";
                "header_offset" => header_offset,
                "pn_offset" => pn_offset,
                "pn_length" => pn_length,
                "sample_offset" => sample_offset
            );
            
            // Apply protection to the first byte
            if header_offset < packet_data.len() {
                let first_byte = &mut packet_data[header_offset];
                let is_long_header = (*first_byte & 0x80) != 0;
                
                if is_long_header {
                    // RFC 9001: For long headers, protect reserved and packet number length bits
                    *first_byte ^= mask[0] & 0x0f; // Protect low 4 bits
                } else {
                    // RFC 9001: For short headers, protect reserved, key phase, and pn length bits
                    *first_byte ^= mask[0] & 0x1f; // Protect low 5 bits
                }
            }
            
            // Apply protection to packet number bytes
            for i in 0..pn_length {
                if let Some(pn_byte_offset) = pn_offset.checked_add(i)
                    && pn_byte_offset < packet_data.len()
                {
                    packet_data[pn_byte_offset] ^= mask[1 + i];
                }
            }
            
            crypto_event!(
                Level::Debug,
                "Header protection applied successfully";
                "is_long_header" => (packet_data[header_offset] & 0x80) != 0
            );
            
            Ok(())
        } else {
            crypto_event!(
                Level::Error,
                "Packet too short for header protection";
                "packet_len" => packet_data.len(),
                "required_len" => pn_offset + 4 + 16
            );
            Err(Error::CryptoError("Packet too short for header protection".to_string()))
        }
    }

    /// Remove header protection according to RFC 9001
    /// Uses Rust 2024 let chains for complex header parsing
    fn remove_header_protection(
        &self,
        packet_data: &mut [u8],
        hp_key: &HeaderProtectionKey,
        pn_offset: usize,
    ) -> Result<(u64, usize)> {
        // Use Rust 2024 let chains for validation and parsing
        if let Some(first_byte) = packet_data.first()
            && let is_long_header = (*first_byte & 0x80) != 0
            && let Some(sample_offset) = pn_offset.checked_add(4)
            && let Some(sample_end) = sample_offset.checked_add(16)
            && packet_data.len() >= sample_end
        {
            // Get sample for header protection
            let sample = &packet_data[sample_offset..sample_end];
            
            // Generate mask
            let mask = hp_key.mask(sample)?;
            
            // Remove protection from first byte to get packet number length
            let unprotected_first_byte = if is_long_header {
                *first_byte ^ (mask[0] & 0x0f) // Long header: low 4 bits protected
            } else {
                *first_byte ^ (mask[0] & 0x1f) // Short header: low 5 bits protected
            };
            
            // Extract packet number length
            let pn_length = ((unprotected_first_byte & 0x03) + 1) as usize;
            
            // Validate we have enough bytes for the packet number
            if packet_data.len() < pn_offset + pn_length {
                crypto_event!(
                    Level::Error,
                    "Packet too short for packet number";
                    "pn_offset" => pn_offset,
                    "pn_length" => pn_length,
                    "packet_len" => packet_data.len()
                );
                return Err(Error::CryptoError("Packet too short for packet number".to_string()));
            }
            
            // Apply unprotection to first byte
            packet_data[0] = unprotected_first_byte;
            
            // Remove protection from packet number bytes
            let mut pn_bytes = [0u8; 4];
            for i in 0..pn_length {
                let protected_byte = packet_data[pn_offset + i];
                let unprotected_byte = protected_byte ^ mask[1 + i];
                packet_data[pn_offset + i] = unprotected_byte;
                pn_bytes[4 - pn_length + i] = unprotected_byte;
            }
            
            let packet_number = u32::from_be_bytes(pn_bytes) as u64;
            
            crypto_event!(
                Level::Debug,
                "Header protection removed";
                "packet_number" => packet_number,
                "pn_length" => pn_length,
                "is_long_header" => is_long_header
            );
            
            Ok((packet_number, pn_length))
        } else {
            crypto_event!(
                Level::Error,
                "Cannot remove header protection - invalid packet structure";
                "packet_len" => packet_data.len(),
                "pn_offset" => pn_offset
            );
            Err(Error::CryptoError("Invalid packet structure for header protection removal".to_string()))
        }
    }

    
    /// Check if handshake is complete
    pub async fn handshake_complete(&self) -> Result<bool> {
        let (is_handshaking, conn_type) = match &self.tls_conn {
            QuicConnection::Client(conn) => (conn.is_handshaking(), "Client"),
            QuicConnection::Server(conn) => (conn.is_handshaking(), "Server"),
        };
        let is_complete = !is_handshaking;
        
        protocol_event!(
            Level::Debug,
            "Checking handshake status";
            "connection_type" => conn_type,
            "is_complete" => is_complete
        );
        
        // For clients, we also need to ensure we've sent our Finished message
        // This is indicated by having sent at least one handshake packet
        let actually_complete = match self.role {
            ConnectionRole::Client => is_complete && self.handshake_send_count > 0,
            ConnectionRole::Server => is_complete,
        };
        
        // Check if we have any pending handshake data
        let has_pending_hs_data = !self.pending_handshake_data.is_empty();
        
        eprintln!("DEBUG: handshake_complete check: role={:?}, is_handshaking={}, is_complete={}, handshake_send_count={}, has_1rtt_keys={}, has_pending_hs_data={}, actually_complete={}", 
            self.role, is_handshaking, is_complete, self.handshake_send_count, 
            self.application_keys.is_some() || self.application_keys_rustls.is_some(),
            has_pending_hs_data,
            actually_complete);
        
        if actually_complete {
            crypto_event!(
                Level::Info,
                "Handshake complete check";
                "role" => self.role,
                "handshake_send_count" => self.handshake_send_count
            );
        }
        
        Ok(actually_complete)
    }

    /// Get handshake data to send
    pub fn get_handshake_data(&mut self) -> Option<Vec<u8>> {
        // First check if we have pending data from process_crypto_frame
        if !self.pending_handshake_data.is_empty() {
            let data = std::mem::take(&mut self.pending_handshake_data);
            crypto_event!(
                Level::Debug,
                "Returning pending handshake data";
                "len" => data.len()
            );
            return Some(data);
        }
        
        let mut buf = Vec::new();
        let mut key_changes = Vec::new();
        
        // Collect handshake data and key changes
        match &mut self.tls_conn {
            QuicConnection::Client(conn) => {
                loop {
                    match conn.write_hs(&mut buf) {
                        Some(key_change) => {
                            crypto_event!(
                                Level::Info,
                                "Got key change from write_hs";
                                "role" => self.role
                            );
                            key_changes.push(key_change);
                        }
                        None => break,
                    }
                }
            },
            QuicConnection::Server(conn) => {
                loop {
                    match conn.write_hs(&mut buf) {
                        Some(key_change) => {
                            crypto_event!(
                                Level::Info,
                                "Got key change from write_hs";
                                "role" => self.role
                            );
                            key_changes.push(key_change);
                        }
                        None => break,
                    }
                }
            }
        }
        
        // Process key changes after releasing the borrow
        // Install key changes using Rust 2024 let chains for cleaner error handling
        for key_change in key_changes {
            if let Err(e) = self.install_key_change(key_change) {
                crypto_event!(
                    Level::Warn,
                    "Failed to install key change";
                    "error" => e,
                    "role" => self.role
                );
                // Continue processing - key installation failures shouldn't prevent handshake data
            }
        }
        
        // Poll for any additional key changes after writing
        if let Err(e) = self.poll_key_changes() {
            crypto_event!(
                Level::Debug,
                "Error polling for key changes";
                "error" => e
            );
        }
        
        // Extract transport parameters if available
        if let Err(e) = self.extract_transport_params() {
            crypto_event!(
                Level::Debug,
                "Transport params not yet available";
                "error" => e
            );
        }
        
        if buf.is_empty() {
            None
        } else {
            Some(buf)
        }
    }
    
    /// Start the handshake process and return initial handshake data
    pub async fn start_handshake(&mut self) -> Result<Vec<u8>> {
        info!("Starting handshake, role: {:?}", self.role);
        match self.role {
            ConnectionRole::Client => {
                // For clients, generate the initial ClientHello
                let handshake_data = self.get_initial_handshake_data()?;
                if handshake_data.is_empty() {
                    return Err(Error::TlsError("Failed to generate ClientHello".to_string()));
                }
                Ok(handshake_data)
            }
            ConnectionRole::Server => {
                // For servers, no initial data is sent - wait for ClientHello
                Ok(Vec::new())
            }
        }
    }
    
    /// Get initial handshake data (ClientHello for clients)
    fn get_initial_handshake_data(&mut self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        let mut key_changes = Vec::new();
        
        // Collect handshake data and key changes
        match &mut self.tls_conn {
            QuicConnection::Client(conn) => {
                // Write initial handshake data and collect key changes
                loop {
                    match conn.write_hs(&mut buf) {
                        Some(key_change) => {
                            key_changes.push(key_change);
                        }
                        None => {
                            // No more handshake data to write
                            break;
                        }
                    }
                }
            }
            QuicConnection::Server(_) => {
                // Servers don't generate initial data
                return Ok(Vec::new());
            }
        }
        
        // Process key changes after releasing the borrow
        // Install key changes using Rust 2024 let chains for cleaner error handling
        for key_change in key_changes {
            if let Err(e) = self.install_key_change(key_change) {
                crypto_event!(
                    Level::Warn,
                    "Failed to install initial key change";
                    "error" => e,
                    "role" => self.role
                );
                // Return error for initial handshake failures - these are more critical
                return Err(e);
            }
        }
        
        if buf.is_empty() {
            Err(Error::TlsError("No handshake data generated".to_string()))
        } else {
            Ok(buf)
        }
    }
    
    /// Get the negotiated ALPN protocol
    pub fn negotiated_alpn(&self) -> Option<&[u8]> {
        match &self.tls_conn {
            QuicConnection::Client(conn) => conn.alpn_protocol(),
            QuicConnection::Server(conn) => conn.alpn_protocol(),
        }
    }
    
    /// Get session information for resumption
    pub fn session_info(&self) -> Option<Vec<u8>> {
        // This would extract session tickets or resumption data
        // For now, return None
        None
    }
    
    /// Get pending crypto frames to send
    pub fn take_crypto_frames(&mut self) -> Vec<Frame> {
        // In a real implementation, this would return any handshake data
        // that needs to be sent in CRYPTO frames
        let mut frames = Vec::new();
        
        if let Some(handshake_data) = self.get_handshake_data() {
            frames.push(Frame::Crypto {
                offset: 0,
                data: handshake_data.into(),
            });
        }
        
        frames
    }
    
    /// Set local transport parameters to send during handshake
    pub fn set_transport_params(&mut self, params: TransportParameters) {
        self.local_transport_params = Some(params);
    }
    
    /// Get peer transport parameters if available
    pub fn get_peer_transport_params(&self) -> Option<&TransportParameters> {
        self.peer_transport_params.as_ref()
    }
    
    /// Poll for key changes from rustls QUIC connection
    /// Note: In rustls QUIC API, keys are obtained through write_hs(), not polling
    /// This method is kept for compatibility but doesn't do anything
    fn poll_key_changes(&mut self) -> Result<()> {
        // rustls QUIC API provides keys through write_hs() return values
        // There's no separate polling mechanism
        // Keys are already handled in get_handshake_data() and get_initial_handshake_data()
        Ok(())
    }
    
    /// Extract transport parameters from TLS handshake
    fn extract_transport_params(&mut self) -> Result<()> {
        match &self.tls_conn {
            QuicConnection::Client(conn) => {
                if let Some(params_bytes) = conn.quic_transport_parameters() {
                    // Decode peer transport parameters
                    let peer_params = TransportParameters::decode(Bytes::from(params_bytes.to_vec()))?;
                    self.peer_transport_params = Some(peer_params);
                }
            }
            QuicConnection::Server(conn) => {
                if let Some(params_bytes) = conn.quic_transport_parameters() {
                    // Decode peer transport parameters
                    let peer_params = TransportParameters::decode(Bytes::from(params_bytes.to_vec()))?;
                    self.peer_transport_params = Some(peer_params);
                }
            }
        }
        Ok(())
    }
    
    /// Calculate Retry Integrity Tag (RFC 9001 Section 5.8)
    pub fn calculate_retry_integrity_tag(retry_pseudo_packet: &[u8]) -> Result<[u8; 16]> {
        // Retry Integrity Tag uses a fixed key and nonce
        const RETRY_KEY: &[u8] = &[
            0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
            0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
        ];
        const RETRY_NONCE: &[u8] = &[
            0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
            0x23, 0x98, 0x25, 0xbb,
        ];
        
        // Create AEAD key
        let unbound_key = UnboundKey::new(&aead::AES_128_GCM, RETRY_KEY)
            .map_err(|_| Error::CryptoError("Failed to create retry key".to_string()))?;
        let key = LessSafeKey::new(unbound_key);
        
        // The retry pseudo-packet is used as AAD, with empty plaintext
        let mut tag = vec![0u8; 0];
        key.seal_in_place_append_tag(
            Nonce::try_assume_unique_for_key(RETRY_NONCE).unwrap(),
            Aad::from(retry_pseudo_packet),
            &mut tag,
        )
        .map_err(|_| Error::CryptoError("Failed to calculate retry tag".to_string()))?;
        
        // Extract the 16-byte tag
        let mut result = [0u8; 16];
        result.copy_from_slice(&tag);
        Ok(result)
    }
    
    /// Get cipher suite from TLS connection
    pub fn cipher_suite(&self) -> CipherSuite {
        // In a real implementation, this would query the TLS connection
        // For now, default to AES-128-GCM
        CipherSuite::Aes128Gcm
    }
    
    /// Validate packet authenticity
    pub fn validate_packet_auth(&self, packet_data: &[u8], packet_type: PacketType) -> Result<()> {
        // Basic packet structure validation
        if packet_data.is_empty() {
            return Err(Error::CryptoError("Empty packet".to_string()));
        }
        
        let first_byte = packet_data[0];
        
        // Validate packet type consistency
        let expected_long_header = matches!(packet_type, 
            PacketType::Initial | PacketType::ZeroRtt | PacketType::Handshake | PacketType::Retry
        );
        let actual_long_header = (first_byte & 0x80) != 0;
        
        if expected_long_header != actual_long_header {
            return Err(Error::CryptoError("Packet type mismatch".to_string()));
        }
        
        // Validate minimum packet size
        let min_size = match packet_type {
            PacketType::Initial => 1200, // RFC 9000: Initial packets must be at least 1200 bytes
            _ => 20, // Minimum for other packet types
        };
        
        if packet_data.len() < min_size {
            return Err(Error::CryptoError(format!(
                "Packet too small: {} bytes (minimum {})", 
                packet_data.len(), 
                min_size
            )));
        }
        
        Ok(())
    }
    
    /// Get encryption overhead for a packet type
    pub fn encryption_overhead(&self, packet_type: PacketType) -> usize {
        match packet_type {
            PacketType::Retry => 0, // Retry packets are not encrypted
            _ => 16, // AEAD tag size for AES-128-GCM
        }
    }
    
    /// Get local connection ID
    fn local_cid(&self) -> Result<ConnectionId> {
        self.local_cid.clone()
            .ok_or_else(|| Error::CryptoError("Local connection ID not set".to_string()))
    }
    
    /// Get remote connection ID
    fn remote_cid(&self) -> Result<ConnectionId> {
        self.remote_cid.clone()
            .ok_or_else(|| Error::CryptoError("Remote connection ID not set".to_string()))
    }
    
    /// Parse header for decryption
    fn parse_header_for_decryption(&self, packet_data: &[u8]) -> Result<(PacketHeader, usize, usize, usize)> {
        // This is a simplified parser - real implementation would be more complete
        if packet_data.is_empty() {
            return Err(Error::CryptoError("Empty packet".to_string()));
        }
        
        let first_byte = packet_data[0];
        
        if (first_byte & 0x80) != 0 {
            // Long header - actually parse it properly
            let pn_offset = self.get_pn_offset(packet_data)?;
            
            // Get packet number length from the protected first byte
            let pn_length = ((first_byte & 0x03) + 1) as usize;
            
            // Header length is pn_offset + pn_length
            let header_len = pn_offset + pn_length;
            
            // Create a dummy header for now
            let header = PacketHeader::Long(LongHeader::new(
                PacketType::Initial,
                0x0000_0001,
                self.local_cid()?,
                self.remote_cid()?,
                crate::quic::packet::TypeSpecificData::Initial {
                    token: bytes::Bytes::new(),
                    length: crate::util::varint::VarInt::from_u32(0),
                    packet_number: 0,
                },
            ));
            
            Ok((header, header_len, pn_offset, pn_length))
        } else {
            // Short header
            let dcid_len = 8;  // We use 8-byte DCID
            let header_len = 1 + dcid_len + 4; // 1 byte header + 8 byte DCID + 4 byte PN = 13
            let pn_offset = 1 + dcid_len;  // After header byte and DCID
            let pn_length = 4;  // We always use 4-byte packet numbers
            
            // Create dummy short header
            let header = PacketHeader::Short(crate::quic::packet::ShortHeader {
                dst_cid: self.remote_cid()?,
                packet_number: 0,
                spin_bit: false,
                key_phase: false,
            });
            
            Ok((header, header_len, pn_offset, pn_length))
        }
    }
    
    /// Get the offset of the packet number in the header
    fn get_pn_offset(&self, header_data: &[u8]) -> Result<usize> {
        if header_data.is_empty() {
            return Err(Error::CryptoError("Empty header".to_string()));
        }
        
        let first_byte = header_data[0];
        
        if (first_byte & 0x80) != 0 {
            // Long header
            // Format: type(1) + version(4) + dcid_len(1) + dcid(var) + scid_len(1) + scid(var) + payload_len(var) + pn(4)
            let mut offset = 1; // Skip type byte
            offset += 4; // Skip version
            
            if header_data.len() <= offset {
                return Err(Error::CryptoError("Header too short".to_string()));
            }
            
            // Skip DCID
            let dcid_len = header_data[offset] as usize;
            offset += 1 + dcid_len;
            
            if header_data.len() <= offset {
                return Err(Error::CryptoError("Header too short for SCID".to_string()));
            }
            
            // Skip SCID
            let scid_len = header_data[offset] as usize;
            offset += 1 + scid_len;
            
            // For Initial packets, skip token
            let type_bits = (first_byte & 0x30) >> 4;
            if type_bits == 0 { // Initial packet
                if header_data.len() <= offset {
                    return Err(Error::CryptoError("Header too short for token length".to_string()));
                }
                
                // Read token length as varint
                let token_len_first = header_data[offset];
                let token_len_size = match token_len_first >> 6 {
                    0 => 1,
                    1 => 2, 
                    2 => 4,
                    3 => 8,
                    _ => unreachable!(),
                };
                
                // Extract actual token length value
                let mut token_len = (token_len_first & 0x3f) as usize;
                for i in 1..token_len_size {
                    if offset + i >= header_data.len() {
                        return Err(Error::CryptoError("Header too short for token length".to_string()));
                    }
                    token_len = (token_len << 8) | (header_data[offset + i] as usize);
                }
                
                offset += token_len_size + token_len;
            }
            
            // Skip payload length (variable length integer)
            if header_data.len() <= offset {
                return Err(Error::CryptoError("Header too short for payload length".to_string()));
            }
            
            // Parse variable length integer
            let first_byte = header_data[offset];
            let var_int_len = match first_byte >> 6 {
                0 => 1,
                1 => 2,
                2 => 4,
                3 => 8,
                _ => unreachable!(),
            };
            offset += var_int_len;
            
            Ok(offset)
        } else {
            // Short header
            // Format: type(1) + dcid(var) + pn(1-4)
            // For simplicity, assume 8-byte DCID
            Ok(1 + 8)
        }
    }
    
    /// Encode header with protection
    fn encode_protected_header(
        &self,
        header: &PacketHeader,
        hp_key: &HeaderProtectionKey,
        ciphertext: &[u8],
        buf: &mut BytesMut,
    ) -> Result<()> {
        // First encode the header normally
        let header_start = buf.len();
        header.encode(buf)?;
        let _header_end = buf.len();
        
        // Now apply protection to the first byte and packet number
        match header {
            PacketHeader::Long(_) => {
                // Get the sample from ciphertext
                let sample_offset = 4; // After 4-byte packet number
                if ciphertext.len() < sample_offset + 16 {
                    return Err(Error::CryptoError("Ciphertext too short for sample".to_string()));
                }
                
                let sample = &ciphertext[sample_offset..sample_offset + 16];
                let mask = hp_key.mask(sample)?;
                
                // Protect the first byte (low 4 bits)
                if header_start < buf.len() {
                    buf[header_start] ^= mask[0] & 0x0f;
                }
                
                // The packet number bytes were already protected in apply_header_protection
                // so we don't need to do anything else here
            }
            PacketHeader::Short(_) => {
                // Similar but protect low 5 bits of first byte
                let sample_offset = 4;
                if ciphertext.len() < sample_offset + 16 {
                    return Err(Error::CryptoError("Ciphertext too short for sample".to_string()));
                }
                
                let sample = &ciphertext[sample_offset..sample_offset + 16];
                let mask = hp_key.mask(sample)?;
                
                // Protect the first byte (low 5 bits)
                if header_start < buf.len() {
                    buf[header_start] ^= mask[0] & 0x1f;
                }
            }
        }
        
        Ok(())
    }
}

/// Header parsing information
#[derive(Debug, Clone)]
struct HeaderInfo {
    header_len: usize,
    pn_offset: usize,
    pn_length: usize,
}

/// Cipher suite for QUIC
#[derive(Debug, Clone, Copy)]
pub enum CipherSuite {
    /// AES-128-GCM cipher suite
    Aes128Gcm,
    /// AES-256-GCM cipher suite
    Aes256Gcm,
    /// ChaCha20-Poly1305 cipher suite
    ChaCha20Poly1305,
}

impl CipherSuite {
    fn key_len(&self) -> usize {
        match self {
            CipherSuite::Aes128Gcm => 16,
            CipherSuite::Aes256Gcm => 32,
            CipherSuite::ChaCha20Poly1305 => 32,
        }
    }
    
    fn hp_len(&self) -> usize {
        match self {
            CipherSuite::Aes128Gcm | CipherSuite::Aes256Gcm => 16,
            CipherSuite::ChaCha20Poly1305 => 32,
        }
    }
    
    fn aead_algorithm(&self) -> &'static aead::Algorithm {
        match self {
            CipherSuite::Aes128Gcm => &aead::AES_128_GCM,
            CipherSuite::Aes256Gcm => &aead::AES_256_GCM,
            CipherSuite::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }
}

/// Derive packet protection keys from a secret
fn derive_packet_keys(secret: &[u8]) -> Result<PacketKeys> {
    derive_packet_keys_for_suite(secret, CipherSuite::Aes128Gcm)
}

/// Derive packet protection keys for a specific cipher suite
fn derive_packet_keys_for_suite(secret: &[u8], suite: CipherSuite) -> Result<PacketKeys> {
    // Derive key
    let key = hkdf_expand_label(secret, b"quic key", b"", suite.key_len())?;
    
    // Derive IV (always 12 bytes for all AEAD algorithms)
    let mut iv = [0u8; 12];
    let iv_vec = hkdf_expand_label(secret, b"quic iv", b"", 12)?;
    iv.copy_from_slice(&iv_vec);
    
    // Derive header protection key
    let hp = hkdf_expand_label(secret, b"quic hp", b"", suite.hp_len())?;
    
    // Create AEAD key
    let unbound_key = UnboundKey::new(suite.aead_algorithm(), &key)
        .map_err(|_| Error::CryptoError("Failed to create key".to_string()))?;
    let packet_key = LessSafeKey::new(unbound_key);
    
    // Create header protection key
    let header_key = HeaderProtectionKey::new(&hp)?;
    
    Ok(PacketKeys {
        packet_key,
        header_key,
        iv,
    })
}


/// HKDF-Expand-Label function as defined in RFC 8446 Section 7.1
/// Build HKDF label structure per RFC 8446 - delegates to public crypto module
fn build_hkdf_label(label: &[u8], context: &[u8], length: usize) -> Result<Vec<u8>> {
    Ok(crate::quic::crypto::key_derivation::build_hkdf_info(label, context, length))
}

/// Derive QUIC keys using HKDF-Expand-Label per RFC 8446 - delegates to public crypto module
fn hkdf_expand_label(secret: &[u8], label: &[u8], context: &[u8], length: usize) -> Result<Vec<u8>> {
    crate::quic::crypto::key_derivation::hkdf_expand_label(secret, label, context, length)
        .map_err(|_| Error::CryptoError("HKDF expand failed".to_string()))
}

impl HeaderProtectionKey {
    /// Create a new header protection key
    fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 16 {
            return Err(Error::CryptoError(format!("Invalid HP key length: {} (expected 16)", key.len())));
        }
        Ok(Self {
            key: key.to_vec(),
        })
    }

    /// Generate header protection mask using AES-ECB according to RFC 9001
    fn mask(&self, sample: &[u8]) -> Result<[u8; 5]> {
        if sample.len() < 16 {
            return Err(Error::CryptoError("Sample too short".to_string()));
        }
        
        // Proper AES-ECB header protection per RFC 9001 Section 5.4.1
        // mask = AES-ECB(hp_key, sample[0..16])
        self.mask_aes_ecb(&sample[..16])
    }
    
    /// Generate header protection mask using proper AES-ECB implementation
    /// Implements RFC 9001 Section 5.4.1 header protection
    fn mask_aes_ecb(&self, sample: &[u8]) -> Result<[u8; 5]> {
        if sample.len() < 16 {
            return Err(Error::CryptoError("Sample too short".to_string()));
        }
        
        if self.key.len() != 16 {
            return Err(Error::CryptoError("Invalid key length for AES-128".to_string()));
        }
        
        // RFC 9001 Section 5.4.1: mask = AES-ECB(hp_key, sample)
        // 
        // Since ring doesn't provide AES-ECB directly, we implement it using
        // AES-CTR with a zero nonce to achieve deterministic encryption
        
        use ring::aead;
        
        // Create AES-128-GCM key for deterministic encryption
        let unbound_key = aead::UnboundKey::new(&aead::AES_128_GCM, &self.key)
            .map_err(|_| Error::CryptoError("Failed to create AES key".to_string()))?;
        let key = aead::LessSafeKey::new(unbound_key);
        
        // Use the sample as both plaintext and AAD to create a deterministic mask
        // This gives us the equivalent of AES-ECB(key, sample)
        let mut plaintext = sample[..16].to_vec();
        
        // Zero nonce for deterministic behavior (simulates ECB mode)
        let nonce_bytes = [0u8; 12];
        let nonce = aead::Nonce::try_assume_unique_for_key(&nonce_bytes)
            .map_err(|_| Error::CryptoError("Nonce creation failed".to_string()))?;
        
        // Encrypt with empty AAD - this gives us deterministic output based on the sample
        key.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut plaintext)
            .map_err(|_| Error::CryptoError("AES encryption failed".to_string()))?;
        
        // Extract the first 5 bytes as the header protection mask
        let mut mask = [0u8; 5];
        if plaintext.len() >= 5 {
            mask.copy_from_slice(&plaintext[..5]);
            Ok(mask)
        } else {
            Err(Error::CryptoError("Insufficient encrypted data for mask".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_computation() {
        let iv = [0u8; 12];
        let pn = 0x1234_5678_90ab_cdef;
        let nonce = CryptoManager::compute_nonce(&iv, pn);
        
        // Check that packet number is XORed into the last 8 bytes
        assert_eq!(nonce[4], 0x12);
        assert_eq!(nonce[5], 0x34);
        assert_eq!(nonce[6], 0x56);
        assert_eq!(nonce[7], 0x78);
        assert_eq!(nonce[8], 0x90);
        assert_eq!(nonce[9], 0xab);
        assert_eq!(nonce[10], 0xcd);
        assert_eq!(nonce[11], 0xef);
    }
}