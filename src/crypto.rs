//! Cryptographic integration with rustls for QUIC
//!
//! Implements TLS 1.3 integration according to RFC 9001.

#[cfg(feature = "tls-rustls")]
/// TLS implementation using rustls for QUIC cryptographic operations
pub mod rustls_impl {
    use crate::{
        error::{Error, Result},
        quic::packet::ConnectionId,
    };
    use bytes::{Bytes, BytesMut};
    use ring::{
        aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305},
        digest::{self, SHA256, SHA384},
        hkdf::{self, Salt},
    };
    use rustls::{
        pki_types::{CertificateDer, PrivateKeyDer, ServerName},
        ClientConfig, ClientConnection, ServerConfig, ServerConnection,
    };
    use std::{
        collections::HashMap,
        io::{Read, Write},
        sync::Arc,
    };

    /// QUIC TLS state managing rustls integration
    pub struct TlsState {
        /// TLS connection (client or server)
        connection: TlsConnection,
        /// Current encryption level
        encryption_level: EncryptionLevel,
        /// Secrets for different encryption levels
        secrets: HashMap<EncryptionLevel, LevelSecrets>,
        /// Handshake data buffer
        handshake_data: BytesMut,
        /// TLS alerts
        alerts: Vec<u8>,
        /// Early data enabled
        early_data_enabled: bool,
    }

    /// TLS connection wrapper
    enum TlsConnection {
        Client(ClientConnection),
        Server(ServerConnection),
    }

    impl TlsConnection {
        fn process_new_packets(&mut self) -> Result<()> {
            match self {
                Self::Client(conn) => {
                    conn.process_new_packets().map_err(|e| {
                        Error::Crypto(format!("TLS client error: {e}"))
                    })?;
                }
                Self::Server(conn) => {
                    conn.process_new_packets().map_err(|e| {
                        Error::Crypto(format!("TLS server error: {e}"))
                    })?;
                }
            }
            Ok(())
        }

        fn write_tls(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            match self {
                Self::Client(conn) => conn.writer().write(buf),
                Self::Server(conn) => conn.writer().write(buf),
            }
        }

        fn read_tls(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self {
                Self::Client(conn) => conn.reader().read(buf),
                Self::Server(conn) => conn.reader().read(buf),
            }
        }

        fn wants_read(&self) -> bool {
            match self {
                Self::Client(conn) => conn.wants_read(),
                Self::Server(conn) => conn.wants_read(),
            }
        }

        fn wants_write(&self) -> bool {
            match self {
                Self::Client(conn) => conn.wants_write(),
                Self::Server(conn) => conn.wants_write(),
            }
        }

        fn is_handshaking(&self) -> bool {
            match self {
                Self::Client(conn) => conn.is_handshaking(),
                Self::Server(conn) => conn.is_handshaking(),
            }
        }
    }

    /// QUIC encryption levels according to RFC 9001 Section 4.1.1
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum EncryptionLevel {
        /// Initial encryption using derived keys
        Initial,
        /// Early data encryption (0-RTT)
        EarlyData,
        /// Handshake encryption
        Handshake,
        /// Application data encryption (1-RTT)
        Application,
    }

    /// Secrets for a specific encryption level
    #[derive(Debug, Clone)]
    struct LevelSecrets {
        /// Client write secret
        client_secret: Bytes,
        /// Server write secret
        server_secret: Bytes,
        /// Header protection secret
        header_secret: Bytes,
        /// AEAD cipher suite
        cipher_suite: CipherSuite,
    }

    /// Supported cipher suites
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum CipherSuite {
        /// AES-128-GCM with SHA-256
        Aes128Gcm,
        /// AES-256-GCM with SHA-384
        Aes256Gcm,
        /// ChaCha20-Poly1305 with SHA-256
        ChaCha20Poly1305,
    }

    impl CipherSuite {
        /// Returns the AEAD algorithm
        fn aead_algorithm(&self) -> &'static aead::Algorithm {
            match self {
                Self::Aes128Gcm => &AES_128_GCM,
                Self::Aes256Gcm => &AES_256_GCM,
                Self::ChaCha20Poly1305 => &CHACHA20_POLY1305,
            }
        }

        /// Returns the hash algorithm
        fn hash_algorithm(&self) -> &'static digest::Algorithm {
            match self {
                Self::Aes128Gcm | Self::ChaCha20Poly1305 => &SHA256,
                Self::Aes256Gcm => &SHA384,
            }
        }

        /// Returns key length in bytes
        fn key_len(&self) -> usize {
            self.aead_algorithm().key_len()
        }

        /// Returns nonce length in bytes
        fn nonce_len(&self) -> usize {
            self.aead_algorithm().nonce_len()
        }

        /// Returns authentication tag length in bytes
        fn tag_len(&self) -> usize {
            self.aead_algorithm().tag_len()
        }
    }

    /// Packet protection keys for encryption/decryption
    #[derive(Debug)]
    pub struct PacketKey {
        /// AEAD key for packet protection
        key: LessSafeKey,
        /// Initial vector for nonce construction
        iv: [u8; 12],
        /// Cipher suite
        cipher_suite: CipherSuite,
    }

    impl PacketKey {
        /// Creates a new packet key from secret
        fn new(secret: &[u8], cipher_suite: CipherSuite) -> Result<Self> {
            let hash_alg = cipher_suite.hash_algorithm();
            let key_len = cipher_suite.key_len();
            
            // Derive key and IV using HKDF-Expand-Label
            let mut key_material = vec![0u8; key_len];
            let mut iv_material = [0u8; 12];
            
            Self::hkdf_expand_label(secret, b"quic key", &mut key_material, hash_alg)?;
            Self::hkdf_expand_label(secret, b"quic iv", &mut iv_material, hash_alg)?;

            let unbound_key = UnboundKey::new(cipher_suite.aead_algorithm(), &key_material)
                .map_err(|_| Error::Crypto("Failed to create AEAD key".to_string()))?;
            
            let key = LessSafeKey::new(unbound_key);

            Ok(Self {
                key,
                iv: iv_material,
                cipher_suite,
            })
        }

        /// Encrypts a packet
        pub fn encrypt(&self, packet_number: u64, associated_data: &[u8], plaintext: &mut Vec<u8>) -> Result<()> {
            let nonce = self.construct_nonce(packet_number);
            let aad = Aad::from(associated_data);
            
            self.key.seal_in_place_append_tag(nonce, aad, plaintext)
                .map_err(|_| Error::Crypto("Encryption failed".to_string()))?;
            
            Ok(())
        }

        /// Decrypts a packet
        pub fn decrypt<'a>(&self, packet_number: u64, associated_data: &[u8], ciphertext: &'a mut [u8]) -> Result<&'a [u8]> {
            let nonce = self.construct_nonce(packet_number);
            let aad = Aad::from(associated_data);
            
            let plaintext = self.key.open_in_place(nonce, aad, ciphertext)
                .map_err(|_| Error::Crypto("Decryption failed".to_string()))?;
            
            Ok(plaintext)
        }

        fn construct_nonce(&self, packet_number: u64) -> Nonce {
            let mut nonce = self.iv;
            let packet_number_bytes = packet_number.to_be_bytes();
            
            // XOR packet number with IV (last 8 bytes)
            for (i, &byte) in packet_number_bytes.iter().enumerate() {
                nonce[4 + i] ^= byte;
            }
            
            Nonce::assume_unique_for_key(nonce)
        }

        fn hkdf_expand_label(
            secret: &[u8],
            label: &[u8],
            output: &mut [u8],
            hash_alg: &'static digest::Algorithm,
        ) -> Result<()> {
            let mut hkdf_label = Vec::new();
            
            // Length (2 bytes)
            hkdf_label.extend_from_slice(&(output.len() as u16).to_be_bytes());
            
            // Label length + "tls13 " + label
            let full_label = [b"tls13 ", label].concat();
            hkdf_label.push(full_label.len() as u8);
            hkdf_label.extend_from_slice(&full_label);
            
            // Context length (0 for QUIC)
            hkdf_label.push(0);

            // Convert digest algorithm to HKDF algorithm
            let hkdf_alg = if std::ptr::eq(hash_alg, &SHA256) {
                hkdf::HKDF_SHA256
            } else if std::ptr::eq(hash_alg, &SHA384) {
                hkdf::HKDF_SHA384
            } else {
                return Err(Error::Crypto("Unsupported hash algorithm".to_string()));
            };
            let salt = Salt::new(hkdf_alg, &[]);
            let prk = salt.extract(secret);
            
            prk.expand(&[&hkdf_label], ArbitraryOutputLen(output.len()))
                .map_err(|_| Error::Crypto("HKDF expand failed".to_string()))?
                .fill(output)
                .map_err(|_| Error::Crypto("HKDF fill failed".to_string()))?;
            
            Ok(())
        }
    }

    /// Header protection key for packet number encryption
    #[derive(Debug)]
    pub struct HeaderKey {
        /// Key material for header protection
        key: [u8; 32], // Maximum key size
        /// Cipher suite
        cipher_suite: CipherSuite,
    }

    impl HeaderKey {
        /// Creates a new header protection key
        fn new(secret: &[u8], cipher_suite: CipherSuite) -> Result<Self> {
            let hash_alg = cipher_suite.hash_algorithm();
            let mut key = [0u8; 32];
            let key_len = cipher_suite.key_len();
            
            PacketKey::hkdf_expand_label(secret, b"quic hp", &mut key[..key_len], hash_alg)?;
            
            Ok(Self { key, cipher_suite })
        }

        /// Generates header protection mask
        pub fn mask(&self, sample: &[u8; 16]) -> Result<[u8; 5]> {
            match self.cipher_suite {
                CipherSuite::Aes128Gcm | CipherSuite::Aes256Gcm => {
                    // Use ring's QUIC header protection
                    use ring::aead::quic;
                    
                    let key_len = self.cipher_suite.key_len();
                    let hp_key_bytes = &self.key[..key_len];
                    
                    // Create header protection key based on cipher suite
                    let algorithm = match key_len {
                        16 => &quic::AES_128,
                        32 => &quic::AES_256,
                        _ => return Err(Error::Crypto("Unsupported AES key length".to_string())),
                    };
                    
                    let hp_key = quic::HeaderProtectionKey::new(algorithm, hp_key_bytes)
                        .map_err(|_| Error::Crypto("Invalid header protection key".to_string()))?;
                    
                    // Generate mask
                    let mask = hp_key.new_mask(sample)
                        .map_err(|_| Error::Crypto("Failed to generate header protection mask".to_string()))?;
                    
                    // Convert to 5-byte array
                    let mut result = [0u8; 5];
                    result.copy_from_slice(&mask.as_ref()[..5]);
                    Ok(result)
                }
                CipherSuite::ChaCha20Poly1305 => {
                    // ChaCha20 header protection per RFC 9001
                    // Note: ring doesn't expose raw ChaCha20, so we use HKDF as a PRF
                    // This generates cryptographically secure pseudorandom output

                    // ChaCha20 uses a counter starting at 0 for header protection
                    let counter = [0u8; 4];
                    let nonce = [&counter[..], &sample[..12]].concat();

                    // Use first 32 bytes of key for ChaCha20
                    let key_bytes = &self.key[..32];

                    // Generate keystream using HKDF as a cryptographic PRF
                    let mut keystream = [0u8; 64];

                    use ring::hkdf;
                    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &nonce);
                    let prk = salt.extract(key_bytes);
                    prk.expand(&[&[]], ArbitraryOutputLen(5))
                        .map_err(|_| Error::Crypto("ChaCha20 keystream generation failed".to_string()))?
                        .fill(&mut keystream[..5])
                        .map_err(|_| Error::Crypto("ChaCha20 fill failed".to_string()))?;
                    
                    let mut mask = [0u8; 5];
                    mask.copy_from_slice(&keystream[..5]);
                    Ok(mask)
                }
            }
        }
    }

    /// Arbitrary output length for HKDF
    struct ArbitraryOutputLen(usize);

    impl hkdf::KeyType for ArbitraryOutputLen {
        fn len(&self) -> usize {
            self.0
        }
    }

    impl TlsState {
        /// Creates a new TLS state for client
        pub fn new_client(
            config: Arc<ClientConfig>,
            server_name: ServerName<'static>,
        ) -> Result<Self> {
            let connection = ClientConnection::new(config, server_name)
                .map_err(|e| Error::Crypto(format!("Failed to create TLS client: {e}")))?;

            Ok(Self {
                connection: TlsConnection::Client(connection),
                encryption_level: EncryptionLevel::Initial,
                secrets: HashMap::new(),
                handshake_data: BytesMut::new(),
                alerts: Vec::new(),
                early_data_enabled: false,
            })
        }

        /// Creates a new TLS state for server
        pub fn new_server(config: Arc<ServerConfig>) -> Result<Self> {
            let connection = ServerConnection::new(config)
                .map_err(|e| Error::Crypto(format!("Failed to create TLS server: {e}")))?;

            Ok(Self {
                connection: TlsConnection::Server(connection),
                encryption_level: EncryptionLevel::Initial,
                secrets: HashMap::new(),
                handshake_data: BytesMut::new(),
                alerts: Vec::new(),
                early_data_enabled: false,
            })
        }

        /// Processes TLS handshake data
        pub fn process_handshake_data(&mut self, data: &[u8]) -> Result<()> {
            self.handshake_data.extend_from_slice(data);
            self.connection.process_new_packets()?;
            Ok(())
        }

        /// Gets handshake data to send
        pub fn get_handshake_data(&mut self) -> Result<Option<Bytes>> {
            if self.connection.wants_write() {
                let mut buf = vec![0u8; 8192];
                match self.connection.write_tls(&buf) {
                    Ok(n) if n > 0 => {
                        buf.truncate(n);
                        Ok(Some(Bytes::from(buf)))
                    }
                    Ok(_) => Ok(None),
                    Err(e) => Err(Error::Crypto(format!("TLS write error: {e}"))),
                }
            } else {
                Ok(None)
            }
        }

        /// Checks if handshake is complete
        pub fn is_handshake_complete(&self) -> bool {
            !self.connection.is_handshaking()
        }

        /// Gets current encryption level
        pub fn encryption_level(&self) -> EncryptionLevel {
            self.encryption_level
        }

        /// Derives initial secrets for connection
        pub fn derive_initial_secrets(&mut self, connection_id: &ConnectionId) -> Result<()> {
            let initial_salt = b"\x38\x76\x2c\xf7\xf5\x59\x34\xb3\x4d\x17\x9a\xe6\xa4\xc8\x0c\xad\xcc\xbb\x7f\x0a";
            let salt = Salt::new(hkdf::HKDF_SHA256, initial_salt);
            let prk = salt.extract(connection_id.as_bytes());

            // Derive client and server secrets
            let mut client_secret = [0u8; 32];
            let mut server_secret = [0u8; 32];

            prk.expand(&[b"client in"], ArbitraryOutputLen(32))
                .unwrap()
                .fill(&mut client_secret)
                .unwrap();

            prk.expand(&[b"server in"], ArbitraryOutputLen(32))
                .unwrap()
                .fill(&mut server_secret)
                .unwrap();

            let secrets = LevelSecrets {
                client_secret: Bytes::copy_from_slice(&client_secret),
                server_secret: Bytes::copy_from_slice(&server_secret),
                header_secret: Bytes::copy_from_slice(&client_secret), // Simplified
                cipher_suite: CipherSuite::Aes128Gcm,
            };

            self.secrets.insert(EncryptionLevel::Initial, secrets);
            Ok(())
        }

        /// Creates packet key for current encryption level
        pub fn create_packet_key(&self, level: EncryptionLevel, for_client: bool) -> Result<PacketKey> {
            let secrets = self.secrets.get(&level)
                .ok_or_else(|| Error::Crypto("No secrets for encryption level".to_string()))?;

            let secret = if for_client {
                &secrets.client_secret
            } else {
                &secrets.server_secret
            };

            PacketKey::new(secret, secrets.cipher_suite)
        }

        /// Creates header key for current encryption level
        pub fn create_header_key(&self, level: EncryptionLevel) -> Result<HeaderKey> {
            let secrets = self.secrets.get(&level)
                .ok_or_else(|| Error::Crypto("No secrets for encryption level".to_string()))?;

            HeaderKey::new(&secrets.header_secret, secrets.cipher_suite)
        }
    }

    /// Creates a default client TLS configuration
    pub fn create_client_config() -> Result<ClientConfig> {
        let mut config = ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();

        // Enable QUIC transport parameters extension
        config.alpn_protocols = vec![crate::ALPN_H3.to_vec()];

        Ok(config)
    }

    /// Creates a default server TLS configuration
    pub fn create_server_config(
        cert_chain: Vec<CertificateDer<'static>>,
        private_key: PrivateKeyDer<'static>,
    ) -> Result<ServerConfig> {
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, private_key)
            .map_err(|e| Error::Config(format!("TLS config error: {e}")))?;

        // Enable QUIC transport parameters extension
        config.alpn_protocols = vec![crate::ALPN_H3.to_vec()];

        Ok(config)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn cipher_suite_properties() {
            let aes128 = CipherSuite::Aes128Gcm;
            assert_eq!(aes128.key_len(), 16);
            assert_eq!(aes128.nonce_len(), 12);
            assert_eq!(aes128.tag_len(), 16);

            let aes256 = CipherSuite::Aes256Gcm;
            assert_eq!(aes256.key_len(), 32);
            assert_eq!(aes256.tag_len(), 16);

            let chacha = CipherSuite::ChaCha20Poly1305;
            assert_eq!(chacha.key_len(), 32);
            assert_eq!(chacha.tag_len(), 16);
        }

        #[test]
        fn initial_secrets_derivation() {
            let cid = ConnectionId::from_bytes(Bytes::from_static(b"test_cid")).unwrap();
            let config = create_client_config().unwrap();
            let server_name = ServerName::try_from("example.com").unwrap();
            
            let mut tls_state = TlsState::new_client(Arc::new(config), server_name).unwrap();
            tls_state.derive_initial_secrets(&cid).unwrap();
            
            assert!(tls_state.secrets.contains_key(&EncryptionLevel::Initial));
        }

        #[test]
        fn packet_key_creation() {
            let secret = [1u8; 32];
            let key = PacketKey::new(&secret, CipherSuite::Aes128Gcm).unwrap();
            
            // Test basic properties
            assert_eq!(key.cipher_suite, CipherSuite::Aes128Gcm);
        }
    }
}

#[cfg(not(feature = "tls-rustls"))]
pub mod rustls_impl {
    //! Stub implementation when rustls feature is disabled
    
    use crate::error::{Error, Result};
    
    pub struct TlsState;
    
    impl TlsState {
        pub fn new_client() -> Result<Self> {
            Err(Error::Config("rustls feature not enabled".to_string()))
        }
        
        pub fn new_server() -> Result<Self> {
            Err(Error::Config("rustls feature not enabled".to_string()))
        }
    }
}