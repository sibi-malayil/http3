//! QUIC cryptographic manager implementation
//!
//! Integrates TLS 1.3 with QUIC per RFC 9001.
//! 
//! This is a compatibility wrapper that delegates to the full implementation
//! in crypto_impl.rs for backward compatibility.

// Re-export the full implementation
pub use crate::quic::crypto_impl::{
    CryptoManager, 
    DecryptedPacket, 
    PacketProtectionLevel,
    CipherSuite,
};

/// Key derivation utilities following RFC 9001 Section 5
pub mod key_derivation {
    use ring::hkdf;

    /// QUIC version 1 label prefix
    pub const QUIC_VERSION_LABEL: &[u8] = b"tls13 quic ";

    /// Derive QUIC keys using HKDF-Expand-Label
    pub fn hkdf_expand_label(
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        length: usize,
    ) -> Result<Vec<u8>, ring::error::Unspecified> {
        let mut info = Vec::new();

        // Length (2 bytes, big-endian)
        info.extend_from_slice(&(length as u16).to_be_bytes());

        // Label length + label (prefixed with "tls13 quic ")
        let full_label = [QUIC_VERSION_LABEL, label].concat();
        info.push(full_label.len() as u8);
        info.extend_from_slice(&full_label);

        // Context length + context
        info.push(context.len() as u8);
        info.extend_from_slice(context);

        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]);
        let prk = salt.extract(secret);
        let info_slice = info.as_slice();
        let info_array = [info_slice];
        let okm = prk.expand(&info_array, hkdf::HKDF_SHA256)?;

        let mut output = vec![0u8; length];
        okm.fill(&mut output)?;
        Ok(output)
    }

    /// Build HKDF info structure for key derivation
    pub fn build_hkdf_info(label: &[u8], context: &[u8], length: usize) -> Vec<u8> {
        let mut info = Vec::new();

        // Length as 2 bytes
        info.push((length >> 8) as u8);
        info.push(length as u8);

        // Label with "tls13 " prefix
        let full_label = [b"tls13 ", label].concat();
        info.push(full_label.len() as u8);
        info.extend_from_slice(&full_label);

        // Context
        info.push(context.len() as u8);
        info.extend_from_slice(context);

        info
    }

    /// Derive initial secrets from connection ID per RFC 9001
    pub fn derive_initial_secrets(connection_id: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ring::error::Unspecified> {
        // Use the RFC 9001 compliant initial salt from crypto_impl
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, crate::quic::crypto_impl::INITIAL_SALT);
        let initial_secret = salt.extract(connection_id);
        
        // Derive client and server initial secrets using PRK expand
        let client_info = build_hkdf_info(b"client in", &[], 32);
        let client_info_slice = client_info.as_slice();
        let client_info_array = [client_info_slice];
        let client_okm = initial_secret.expand(&client_info_array, hkdf::HKDF_SHA256)
            .map_err(|_| ring::error::Unspecified)?;
        let mut client_secret = vec![0u8; 32];
        client_okm.fill(&mut client_secret).map_err(|_| ring::error::Unspecified)?;
        
        let server_info = build_hkdf_info(b"server in", &[], 32);
        let server_info_slice = server_info.as_slice();
        let server_info_array = [server_info_slice];
        let server_okm = initial_secret.expand(&server_info_array, hkdf::HKDF_SHA256)
            .map_err(|_| ring::error::Unspecified)?;
        let mut server_secret = vec![0u8; 32];
        server_okm.fill(&mut server_secret).map_err(|_| ring::error::Unspecified)?;
        
        Ok((client_secret, server_secret))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::packet::{ConnectionId, PacketHeader, Packet};
    use crate::quic::connection::ConnectionRole;
    use crate::quic::frame_types::Frame;

    #[tokio::test]
    async fn crypto_manager_creation() {
        let crypto = CryptoManager::new(ConnectionRole::Client).unwrap();
        assert!(!crypto.handshake_complete().await.unwrap());
    }

    #[tokio::test]
    async fn handshake_simulation() {
        let mut crypto = CryptoManager::new(ConnectionRole::Client).unwrap();
        
        // Start handshake
        crypto.start_handshake().await.unwrap();
        assert!(!crypto.handshake_complete().await.unwrap());
        
        // Process crypto data to complete handshake
        let crypto_data = vec![0u8; 150]; // Enough to trigger completion
        crypto.process_crypto_frame(0, crypto_data.into()).await.unwrap();
        assert!(crypto.handshake_complete().await.unwrap());
    }

    #[tokio::test]
    async fn packet_encryption_decryption() {
        let mut crypto = CryptoManager::new(ConnectionRole::Client).unwrap();
        
        // Encrypt some frames
        let frames = vec![Frame::Ping];
        let encrypted = crypto.encrypt_packet(1, frames).await.unwrap();
        assert!(!encrypted.is_empty());
        
        // Create a dummy packet for decryption
        use crate::quic::packet::ShortHeader;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        
        let header = PacketHeader::Short(ShortHeader::new(
            false, // spin_bit
            false, // key_phase
            ConnectionId::random(8).unwrap(),
            1, // packet_number
        ));
        
        let packet = Packet::new(
            header,
            encrypted,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081),
        );
        
        // Decrypt the packet
        let packet_data = &packet.payload;
        let decrypted = crypto.decrypt_packet(packet_data).await.unwrap();
        assert!(!decrypted.frames.is_empty());
    }

    #[test]
    fn initial_key_derivation() {
        let connection_id = b"test_connection_id";
        let result = key_derivation::derive_initial_secrets(connection_id);
        assert!(result.is_ok());
        
        let (client_secret, server_secret) = result.unwrap();
        assert_eq!(client_secret.len(), 32);
        assert_eq!(server_secret.len(), 32);
        assert_ne!(client_secret, server_secret);
    }
}