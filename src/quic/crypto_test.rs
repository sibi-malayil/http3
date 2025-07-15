//! Test crypto functionality

#[cfg(test)]
mod tests {
    use super::super::{
        crypto_impl::CryptoManager,
        frame_types::Frame,
        connection::ConnectionRole,
    };
    use bytes::Bytes;

    #[tokio::test]
    async fn test_basic_crypto_operations() {
        // Create a crypto manager
        let mut crypto = CryptoManager::new(ConnectionRole::Client).unwrap();
        
        // Initialize with dummy connection ID
        let connection_id = b"test_cid";
        crypto.init_initial_keys(connection_id).unwrap();
        
        // Create some test frames
        let frames = vec![
            Frame::Ping,
            Frame::Crypto {
                offset: 0,
                data: Bytes::from_static(b"hello world"),
            },
            Frame::Padding,
        ];
        
        // Test encryption
        let encrypted = crypto.encrypt_packet(1, frames).await.unwrap();
        assert!(!encrypted.is_empty());
        
        // Test decryption
        let decrypted = crypto.decrypt_packet(&encrypted).await.unwrap();
        assert!(decrypted.packet_number > 0);
        assert!(!decrypted.frames.is_empty());
        
        println!("✅ Basic crypto operations test passed");
        println!("   - Encrypted packet size: {} bytes", encrypted.len());
        println!("   - Decrypted frames: {}", decrypted.frames.len());
    }

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
        
        println!("✅ Nonce computation test passed");
    }
}