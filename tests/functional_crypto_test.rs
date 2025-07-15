//! Functional cryptographic integration tests
//!
//! These tests demonstrate the working crypto functionality

use http3::{
    quic::{
        crypto_impl::CryptoManager,
        connection::ConnectionRole,
        frame_types::Frame,
        packet::PacketType,
    },
    error::Result,
};
use bytes::Bytes;
use tokio;

#[tokio::test]
async fn test_crypto_manager_creation() -> Result<()> {
    // Test client creation
    let client_crypto = CryptoManager::new_client("localhost")?;
    assert_eq!(client_crypto.role(), ConnectionRole::Client);
    
    // Test server creation
    let server_crypto = CryptoManager::new_server_self_signed()?;
    assert_eq!(server_crypto.role(), ConnectionRole::Server);
    
    println!("✅ Crypto manager creation successful");
    Ok(())
}

#[tokio::test]
async fn test_initial_key_derivation() -> Result<()> {
    let mut crypto = CryptoManager::new_client("localhost")?;
    
    // Test initial key derivation
    let client_dst_cid = b"test_connection_id_12345678";
    crypto.init_initial_keys(client_dst_cid)?;
    
    // Verify we can determine packet type
    let level = crypto.current_level();
    assert_eq!(level, http3::quic::crypto_impl::PacketProtectionLevel::Initial);
    
    println!("✅ Initial key derivation successful");
    Ok(())
}

#[tokio::test]
async fn test_packet_encryption_decryption() -> Result<()> {
    let mut crypto = CryptoManager::new_client("localhost")?;
    
    // Initialize with test connection ID
    let client_dst_cid = b"test_conn_id_1234567890ab";
    crypto.init_initial_keys(client_dst_cid)?;
    
    // Create test frames
    let frames = vec![
        Frame::Ping,
        Frame::Crypto {
            offset: 0,
            data: Bytes::from_static(b"TLS handshake data"),
        },
    ];
    
    // Test encryption
    let encrypted_packet = crypto.encrypt_packet(1, frames.clone()).await?;
    assert!(!encrypted_packet.is_empty());
    assert!(encrypted_packet.len() >= 1200, "Initial packets must be >= 1200 bytes");
    
    println!("✅ Packet encryption successful: {} bytes", encrypted_packet.len());
    
    // Test decryption
    let decrypted = crypto.decrypt_packet(&encrypted_packet).await?;
    assert!(decrypted.packet_number > 0);
    assert!(!decrypted.frames.is_empty());
    
    println!("✅ Packet decryption successful: {} frames", decrypted.frames.len());
    Ok(())
}

#[tokio::test]
async fn test_crypto_frame_processing() -> Result<()> {
    let mut client_crypto = CryptoManager::new_client("localhost")?;
    let mut server_crypto = CryptoManager::new_server_self_signed()?;
    
    // Initialize initial keys
    let client_dst_cid = b"client_connection_id_123";
    client_crypto.init_initial_keys(client_dst_cid)?;
    server_crypto.init_initial_keys(client_dst_cid)?;
    
    // Start handshake on client
    client_crypto.start_handshake().await?;
    
    // Get initial handshake data from client
    if let Some(handshake_data) = client_crypto.get_handshake_data() {
        let crypto_data = Bytes::from(handshake_data);
        
        // Process on server
        server_crypto.process_crypto_frame(0, crypto_data).await?;
        
        println!("✅ CRYPTO frame processing successful");
    }
    
    Ok(())
}

#[tokio::test]
async fn test_key_update() -> Result<()> {
    let mut crypto = CryptoManager::new_client("localhost")?;
    
    // Initialize initial keys
    let client_dst_cid = b"test_key_update_conn_id_";
    crypto.init_initial_keys(client_dst_cid)?;
    
    // Simulate handshake completion and derive application keys
    let client_secret = vec![0x42u8; 32];
    let server_secret = vec![0x84u8; 32];
    crypto.derive_application_keys(&client_secret, &server_secret)?;
    
    // Test key update
    crypto.update_keys()?;
    
    println!("✅ Key update successful");
    Ok(())
}

#[tokio::test]
async fn test_alpn_negotiation() -> Result<()> {
    let crypto = CryptoManager::new_client("localhost")?;
    
    // Test ALPN protocol detection
    let alpn = crypto.negotiated_alpn();
    // Initially none, would be Some(b"h3") after successful handshake
    println!("✅ ALPN state: {:?}", alpn);
    
    Ok(())
}

#[tokio::test]
async fn test_retry_integrity_tag() -> Result<()> {
    // Test Retry Integrity Tag calculation per RFC 9001
    let retry_pseudo_packet = b"test retry pseudo packet data for integrity calculation";
    
    let tag = CryptoManager::calculate_retry_integrity_tag(retry_pseudo_packet)?;
    assert_eq!(tag.len(), 16);
    
    // Verify deterministic calculation
    let tag2 = CryptoManager::calculate_retry_integrity_tag(retry_pseudo_packet)?;
    assert_eq!(tag, tag2);
    
    println!("✅ Retry integrity tag calculation successful");
    Ok(())
}

#[tokio::test]
async fn test_packet_validation() -> Result<()> {
    let crypto = CryptoManager::new_client("localhost")?;
    
    // Test valid Initial packet
    let mut initial_packet = vec![0x80]; // Long header with Initial type
    initial_packet.extend_from_slice(&[0, 0, 0, 1]); // Version
    initial_packet.extend_from_slice(&[8]); // DCID length
    initial_packet.extend_from_slice(&[0; 8]); // DCID
    initial_packet.extend_from_slice(&[8]); // SCID length  
    initial_packet.extend_from_slice(&[0; 8]); // SCID
    initial_packet.extend_from_slice(&[0]); // Token length
    initial_packet.extend_from_slice(&[0x44, 0x00]); // Length (VarInt)
    initial_packet.extend_from_slice(&[0; 1200]); // Padding to minimum size
    
    crypto.validate_packet_auth(&initial_packet, PacketType::Initial)?;
    
    println!("✅ Packet validation successful");
    Ok(())
}

#[tokio::test]
async fn test_cipher_suite_support() -> Result<()> {
    let crypto = CryptoManager::new_client("localhost")?;
    
    // Test cipher suite detection
    let suite = crypto.cipher_suite();
    println!("✅ Cipher suite: {:?}", suite);
    
    // Test encryption overhead calculation
    let overhead = crypto.encryption_overhead(PacketType::Initial);
    assert_eq!(overhead, 16); // AEAD tag size
    
    let retry_overhead = crypto.encryption_overhead(PacketType::Retry);
    assert_eq!(retry_overhead, 0); // Retry packets not encrypted
    
    println!("✅ Cipher suite support verified");
    Ok(())
}

#[tokio::test]
async fn test_zero_rtt_support() -> Result<()> {
    let crypto = CryptoManager::new_client("localhost")?;
    
    // Test 0-RTT availability
    let zero_rtt_available = crypto.zero_rtt_available();
    println!("✅ 0-RTT available: {}", zero_rtt_available);
    
    // Test early keying material export
    if zero_rtt_available {
        let early_data = crypto.export_early_keying_material(b"test", b"context", 32)?;
        assert_eq!(early_data.len(), 32);
        println!("✅ Early keying material export successful");
    }
    
    Ok(())
}

/// Integration test demonstrating end-to-end crypto functionality
#[tokio::test]
async fn test_end_to_end_crypto_flow() -> Result<()> {
    println!("🚀 Starting end-to-end crypto integration test");
    
    // 1. Create client and server crypto managers
    let mut client = CryptoManager::new_client("localhost")?;
    let mut server = CryptoManager::new_server_self_signed()?;
    
    // 2. Initialize initial keys with shared connection ID
    let shared_cid = b"shared_connection_id_e2e_test";
    client.init_initial_keys(shared_cid)?;
    server.init_initial_keys(shared_cid)?;
    
    println!("   ✓ Initial keys derived");
    
    // 3. Start handshake
    client.start_handshake().await?;
    
    // 4. Test packet encryption/decryption cycle
    let test_frames = vec![
        Frame::Ping,
        Frame::Crypto {
            offset: 0,
            data: Bytes::from_static(b"ClientHello handshake message"),
        },
    ];
    
    // 5. Client encrypts packet
    let encrypted = client.encrypt_packet(1, test_frames).await?;
    println!("   ✓ Client encrypted packet: {} bytes", encrypted.len());
    
    // 6. Server decrypts packet  
    let decrypted = server.decrypt_packet(&encrypted).await?;
    println!("   ✓ Server decrypted packet: {} frames", decrypted.frames.len());
    
    // 7. Verify packet number
    assert_eq!(decrypted.packet_number, 1);
    
    // 8. Test CRYPTO frame processing
    if let Some(Frame::Crypto { data, .. }) = decrypted.frames.iter().find(|f| matches!(f, Frame::Crypto { .. })) {
        server.process_crypto_frame(0, data.clone()).await?;
        println!("   ✓ Server processed CRYPTO frame");
    }
    
    // 9. Get server response
    if let Some(server_handshake_data) = server.get_handshake_data() {
        let response_frame = Frame::Crypto {
            offset: 0,
            data: Bytes::from(server_handshake_data),
        };
        
        let server_response = server.encrypt_packet(1, vec![response_frame]).await?;
        println!("   ✓ Server encrypted response: {} bytes", server_response.len());
        
        // 10. Client processes server response
        let client_decrypted = client.decrypt_packet(&server_response).await?;
        println!("   ✓ Client decrypted server response: {} frames", client_decrypted.frames.len());
    }
    
    println!("🎉 End-to-end crypto integration test completed successfully!");
    Ok(())
}