//! Test rustls key extraction and packet encryption/decryption

use http3::quic::{
    crypto_impl::CryptoManager,
    frame_types::Frame,
};

#[tokio::test]
async fn test_rustls_key_extraction() {
    // Create server first
    let mut server = CryptoManager::new_server_self_signed().unwrap();
    
    // Create client that accepts self-signed certificates
    let mut client = CryptoManager::new_client_for_testing("localhost").unwrap();
    
    // Initialize initial keys
    let connection_id = b"test_conn_id";
    client.init_initial_keys(connection_id).unwrap();
    server.init_initial_keys(connection_id).unwrap();
    
    // Start handshake
    let client_hello = client.start_handshake().await.unwrap();
    assert!(!client_hello.is_empty(), "Client should generate ClientHello");
    
    // Server processes ClientHello
    server.process_crypto_frame(0, client_hello.into()).await.unwrap();
    
    // Get server response (ServerHello + other handshake messages)
    let server_data = server.get_handshake_data();
    assert!(server_data.is_some(), "Server should generate handshake data");
    
    // Client processes server handshake
    client.process_crypto_frame(0, server_data.unwrap().into()).await.unwrap();
    
    // Check if handshake keys are installed
    // After processing handshake messages, rustls should call install_key_change
    // with handshake keys
    
    // Try to encrypt a handshake packet
    let test_frame = Frame::Ping;
    let result = client.encrypt_packet(0, vec![test_frame]).await;
    
    // The encryption should work if keys are properly installed
    if let Err(e) = &result {
        eprintln!("Encryption failed: {:?}", e);
    }
    assert!(result.is_ok(), "Should be able to encrypt with handshake keys");
}

#[tokio::test] 
async fn test_packet_encryption_with_rustls_keys() {
    // This test verifies that once rustls keys are installed,
    // we can properly encrypt and decrypt packets
    
    let mut server = CryptoManager::new_server_self_signed().unwrap();
    let mut client = CryptoManager::new_client_for_testing("localhost").unwrap();
    
    // Initialize and complete handshake (simplified)
    let connection_id = b"test_conn_id";
    client.init_initial_keys(connection_id).unwrap();
    server.init_initial_keys(connection_id).unwrap();
    
    // Exchange handshake messages
    let client_hello = client.start_handshake().await.unwrap();
    server.process_crypto_frame(0, client_hello.into()).await.unwrap();
    
    if let Some(server_hello) = server.get_handshake_data() {
        client.process_crypto_frame(0, server_hello.into()).await.unwrap();
    }
    
    // Continue handshake until complete
    let mut round = 0;
    while !client.handshake_complete().await.unwrap() && round < 10 {
        // Client's turn
        if let Some(data) = client.get_handshake_data() {
            server.process_crypto_frame(0, data.into()).await.unwrap();
        }
        
        // Server's turn
        if let Some(data) = server.get_handshake_data() {
            client.process_crypto_frame(0, data.into()).await.unwrap();
        }
        
        round += 1;
    }
    
    // Now test encryption/decryption with application keys
    if client.handshake_complete().await.unwrap() {
        let test_frames = vec![Frame::Ping, Frame::Padding];
        
        // Client encrypts
        let encrypted = client.encrypt_packet(1, test_frames.clone()).await.unwrap();
        
        // Server decrypts
        let decrypted = server.decrypt_packet(&encrypted).await.unwrap();
        
        // Verify frames match
        assert_eq!(decrypted.frames.len(), test_frames.len());
        assert_eq!(decrypted.packet_number, 1);
    }
}