//! Debug test for crypto issues

use http3::quic::{
    crypto_impl::CryptoManager,
    connection::ConnectionRole,
    packet::ConnectionId,
    frame_types::Frame,
};
use bytes::Bytes;

#[tokio::test]
async fn test_matching_crypto() {
    // Use the exact same connection IDs from the failing test
    let client_cid = ConnectionId::from_bytes(Bytes::from(vec![0xbc, 0x50, 0x29, 0x4f, 0x90, 0x65, 0x0e, 0xfa])).unwrap();
    let server_cid = ConnectionId::from_bytes(Bytes::from(vec![0x24, 0x7a, 0x0d, 0x5e, 0xf0, 0x32, 0x9e, 0x46])).unwrap();
    
    // Create crypto managers
    let mut server_crypto = CryptoManager::new(ConnectionRole::Server).unwrap();
    server_crypto.set_connection_ids(server_cid.clone(), client_cid.clone());
    
    // Initialize with server's CID as DCID
    let initial_dcid = server_cid.as_bytes();
    server_crypto.init_initial_keys(initial_dcid).unwrap();
    
    // Create a large CRYPTO frame like in the real test
    let crypto_data = vec![0x42; 1752]; // 1752 bytes of dummy data
    let frame = Frame::Crypto {
        offset: 0,
        data: Bytes::from(crypto_data),
    };
    
    // Server encrypts
    println!("Server encrypting packet with 1752-byte CRYPTO frame");
    let encrypted = server_crypto.encrypt_packet(0, vec![frame]).await.unwrap();
    println!("Encrypted packet size: {} bytes", encrypted.len());
    
    // Now create client with same setup
    let mut client_crypto = CryptoManager::new(ConnectionRole::Client).unwrap();
    client_crypto.set_connection_ids(client_cid.clone(), server_cid.clone());
    client_crypto.init_initial_keys(initial_dcid).unwrap();
    
    // Client decrypts
    println!("\nClient attempting to decrypt");
    match client_crypto.decrypt_packet(&encrypted).await {
        Ok(decrypted) => {
            println!("✓ Decryption successful!");
            println!("  Packet number: {}", decrypted.packet_number);
            println!("  Frames: {}", decrypted.frames.len());
            if let Some(Frame::Crypto { data, .. }) = decrypted.frames.first() {
                println!("  CRYPTO frame size: {} bytes", data.len());
            }
        }
        Err(e) => {
            println!("✗ Decryption failed: {:?}", e);
            panic!("Test failed");
        }
    }
}