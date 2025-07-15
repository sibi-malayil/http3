//! Test Initial packet encryption/decryption

use http3::quic::{
    crypto_impl::CryptoManager,
    connection::ConnectionRole,
    packet::ConnectionId,
    frame_types::Frame,
};
use bytes::Bytes;

#[tokio::test]
async fn test_initial_packet_roundtrip() {
    // Create connection IDs
    let client_cid = ConnectionId::from_bytes(Bytes::from_static(b"client01")).unwrap();
    let server_cid = ConnectionId::from_bytes(Bytes::from_static(b"server01")).unwrap();
    
    // Create crypto managers
    let mut client_crypto = CryptoManager::new(ConnectionRole::Client).unwrap();
    client_crypto.set_connection_ids(client_cid.clone(), server_cid.clone());
    
    let mut server_crypto = CryptoManager::new(ConnectionRole::Server).unwrap();
    server_crypto.set_connection_ids(server_cid.clone(), client_cid.clone());
    
    // Initialize initial keys using server's CID (per RFC 9001)
    let initial_dcid = server_cid.as_bytes();
    client_crypto.init_initial_keys(initial_dcid).unwrap();
    server_crypto.init_initial_keys(initial_dcid).unwrap();
    
    // Test 1: Client -> Server
    println!("Test 1: Client -> Server Initial packet");
    let client_frame = Frame::Crypto {
        offset: 0,
        data: Bytes::from_static(b"ClientHello"),
    };
    let client_packet = client_crypto.encrypt_packet(0, vec![client_frame]).await.unwrap();
    println!("  Encrypted packet size: {} bytes", client_packet.len());
    
    match server_crypto.decrypt_packet(&client_packet).await {
        Ok(decrypted) => {
            println!("  ✓ Decryption successful!");
            println!("    Packet number: {}", decrypted.packet_number);
            println!("    Frames: {}", decrypted.frames.len());
        }
        Err(e) => {
            panic!("  ✗ Decryption failed: {:?}", e);
        }
    }
    
    // Test 2: Server -> Client
    println!("\nTest 2: Server -> Client Initial packet");
    let server_frame = Frame::Crypto {
        offset: 0,
        data: Bytes::from_static(b"ServerHello"),
    };
    let server_packet = server_crypto.encrypt_packet(0, vec![server_frame]).await.unwrap();
    println!("  Encrypted packet size: {} bytes", server_packet.len());
    
    match client_crypto.decrypt_packet(&server_packet).await {
        Ok(decrypted) => {
            println!("  ✓ Decryption successful!");
            println!("    Packet number: {}", decrypted.packet_number);
            println!("    Frames: {}", decrypted.frames.len());
        }
        Err(e) => {
            panic!("  ✗ Decryption failed: {:?}", e);
        }
    }
}