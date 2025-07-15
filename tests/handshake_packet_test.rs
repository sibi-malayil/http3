//! Test handshake packet encryption/decryption

use http3::quic::{
    crypto_impl::CryptoManager,
    connection::ConnectionRole,
    packet::ConnectionId,
    frame_types::Frame,
};
use bytes::Bytes;

#[tokio::test]
async fn test_handshake_packet_client_server() {
    // Create client and server crypto managers
    let mut client = CryptoManager::new_client_for_testing("localhost").unwrap();
    let mut server = CryptoManager::new(ConnectionRole::Server).unwrap();
    
    // Set connection IDs
    let client_cid = ConnectionId::from_bytes(Bytes::from(vec![0x11; 8])).unwrap();
    let server_cid = ConnectionId::from_bytes(Bytes::from(vec![0x22; 8])).unwrap();
    
    client.set_connection_ids(client_cid.clone(), server_cid.clone());
    server.set_connection_ids(server_cid.clone(), client_cid.clone());
    
    // Initialize with server's CID as DCID
    let initial_dcid = server_cid.as_bytes();
    client.init_initial_keys(initial_dcid).unwrap();
    server.init_initial_keys(initial_dcid).unwrap();
    
    // Create a simple CRYPTO frame for Initial packet
    let frame = Frame::Crypto {
        offset: 0,
        data: Bytes::from(vec![0x42; 50]),
    };
    
    // Client encrypts Initial packet
    println!("Client encrypting Initial packet...");
    let client_packet = client.encrypt_packet(0, vec![frame.clone()]).await.unwrap();
    println!("Client packet size: {} bytes", client_packet.len());
    
    // Server decrypts Initial packet
    println!("\nServer decrypting Initial packet...");
    match server.decrypt_packet(&client_packet).await {
        Ok(decrypted) => {
            println!("✓ Server decryption successful!");
            println!("  Packet number: {}", decrypted.packet_number);
            println!("  Frames: {}", decrypted.frames.len());
        }
        Err(e) => {
            println!("✗ Server decryption failed: {:?}", e);
            panic!("Server should decrypt client's Initial packet!");
        }
    }
    
    // Now test with handshake keys (if we had them)
    // For now, just verify Initial packets work correctly
}

#[tokio::test]
async fn test_initial_to_handshake_transition() {
    // Test the transition from Initial to Handshake packets
    let mut client = CryptoManager::new_client_for_testing("localhost").unwrap();
    let mut server = CryptoManager::new(ConnectionRole::Server).unwrap();
    
    // Set up connection IDs
    let client_cid = ConnectionId::from_bytes(Bytes::from(vec![0xaa; 8])).unwrap();
    let server_cid = ConnectionId::from_bytes(Bytes::from(vec![0xbb; 8])).unwrap();
    
    client.set_connection_ids(client_cid.clone(), server_cid.clone());
    server.set_connection_ids(server_cid.clone(), client_cid.clone());
    
    // Initialize with server's CID
    let initial_dcid = server_cid.as_bytes();
    client.init_initial_keys(initial_dcid).unwrap();
    server.init_initial_keys(initial_dcid).unwrap();
    
    // Client sends Initial packet
    let client_hello = client.start_handshake().await.unwrap();
    println!("ClientHello size: {} bytes", client_hello.len());
    
    let initial_frame = Frame::Crypto {
        offset: 0,
        data: Bytes::from(client_hello),
    };
    
    let client_initial = client.encrypt_packet(0, vec![initial_frame]).await.unwrap();
    println!("Client Initial packet: {} bytes", client_initial.len());
    
    // Server decrypts Initial packet
    let decrypted = server.decrypt_packet(&client_initial).await.unwrap();
    println!("Server decrypted Initial packet, {} frames", decrypted.frames.len());
    
    // Server processes CRYPTO frame
    if let Some(Frame::Crypto { offset, data }) = decrypted.frames.first() {
        server.process_crypto_frame(*offset, data.clone()).await.unwrap();
    }
    
    // Check if server has handshake data to send
    if let Some(server_hello) = server.get_handshake_data() {
        println!("ServerHello size: {} bytes", server_hello.len());
        
        // Server should still send Initial packet for first response
        let packet_type = server.determine_packet_type();
        println!("Server packet type: {:?}", packet_type);
    }
}