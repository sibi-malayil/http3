use http3::{
    quic::{
        crypto_impl::CryptoManager,
        packet::ConnectionId,
    },
    error::Result,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    println!("Testing key consistency between client and server...");

    // Create connection IDs
    let server_cid = ConnectionId::random(8)?;
    let client_cid = ConnectionId::random(8)?;
    
    // Create server crypto manager
    let mut server_crypto = CryptoManager::new_server_self_signed()?;
    server_crypto.set_connection_ids(server_cid.clone(), client_cid.clone());
    server_crypto.init_initial_keys(server_cid.as_bytes())?;
    
    // Create client crypto manager  
    let mut client_crypto = CryptoManager::new_client_for_testing("localhost")?;
    client_crypto.set_connection_ids(client_cid.clone(), server_cid.clone());
    client_crypto.init_initial_keys(server_cid.as_bytes())?;
    
    // Simulate handshake data exchange
    println!("\n1. Client generates initial handshake data...");
    let client_hello = client_crypto.start_handshake().await?;
    println!("Client hello: {} bytes", client_hello.len());
    
    println!("\n2. Server processes client hello...");
    server_crypto.process_crypto_frame(0, client_hello.into()).await?;
    
    println!("\n3. Server generates response...");
    let server_response = server_crypto.get_handshake_data()
        .ok_or_else(|| http3::error::Error::TlsError("No server response".to_string()))?;
    println!("Server response: {} bytes", server_response.len());
    
    println!("\n4. Client processes server response...");
    client_crypto.process_crypto_frame(0, server_response.into()).await?;
    
    println!("\n5. Client generates final handshake message...");
    let client_finish = client_crypto.get_handshake_data();
    if let Some(data) = client_finish {
        println!("Client finish: {} bytes", data.len());
        
        println!("\n6. Server processes client finish...");
        server_crypto.process_crypto_frame(0, data.into()).await?;
    }
    
    // Check if handshake is complete
    println!("\n=== Handshake Status ===");
    let client_complete = client_crypto.handshake_complete().await?;
    let server_complete = server_crypto.handshake_complete().await?;
    
    println!("Client handshake complete: {}", client_complete);
    println!("Server handshake complete: {}", server_complete);
    
    // Test encryption/decryption with handshake keys
    if client_complete && server_complete {
        println!("\n=== Testing Handshake Key Consistency ===");
        
        // Client encrypts a test packet
        let test_frames = vec![http3::quic::frame_types::Frame::Ping];
        let encrypted = client_crypto.encrypt_packet(0, test_frames.clone()).await?;
        println!("Client encrypted packet: {} bytes", encrypted.len());
        
        // Server decrypts the packet
        match server_crypto.decrypt_packet(&encrypted).await {
            Ok(decrypted) => {
                println!("Server successfully decrypted packet!");
                println!("Packet number: {}", decrypted.packet_number);
                println!("Frames: {:?}", decrypted.frames);
            }
            Err(e) => {
                println!("Server failed to decrypt packet: {}", e);
            }
        }
    } else {
        println!("\nHandshake not complete, cannot test keys");
    }
    
    Ok(())
}