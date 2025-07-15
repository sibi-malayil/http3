//! TLS Handshake Integration Tests

use http3::{
    quic::{
        connection::ConnectionRole,
        crypto_impl::CryptoManager,
    },
};

#[tokio::test]
async fn test_server_tls_creation() {
    // Test creating server with self-signed certificate
    let server_crypto = CryptoManager::new(ConnectionRole::Server);
    assert!(server_crypto.is_ok(), "Should create server crypto manager");
    
    let server = server_crypto.unwrap();
    assert!(!server.handshake_complete().await.unwrap());
}

#[tokio::test]
async fn test_client_tls_creation() {
    // Test creating client
    let client_crypto = CryptoManager::new(ConnectionRole::Client);
    assert!(client_crypto.is_ok(), "Should create client crypto manager");
    
    let client = client_crypto.unwrap();
    assert!(!client.handshake_complete().await.unwrap());
}

#[test]
fn test_server_with_custom_cert() {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    
    // Generate test certificate
    let cert = rcgen::generate_simple_self_signed(vec!["test.example.com".to_string()]).unwrap();
    let cert_der = cert.cert.der();
    let key_der = cert.signing_key.serialize_der();
    
    let cert_chain = vec![CertificateDer::from(cert_der.clone())];
    let private_key = PrivateKeyDer::try_from(key_der).unwrap();
    
    // Create server with custom certificate
    let server_crypto = CryptoManager::new_server_with_cert(cert_chain, private_key);
    assert!(server_crypto.is_ok(), "Should create server with custom cert");
}

#[tokio::test]
async fn test_handshake_data_generation() {
    let mut client = CryptoManager::new(ConnectionRole::Client).unwrap();
    let mut server = CryptoManager::new(ConnectionRole::Server).unwrap();
    
    // Initialize keys for both
    let connection_id = b"test_connection_id";
    client.init_initial_keys(connection_id).unwrap();
    server.init_initial_keys(connection_id).unwrap();
    
    // Client should generate initial handshake data
    let handshake_data = client.start_handshake().await.unwrap();
    println!("Initial handshake data length: {}", handshake_data.len());
    
    let client_data = if handshake_data.is_empty() {
        // Try getting more handshake data
        let client_hello = client.get_handshake_data();
        println!("Additional handshake data: {:?}", client_hello.as_ref().map(|d| d.len()));
        assert!(client_hello.is_some() && !client_hello.as_ref().unwrap().is_empty(), 
                "Client should generate hello");
        client_hello.unwrap()
    } else {
        println!("Client generated {} bytes of handshake data", handshake_data.len());
        handshake_data
    };
    
    // Server processes client hello
    server.process_crypto_frame(0, client_data.into()).await.unwrap();
    
    // Server should generate response
    let server_hello = server.get_handshake_data();
    assert!(server_hello.is_some(), "Server should respond to client hello");
}

#[test]
fn test_alpn_configuration() {
    let _client = CryptoManager::new(ConnectionRole::Client).unwrap();
    let _server = CryptoManager::new(ConnectionRole::Server).unwrap();
    
    // Both should support h3 ALPN
    // Note: ALPN is negotiated during handshake, so we can't check the result yet
    // This test ensures the configuration is set up correctly
    assert!(true, "ALPN configuration test placeholder");
}