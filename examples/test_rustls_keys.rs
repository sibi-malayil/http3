use rustls::quic::{ClientConnection, ServerConnection, Version, KeyChange};
use rustls::pki_types::{ServerName, CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, ServerConfig};
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create test certificate
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.signing_key.serialize_der();
    
    // Create configs
    let client_config = Arc::new(
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
            .with_no_client_auth()
    );
    
    let server_config = Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert_der)],
                PrivateKeyDer::try_from(key_der)?
            )?
    );
    
    // Create QUIC connections
    let mut client = ClientConnection::new(
        client_config,
        Version::V1,
        ServerName::try_from("localhost")?,
        b"h3".to_vec(),
    )?;
    
    let mut server = ServerConnection::new(
        server_config,
        Version::V1,
        b"h3".to_vec(),
    )?;
    
    // Exchange handshake
    let mut client_buf = Vec::new();
    let mut server_buf = Vec::new();
    
    // Client writes initial
    println!("=== Client Initial ===");
    while let Some(kc) = client.write_hs(&mut client_buf) {
        println!("Client key change: {:?}", match kc {
            KeyChange::Handshake { .. } => "Handshake",
            KeyChange::OneRtt { .. } => "OneRtt",
        });
    }
    println!("Client sent {} bytes", client_buf.len());
    
    // Server reads and responds
    println!("\n=== Server Processing ===");
    server.read_hs(&client_buf)?;
    
    // Get server handshake keys
    let mut server_handshake_keys = None;
    server_buf.clear();
    while let Some(kc) = server.write_hs(&mut server_buf) {
        match kc {
            KeyChange::Handshake { keys } => {
                println!("Server got handshake keys!");
                server_handshake_keys = Some(keys);
            }
            _ => {}
        }
    }
    println!("Server sent {} bytes", server_buf.len());
    
    // Client reads server response
    println!("\n=== Client Processing ===");
    client.read_hs(&server_buf)?;
    
    // Get client handshake keys
    let mut client_handshake_keys = None;
    client_buf.clear();
    while let Some(kc) = client.write_hs(&mut client_buf) {
        match kc {
            KeyChange::Handshake { keys } => {
                println!("Client got handshake keys!");
                client_handshake_keys = Some(keys);
            }
            _ => {}
        }
    }
    println!("Client sent {} more bytes", client_buf.len());
    
    // Compare keys
    if let (Some(client_keys), Some(server_keys)) = (client_handshake_keys, server_handshake_keys) {
        println!("\n=== Key Comparison ===");
        
        // Create a simple test packet
        let packet_number = 1u64;
        let header = b"test_header";
        let plaintext = b"Hello!";
        let mut ciphertext = plaintext.to_vec();
        ciphertext.resize(plaintext.len() + 16, 0); // Space for tag
        
        // Test 1: Client encrypts, server decrypts
        println!("\nTest 1: Client -> Server");
        match client_keys.local.packet.encrypt_in_place(packet_number, header, &mut ciphertext) {
            Ok(tag) => {
                println!("Client encrypted successfully!");
                
                // Server tries to decrypt
                let mut decrypt_buf = ciphertext.clone();
                match server_keys.remote.packet.decrypt_in_place(packet_number, header, &mut decrypt_buf) {
                    Ok(plaintext) => {
                        println!("Server decrypted successfully: {:?}", std::str::from_utf8(plaintext).unwrap());
                    }
                    Err(e) => {
                        println!("Server decryption failed: {:?}", e);
                        
                        // Debug: Check key pointers
                        println!("\nDebug info:");
                        println!("Client local key ptr: {:p}", client_keys.local.packet.as_ref() as *const _);
                        println!("Server remote key ptr: {:p}", server_keys.remote.packet.as_ref() as *const _);
                    }
                }
            }
            Err(e) => println!("Client encryption failed: {:?}", e),
        }
        
        // Test 2: Server encrypts, client decrypts
        println!("\nTest 2: Server -> Client");
        let mut ciphertext2 = plaintext.to_vec();
        ciphertext2.resize(plaintext.len() + 16, 0);
        
        match server_keys.local.packet.encrypt_in_place(packet_number, header, &mut ciphertext2) {
            Ok(tag) => {
                println!("Server encrypted successfully!");
                
                // Client tries to decrypt
                let mut decrypt_buf = ciphertext2.clone();
                match client_keys.remote.packet.decrypt_in_place(packet_number, header, &mut decrypt_buf) {
                    Ok(plaintext) => {
                        println!("Client decrypted successfully: {:?}", std::str::from_utf8(plaintext).unwrap());
                    }
                    Err(e) => {
                        println!("Client decryption failed: {:?}", e);
                        
                        // Debug: Check key pointers
                        println!("\nDebug info:");
                        println!("Server local key ptr: {:p}", server_keys.local.packet.as_ref() as *const _);
                        println!("Client remote key ptr: {:p}", client_keys.remote.packet.as_ref() as *const _);
                    }
                }
            }
            Err(e) => println!("Server encryption failed: {:?}", e),
        }
    }
    
    Ok(())
}

#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}