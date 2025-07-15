use rustls::quic::{ClientConnection, ServerConnection, Version, KeyChange, Keys};
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
    while let Some(_) = client.write_hs(&mut client_buf) {}
    println!("Client sent {} bytes", client_buf.len());
    
    // Server reads and responds
    println!("\n=== Server Processing ===");
    server.read_hs(&client_buf)?;
    
    // Get server handshake keys
    let mut server_keys: Option<Keys> = None;
    server_buf.clear();
    while let Some(kc) = server.write_hs(&mut server_buf) {
        match kc {
            KeyChange::Handshake { keys } => {
                println!("Server got handshake keys!");
                server_keys = Some(keys);
            }
            _ => {}
        }
    }
    println!("Server sent {} bytes", server_buf.len());
    
    // Client reads server response
    println!("\n=== Client Processing ===");
    client.read_hs(&server_buf)?;
    
    // Get client handshake keys
    let mut client_keys: Option<Keys> = None;
    client_buf.clear();
    while let Some(kc) = client.write_hs(&mut client_buf) {
        match kc {
            KeyChange::Handshake { keys } => {
                println!("Client got handshake keys!");
                client_keys = Some(keys);
            }
            KeyChange::OneRtt { keys, .. } => {
                println!("Client got 1-RTT keys!");
            }
            _ => {}
        }
    }
    println!("Client sent {} more bytes", client_buf.len());
    
    // If client sent more data, server needs to process it
    if !client_buf.is_empty() {
        println!("\n=== Server Final Processing ===");
        server.read_hs(&client_buf)?;
        
        // Check for more server keys
        server_buf.clear();
        while let Some(kc) = server.write_hs(&mut server_buf) {
            match kc {
                KeyChange::OneRtt { keys, .. } => {
                    println!("Server got 1-RTT keys!");
                }
                _ => {}
            }
        }
        if !server_buf.is_empty() {
            println!("Server sent {} more bytes", server_buf.len());
        }
    }
    
    // Test encryption with the keys
    if let (Some(client_keys), Some(server_keys)) = (client_keys, server_keys) {
        println!("\n=== Testing Encryption ===");
        
        // Create a proper QUIC handshake packet header
        let packet_number = 1u64;
        
        // Build a minimal handshake packet header
        // Format: [flags] [version] [DCID len] [DCID] [SCID len] [SCID] [length] [packet number]
        let mut header = Vec::new();
        header.push(0xE3); // Long header, Handshake type (0x2 << 4), 4-byte packet number
        header.extend_from_slice(&0x00000001u32.to_be_bytes()); // Version 1
        header.push(8); // DCID length
        header.extend_from_slice(b"\x01\x02\x03\x04\x05\x06\x07\x08"); // DCID
        header.push(8); // SCID length  
        header.extend_from_slice(b"\x11\x12\x13\x14\x15\x16\x17\x18"); // SCID
        header.push(0x40 | 28); // Length as varint (28 = 12 payload + 16 tag)
        header.extend_from_slice(&(packet_number as u32).to_be_bytes()); // 4-byte packet number
        
        let plaintext = b"Hello, QUIC!";
        
        // Client encrypts
        let mut ciphertext = plaintext.to_vec();
        ciphertext.resize(plaintext.len() + 16, 0); // Space for tag
        
        println!("Client encrypting with local key...");
        match client_keys.local.packet.encrypt_in_place(packet_number, &header, &mut ciphertext) {
            Ok(_tag) => println!("Client encryption successful! {} bytes", ciphertext.len()),
            Err(e) => println!("Client encryption failed: {:?}", e),
        }
        
        // Server tries to decrypt
        println!("\nServer decrypting with remote key...");
        let mut decrypted = ciphertext.clone();
        match server_keys.remote.packet.decrypt_in_place(packet_number, &header, &mut decrypted) {
            Ok(plaintext) => {
                println!("Server decryption successful!");
                println!("Decrypted: {:?}", String::from_utf8_lossy(plaintext));
            }
            Err(e) => {
                println!("Server decryption failed: {:?}", e);
                
                // Try with local key as debug
                println!("\nTrying with server local key...");
                let mut decrypted2 = ciphertext.clone();
                match server_keys.local.packet.decrypt_in_place(packet_number, &header, &mut decrypted2) {
                    Ok(plaintext) => println!("Works with local: {:?}", String::from_utf8_lossy(plaintext)),
                    Err(e) => println!("Also fails with local: {:?}", e),
                }
            }
        }
        
        // Try the other direction
        println!("\n=== Testing Other Direction ===");
        
        // Server encrypts
        let mut ciphertext2 = plaintext.to_vec();
        ciphertext2.resize(plaintext.len() + 16, 0);
        
        println!("Server encrypting with local key...");
        match server_keys.local.packet.encrypt_in_place(packet_number, &header, &mut ciphertext2) {
            Ok(_tag) => println!("Server encryption successful! {} bytes", ciphertext2.len()),
            Err(e) => println!("Server encryption failed: {:?}", e),
        }
        
        // Client tries to decrypt
        println!("\nClient decrypting with remote key...");
        let mut decrypted3 = ciphertext2.clone();
        match client_keys.remote.packet.decrypt_in_place(packet_number, &header, &mut decrypted3) {
            Ok(plaintext) => {
                println!("Client decryption successful!");
                println!("Decrypted: {:?}", String::from_utf8_lossy(plaintext));
            }
            Err(e) => println!("Client decryption failed: {:?}", e),
        }
    } else {
        println!("\nNo keys available for testing!");
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