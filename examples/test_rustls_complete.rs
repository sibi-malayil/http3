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
    
    // Track handshake state
    let mut client_handshake_complete = false;
    let mut server_handshake_complete = false;
    
    // Exchange handshake until both sides are done
    let mut round = 0;
    while !client_handshake_complete || !server_handshake_complete {
        round += 1;
        println!("\n=== Round {} ===", round);
        
        let mut client_buf = Vec::new();
        let mut server_buf = Vec::new();
        
        // Client writes
        if !client_handshake_complete {
            println!("Client handshaking: {}", client.is_handshaking());
            while let Some(kc) = client.write_hs(&mut client_buf) {
                println!("Client key change: {:?}", match kc {
                    KeyChange::Handshake { .. } => "Handshake",
                    KeyChange::OneRtt { .. } => "OneRtt",
                });
            }
            if !client_buf.is_empty() {
                println!("Client sent {} bytes", client_buf.len());
            }
            client_handshake_complete = !client.is_handshaking();
        }
        
        // Server processes client data
        if !client_buf.is_empty() {
            server.read_hs(&client_buf)?;
        }
        
        // Server writes response
        if !server_handshake_complete {
            println!("Server handshaking: {}", server.is_handshaking());
            while let Some(kc) = server.write_hs(&mut server_buf) {
                println!("Server key change: {:?}", match kc {
                    KeyChange::Handshake { .. } => "Handshake",
                    KeyChange::OneRtt { .. } => "OneRtt",
                });
            }
            if !server_buf.is_empty() {
                println!("Server sent {} bytes", server_buf.len());
            }
            server_handshake_complete = !server.is_handshaking();
        }
        
        // Client processes server data
        if !server_buf.is_empty() {
            client.read_hs(&server_buf)?;
        }
        
        // Safety check to avoid infinite loop
        if round > 10 {
            println!("Too many rounds, breaking");
            break;
        }
    }
    
    println!("\n=== Handshake Complete ===");
    println!("Client handshake complete: {}", !client.is_handshaking());
    println!("Server handshake complete: {}", !server.is_handshaking());
    
    // Now try to get 1-RTT keys and test encryption
    println!("\n=== Getting Application Keys ===");
    
    // Get any remaining key changes
    let mut client_app_keys = None;
    let mut server_app_keys = None;
    
    let mut buf = Vec::new();
    while let Some(kc) = client.write_hs(&mut buf) {
        match kc {
            KeyChange::OneRtt { keys, .. } => {
                println!("Client got 1-RTT keys!");
                client_app_keys = Some(keys);
            }
            _ => {}
        }
    }
    
    buf.clear();
    while let Some(kc) = server.write_hs(&mut buf) {
        match kc {
            KeyChange::OneRtt { keys, .. } => {
                println!("Server got 1-RTT keys!");
                server_app_keys = Some(keys);
            }
            _ => {}
        }
    }
    
    if let (Some(client_keys), Some(server_keys)) = (client_app_keys, server_app_keys) {
        println!("\n=== Testing Application Data Encryption ===");
        
        // Create a simple test packet
        let packet_number = 1u64;
        let header = b"test_1rtt_header";
        let plaintext = b"Application data!";
        let mut ciphertext = plaintext.to_vec();
        ciphertext.resize(plaintext.len() + 16, 0); // Space for tag
        
        // Test: Client encrypts, server decrypts
        println!("\nClient -> Server:");
        match client_keys.local.packet.encrypt_in_place(packet_number, header, &mut ciphertext) {
            Ok(_) => {
                println!("Client encrypted successfully!");
                
                // Server tries to decrypt
                let mut decrypt_buf = ciphertext.clone();
                match server_keys.remote.packet.decrypt_in_place(packet_number, header, &mut decrypt_buf) {
                    Ok(plaintext) => {
                        println!("Server decrypted successfully: {:?}", std::str::from_utf8(plaintext).unwrap());
                    }
                    Err(e) => {
                        println!("Server decryption failed: {:?}", e);
                    }
                }
            }
            Err(e) => println!("Client encryption failed: {:?}", e),
        }
    } else {
        println!("No application keys available!");
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