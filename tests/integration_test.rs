//! Comprehensive Integration Tests for HTTP/3 Implementation

use http3::{
    quic::{
        connection::{Connection, ConnectionRole, ConnectionState},
        crypto_impl::{CryptoManager},
        frame_types::Frame,
    },
    error::{Error, Result},
};
use bytes::Bytes;

/// Test the complete QUIC cryptographic pipeline
#[tokio::test]
async fn test_quic_crypto_pipeline() {
    let mut crypto = CryptoManager::new(ConnectionRole::Client).unwrap();
    
    // Initialize initial keys
    let connection_id = b"test_connection_id_12345";
    crypto.init_initial_keys(connection_id).unwrap();
    
    // Create test frames
    let test_frames = vec![
        Frame::Ping,
        Frame::Crypto {
            offset: 0,
            data: Bytes::from_static(b"TLS handshake data"),
        },
        Frame::Padding,
    ];
    
    // Test encryption
    let encrypted_packet = crypto.encrypt_packet(1, test_frames.clone()).await.unwrap();
    assert!(!encrypted_packet.is_empty());
    assert!(encrypted_packet.len() >= 1200); // Minimum Initial packet size
    
    // Test decryption
    let decrypted = crypto.decrypt_packet(&encrypted_packet).await.unwrap();
    assert!(decrypted.packet_number > 0);
    assert_eq!(decrypted.frames.len(), 3);
    
    println!("✅ QUIC crypto pipeline test passed");
}

/// Test frame encoding and decoding round-trip
#[test]
fn test_frame_encoding_roundtrip() {
    use bytes::BytesMut;
    
    let original_frames = vec![
        Frame::Ping,
        Frame::ResetStream {
            stream_id: 4.into(),
            application_error_code: 0x123,
            final_size: 1024,
        },
        Frame::MaxData {
            maximum_data: 0x1000000,
        },
        Frame::Crypto {
            offset: 42,
            data: Bytes::from_static(b"test crypto data"),
        },
    ];
    
    for original_frame in original_frames {
        // Encode frame
        let mut buf = BytesMut::new();
        original_frame.encode(&mut buf).unwrap();
        
        // Decode frame
        let mut decode_buf = buf.freeze();
        let decoded_frame = Frame::decode(&mut decode_buf).unwrap();
        
        // Verify round-trip
        assert_eq!(original_frame, decoded_frame);
    }
    
    println!("✅ Frame encoding round-trip test passed");
}