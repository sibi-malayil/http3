//! QPACK integration tests

use http3::{
    qpack::{
        Config, QpackStreamManager,
        field::{HeaderField, HeaderName, HeaderValue},
    },
};
use bytes::Bytes;

#[tokio::test]
async fn test_qpack_end_to_end() {
    let config = Config {
        max_table_capacity: 4096,
        max_blocked_streams: 16,
        use_huffman: false, // Disable Huffman for easier debugging
    };
    
    let manager = QpackStreamManager::new(config);
    
    // Test 1: Encode and decode simple headers
    let headers = vec![
        HeaderField::new(
            HeaderName::new(":method").unwrap(),
            HeaderValue::new("GET").unwrap(),
        ),
        HeaderField::new(
            HeaderName::new(":path").unwrap(),
            HeaderValue::new("/index.html").unwrap(),
        ),
        HeaderField::new(
            HeaderName::new(":scheme").unwrap(),
            HeaderValue::new("https").unwrap(),
        ),
        HeaderField::new(
            HeaderName::new(":authority").unwrap(),
            HeaderValue::new("example.com").unwrap(),
        ),
    ];
    
    // Encode headers for stream 1
    let encoded = manager.encode_headers(1, headers.clone(), true).await.unwrap();
    assert!(!encoded.is_empty());
    
    // Decode the headers
    let decoded = manager.decode_headers(1, encoded).await.unwrap();
    assert!(decoded.is_some());
    let decoded_headers = decoded.unwrap();
    
    // Verify all headers match
    assert_eq!(decoded_headers.len(), headers.len());
    for (original, decoded) in headers.iter().zip(decoded_headers.iter()) {
        assert_eq!(original.name, decoded.name);
        assert_eq!(original.value, decoded.value);
    }
}

#[tokio::test]
async fn test_qpack_dynamic_table() {
    let config = Config {
        max_table_capacity: 4096,
        max_blocked_streams: 16,
        use_huffman: false,
    };
    
    let manager = QpackStreamManager::new(config);
    
    // Update dynamic table capacity
    manager.set_dynamic_table_capacity(2048).await.unwrap();
    
    // Check for encoder instructions
    let encoder_data = manager.get_encoder_stream_data().await;
    assert!(encoder_data.is_some());
    
    // Test custom headers that should use dynamic table
    let custom_headers = vec![
        HeaderField::new(
            HeaderName::new("x-custom-header").unwrap(),
            HeaderValue::new("custom-value-1").unwrap(),
        ),
        HeaderField::new(
            HeaderName::new("x-another-header").unwrap(),
            HeaderValue::new("another-value").unwrap(),
        ),
    ];
    
    // Encode multiple times to test dynamic table reuse
    for stream_id in 2..5 {
        let encoded = manager.encode_headers(stream_id, custom_headers.clone(), true).await.unwrap();
        let decoded = manager.decode_headers(stream_id, encoded).await.unwrap();
        assert!(decoded.is_some());
    }
}

#[tokio::test]
async fn test_qpack_stream_cancellation() {
    let config = Config::default();
    let manager = QpackStreamManager::new(config);
    
    // Encode headers for a stream
    let headers = vec![
        HeaderField::new(
            HeaderName::new(":status").unwrap(),
            HeaderValue::new("200").unwrap(),
        ),
    ];
    
    let _encoded = manager.encode_headers(10, headers, true).await.unwrap();
    
    // Cancel the stream
    manager.cancel_stream(10).await.unwrap();
    
    // Check for decoder instructions
    let decoder_data = manager.get_decoder_stream_data().await;
    assert!(decoder_data.is_some());
}

#[tokio::test]
async fn test_qpack_blocking_behavior() {
    let config = Config {
        max_table_capacity: 4096,
        max_blocked_streams: 2, // Low limit for testing
        use_huffman: false,
    };
    
    let manager = QpackStreamManager::new(config);
    
    // Test that non-blocking encoding works for static table entries
    let static_headers = vec![
        HeaderField::new(
            HeaderName::new(":method").unwrap(),
            HeaderValue::new("POST").unwrap(),
        ),
    ];
    
    let encoded = manager.encode_headers(20, static_headers, false).await.unwrap();
    assert!(!encoded.is_empty());
}

#[tokio::test]
async fn test_qpack_statistics() {
    let config = Config::default();
    let manager = QpackStreamManager::new(config);
    
    // Get initial stats
    let initial_stats = manager.get_stats().await;
    assert_eq!(initial_stats.headers_encoded, 0);
    assert_eq!(initial_stats.headers_decoded, 0);
    
    // Encode and decode some headers
    let headers = vec![
        HeaderField::new(
            HeaderName::new("content-type").unwrap(),
            HeaderValue::new("application/json").unwrap(),
        ),
    ];
    
    let encoded = manager.encode_headers(30, headers, true).await.unwrap();
    let _decoded = manager.decode_headers(30, encoded).await.unwrap();
    
    // Check updated stats
    let updated_stats = manager.get_stats().await;
    assert_eq!(updated_stats.headers_encoded, 1);
    assert_eq!(updated_stats.headers_decoded, 1);
    assert!(updated_stats.total_encoded_bytes > 0);
}

#[tokio::test]
async fn test_qpack_reference_tracking() {
    let config = Config::default();
    let manager = QpackStreamManager::new(config);
    
    // Get initial reference info
    let ref_info = manager.get_reference_info().await;
    assert_eq!(ref_info.blocked_streams, 0);
    
    // Encode headers with custom values
    let headers = vec![
        HeaderField::new(
            HeaderName::new("x-request-id").unwrap(),
            HeaderValue::new("12345").unwrap(),
        ),
    ];
    
    let _encoded = manager.encode_headers(40, headers, true).await.unwrap();
    
    // Check reference info after encoding
    let ref_info_after = manager.get_reference_info().await;
    // The specifics depend on dynamic table usage
    assert_eq!(ref_info_after.acknowledged_insert_count, 0);
}