//! Integration tests for QPACK dynamic table management

use http3::qpack::{
    Config, EncoderInstruction,
    field::{HeaderField, HeaderName, HeaderValue},
    encoder_enhanced::{EnhancedEncoder, EncoderStats},
    dynamic_table_manager::{DynamicTableManager, InsertionPolicy},
    instruction_processor::{EncoderInstructionProcessor, DecoderInstructionProcessor},
};
use std::sync::Arc;
use bytes::{Bytes, BytesMut};
use std::sync::atomic::{AtomicU64, Ordering};

#[tokio::test]
async fn test_dynamic_table_basic_insertion() {
    let config = Config {
        max_table_capacity: 1024,
        max_blocked_streams: 10,
        use_huffman: true,
    };
    
    let encoder = EnhancedEncoder::new(config.clone(), InsertionPolicy::Always);
    
    // Create headers that should be inserted
    let fields = vec![
        HeaderField::new(
            HeaderName::from("x-custom-header"),
            HeaderValue::from("custom-value"),
        ),
        HeaderField::new(
            HeaderName::from("x-another-header"),
            HeaderValue::from("another-value"),
        ),
    ];
    
    // Encode headers for stream 1
    let (encoded1, instructions1) = encoder.encode_with_management(1, &fields).await.unwrap();
    assert!(!encoded1.is_empty());
    assert_eq!(instructions1.len(), 2); // Two insertions
    
    // Verify instructions are correct
    for (i, instruction) in instructions1.iter().enumerate() {
        match instruction {
            EncoderInstruction::InsertWithLiteralName { name, value } => {
                assert!(name.as_str().starts_with("x-"));
                assert!(value.as_str().ends_with("-value"));
            }
            _ => panic!("Expected InsertWithLiteralName instruction"),
        }
    }
    
    // Check stats
    let stats = encoder.get_stats().await;
    assert_eq!(stats.entry_count, 2);
    assert!(stats.dynamic_table_size > 0);
    assert_eq!(stats.insert_count, 2);
}

#[tokio::test]
async fn test_dynamic_table_eviction() {
    let config = Config {
        max_table_capacity: 200, // Small table to force eviction
        max_blocked_streams: 10,
        use_huffman: false, // Disable huffman for predictable sizes
    };
    
    let encoder = EnhancedEncoder::new(config.clone(), InsertionPolicy::Always);
    
    // Fill the table with entries
    let mut all_fields = Vec::new();
    for i in 0..5 {
        all_fields.push(HeaderField::new(
            HeaderName::from(format!("header-{}", i)),
            HeaderValue::from(format!("value-{}", i)),
        ));
    }
    
    // Encode to fill the table
    let (_, _) = encoder.encode_with_management(1, &all_fields).await.unwrap();
    
    let stats = encoder.get_stats().await;
    let initial_count = stats.entry_count;
    
    // Add a large entry that requires eviction
    let large_field = HeaderField::new(
        HeaderName::from("x-large-header"),
        HeaderValue::from("x".repeat(50)), // Large value
    );
    
    let (_, _) = encoder.encode_with_management(2, &[large_field]).await.unwrap();
    
    // Check that eviction occurred
    let stats = encoder.get_stats().await;
    assert!(stats.entry_count <= initial_count); // Some entries were evicted
    assert!(stats.dynamic_table_size <= config.max_table_capacity as usize);
}

#[tokio::test]
async fn test_frequency_based_insertion() {
    let config = Config {
        max_table_capacity: 1024,
        max_blocked_streams: 10,
        use_huffman: true,
    };
    
    let encoder = EnhancedEncoder::new(
        config.clone(), 
        InsertionPolicy::FrequencyBased { min_occurrences: 3 }
    );
    
    let field = HeaderField::new(
        HeaderName::from("x-frequent"),
        HeaderValue::from("appears-often"),
    );
    
    // First two occurrences - should not insert
    for stream_id in 1..=2 {
        let (_, instructions) = encoder.encode_with_management(stream_id, &[field.clone()]).await.unwrap();
        assert!(instructions.is_empty()); // No insertions
    }
    
    // Third occurrence - should insert
    let (_, instructions) = encoder.encode_with_management(3, &[field]).await.unwrap();
    assert_eq!(instructions.len(), 1); // One insertion
    
    let stats = encoder.get_stats().await;
    assert_eq!(stats.entry_count, 1);
}

#[tokio::test]
async fn test_stream_blocking_and_acknowledgment() {
    let config = Config {
        max_table_capacity: 1024,
        max_blocked_streams: 10,
        use_huffman: true,
    };
    
    let encoder = EnhancedEncoder::new(config.clone(), InsertionPolicy::Always);
    
    // Create a field that will be inserted
    let field = HeaderField::new(
        HeaderName::from("x-blocking-test"),
        HeaderValue::from("test-value"),
    );
    
    // Encode for stream 1
    let (_, instructions) = encoder.encode_with_management(1, &[field.clone()]).await.unwrap();
    assert!(!instructions.is_empty());
    
    // Stream should be blocked until acknowledgment
    let stats = encoder.get_stats().await;
    assert_eq!(stats.blocked_streams, 1);
    
    // Encode same field for stream 2 (should reference the dynamic table)
    let (_, instructions2) = encoder.encode_with_management(2, &[field]).await.unwrap();
    assert!(instructions2.is_empty()); // No new insertions
    
    // Both streams should be blocked
    let stats = encoder.get_stats().await;
    assert_eq!(stats.blocked_streams, 2);
    
    // Process acknowledgment for stream 1
    encoder.process_acknowledgment(1, 1).await.unwrap();
    
    // Stream 1 should be unblocked
    let stats = encoder.get_stats().await;
    assert_eq!(stats.blocked_streams, 1); // Only stream 2 blocked
    
    // Process acknowledgment for stream 2
    encoder.process_acknowledgment(2, 1).await.unwrap();
    
    // All streams should be unblocked
    let stats = encoder.get_stats().await;
    assert_eq!(stats.blocked_streams, 0);
}

#[tokio::test]
async fn test_stream_cancellation() {
    let config = Config {
        max_table_capacity: 1024,
        max_blocked_streams: 10,
        use_huffman: true,
    };
    
    let encoder = EnhancedEncoder::new(config.clone(), InsertionPolicy::Always);
    
    // Create fields for multiple streams
    let field = HeaderField::new(
        HeaderName::from("x-cancel-test"),
        HeaderValue::from("will-be-cancelled"),
    );
    
    // Encode for streams 1, 2, and 3
    for stream_id in 1..=3 {
        let (_, _) = encoder.encode_with_management(stream_id, &[field.clone()]).await.unwrap();
    }
    
    // All streams should be blocked
    let stats = encoder.get_stats().await;
    assert_eq!(stats.blocked_streams, 3);
    
    // Cancel stream 2
    encoder.process_stream_cancellation(2).await.unwrap();
    
    // Stream 2 should no longer be blocked
    let stats = encoder.get_stats().await;
    assert_eq!(stats.blocked_streams, 2);
    
    // Process acknowledgments for remaining streams
    encoder.process_acknowledgment(1, 1).await.unwrap();
    encoder.process_acknowledgment(3, 1).await.unwrap();
    
    // All streams should be cleared
    let stats = encoder.get_stats().await;
    assert_eq!(stats.blocked_streams, 0);
}

#[tokio::test]
async fn test_adaptive_insertion_policy() {
    let config = Config {
        max_table_capacity: 1024,
        max_blocked_streams: 10,
        use_huffman: true,
    };
    
    let encoder = EnhancedEncoder::new(config.clone(), InsertionPolicy::Adaptive);
    
    // Small field - should not be inserted (too small)
    let small_field = HeaderField::new(
        HeaderName::from("x"),
        HeaderValue::from("y"),
    );
    
    let (_, instructions) = encoder.encode_with_management(1, &[small_field]).await.unwrap();
    assert!(instructions.is_empty());
    
    // Medium field - needs multiple occurrences
    let medium_field = HeaderField::new(
        HeaderName::from("x-medium-header"),
        HeaderValue::from("medium-value-here"),
    );
    
    // First occurrence - should not insert
    let (_, instructions) = encoder.encode_with_management(2, &[medium_field.clone()]).await.unwrap();
    assert!(instructions.is_empty());
    
    // Second occurrence - should insert
    let (_, instructions) = encoder.encode_with_management(3, &[medium_field]).await.unwrap();
    assert_eq!(instructions.len(), 1);
    
    // Large field - should insert on first occurrence
    let large_field = HeaderField::new(
        HeaderName::from("x-large-header-name-that-is-worth-compressing"),
        HeaderValue::from("large-value-that-benefits-from-dynamic-table-compression"),
    );
    
    let (_, instructions) = encoder.encode_with_management(4, &[large_field]).await.unwrap();
    assert_eq!(instructions.len(), 1);
    
    let stats = encoder.get_stats().await;
    assert_eq!(stats.entry_count, 2); // Medium and large fields
}

#[tokio::test]
async fn test_never_index_fields() {
    let config = Config::default();
    let encoder = EnhancedEncoder::new(config.clone(), InsertionPolicy::Always);
    
    // Create a sensitive field that should never be indexed
    let sensitive_field = HeaderField::new_never_index(
        HeaderName::from("authorization"),
        HeaderValue::from("Bearer secret-token-12345"),
    );
    
    // Try to encode - should not insert
    let (encoded, instructions) = encoder.encode_with_management(1, &[sensitive_field]).await.unwrap();
    assert!(!encoded.is_empty());
    assert!(instructions.is_empty()); // No insertions for never-index fields
    
    let stats = encoder.get_stats().await;
    assert_eq!(stats.entry_count, 0);
}

#[tokio::test]
async fn test_reference_tracking() {
    let config = Config {
        max_table_capacity: 512,
        max_blocked_streams: 10,
        use_huffman: true,
    };
    
    let manager = DynamicTableManager::new(&config, InsertionPolicy::Always);
    
    // Insert a field
    let field = HeaderField::new(
        HeaderName::from("x-ref-test"),
        HeaderValue::from("referenced-value"),
    );
    
    let index = manager.insert_field(field.clone()).await.unwrap().unwrap();
    
    // Add references from multiple streams
    manager.add_reference(index, 1).await.unwrap();
    manager.add_reference(index, 2).await.unwrap();
    
    // Try to evict - should not evict referenced entry
    manager.evict_for_space(config.max_table_capacity as usize).await.unwrap();
    
    let stats = manager.get_stats().await;
    assert_eq!(stats.entry_count, 1); // Entry still there
    
    // Remove one reference
    manager.remove_reference(index, 1).await.unwrap();
    
    // Entry should still be there (still referenced by stream 2)
    let stats = manager.get_stats().await;
    assert_eq!(stats.entry_count, 1);
    
    // Remove last reference
    manager.remove_reference(index, 2).await.unwrap();
    
    // Now entry can be evicted
    manager.evict_for_space(config.max_table_capacity as usize).await.unwrap();
}

#[tokio::test]
async fn test_concurrent_encoding() {
    let config = Config {
        max_table_capacity: 2048,
        max_blocked_streams: 100,
        use_huffman: true,
    };
    
    let encoder = Arc::new(EnhancedEncoder::new(config, InsertionPolicy::Always));
    
    // Spawn multiple concurrent encoding tasks
    let mut handles = Vec::new();
    
    for stream_id in 1..=10 {
        let encoder_clone = Arc::clone(&encoder);
        let handle = tokio::spawn(async move {
            let fields = vec![
                HeaderField::new(
                    HeaderName::from(format!("x-stream-{}", stream_id)),
                    HeaderValue::from(format!("value-{}", stream_id)),
                ),
            ];
            
            encoder_clone.encode_with_management(stream_id, &fields).await
        });
        handles.push(handle);
    }
    
    // Wait for all tasks to complete
    let mut total_instructions = 0;
    for handle in handles {
        let (_, instructions) = handle.await.unwrap().unwrap();
        total_instructions += instructions.len();
    }
    
    // Verify all insertions were made
    assert_eq!(total_instructions, 10);
    
    let stats = encoder.get_stats().await;
    assert_eq!(stats.entry_count, 10);
    assert_eq!(stats.blocked_streams, 10); // All streams blocked
}

#[tokio::test]
async fn test_instruction_processor_integration() {
    use http3::qpack::table::DynamicTable;
    use tokio::sync::RwLock;

    // Create a dynamic table for the processor
    let table = Arc::new(RwLock::new(DynamicTable::new(1024)));
    let processor = EncoderInstructionProcessor::new(Arc::clone(&table), 1024);

    // Create instruction data for "InsertWithNameReference" using static table
    let mut instruction_data = BytesMut::new();
    
    // Insert with name reference to ":method" (static table index 15) with value "POST"
    instruction_data.extend_from_slice(&[0x8F]); // 10001111 - static table reference, index 15
    instruction_data.extend_from_slice(&[0x04]); // String length 4, no huffman
    instruction_data.extend_from_slice(b"POST"); // Value

    let mut data = instruction_data.freeze();
    let responses = processor.process_stream(&mut data).await.unwrap();

    // Should get one insert count increment response
    assert_eq!(responses.len(), 1);
    match &responses[0] {
        http3::qpack::DecoderInstruction::InsertCountIncrement { increment } => {
            assert_eq!(*increment, 1);
        }
        _ => panic!("Expected InsertCountIncrement"),
    }

    // Verify the entry was inserted into the dynamic table
    let table_guard = table.read().await;
    assert_eq!(table_guard.len(), 1);
    let entry = table_guard.get(0).unwrap();
    assert_eq!(entry.name.as_str(), ":method");
    assert_eq!(entry.value.as_str().unwrap(), "POST");
}

#[tokio::test]
async fn test_decoder_instruction_processor() {

    let section_ack_counter = Arc::new(AtomicU64::new(0));
    let stream_cancel_counter = Arc::new(AtomicU64::new(0));
    let insert_count_total = Arc::new(AtomicU64::new(0));

    let section_ack_counter_clone = Arc::clone(&section_ack_counter);
    let stream_cancel_counter_clone = Arc::clone(&stream_cancel_counter);
    let insert_count_total_clone = Arc::clone(&insert_count_total);

    let processor = DecoderInstructionProcessor::new(
        move |stream_id| {
            assert_eq!(stream_id, 42);
            section_ack_counter_clone.fetch_add(1, Ordering::SeqCst);
        },
        move |stream_id| {
            assert_eq!(stream_id, 24);
            stream_cancel_counter_clone.fetch_add(1, Ordering::SeqCst);
        },
        move |increment| {
            insert_count_total_clone.fetch_add(increment, Ordering::SeqCst);
        },
    );

    // Create mixed instruction data
    let mut instruction_data = BytesMut::new();
    
    // Section acknowledgment for stream 42
    instruction_data.extend_from_slice(&[0x80 | 42]); // 10101010
    
    // Stream cancellation for stream 24
    instruction_data.extend_from_slice(&[0x40 | 24]); // 01011000
    
    // Insert count increment of 5
    instruction_data.extend_from_slice(&[0x05]); // 00000101

    let mut data = instruction_data.freeze();
    processor.process_stream(&mut data).await.unwrap();

    // Verify all callbacks were called correctly
    assert_eq!(section_ack_counter.load(Ordering::SeqCst), 1);
    assert_eq!(stream_cancel_counter.load(Ordering::SeqCst), 1);
    assert_eq!(insert_count_total.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn test_end_to_end_dynamic_table_workflow() {
    let config = Config {
        max_table_capacity: 1024,
        max_blocked_streams: 10,
        use_huffman: false, // Disable for predictable testing
    };

    // Create encoder and dynamic table manager
    let encoder = EnhancedEncoder::new(config.clone(), InsertionPolicy::Always);
    let manager = DynamicTableManager::new(&config, InsertionPolicy::Always);

    // Step 1: Encode headers that should be inserted into dynamic table
    let fields = vec![
        HeaderField::new(
            HeaderName::from("x-custom-api-key"),
            HeaderValue::from("secret-key-12345"),
        ),
        HeaderField::new(
            HeaderName::from("x-request-id"),
            HeaderValue::from("req-67890"),
        ),
    ];

    let (encoded_data, instructions) = encoder.encode_with_management(1, &fields).await.unwrap();
    assert!(!encoded_data.is_empty());
    assert_eq!(instructions.len(), 2); // Two custom headers should be inserted

    // Step 2: Process the generated instructions
    for field in &fields {
        let insert_result = manager.insert_field(field.clone()).await.unwrap();
        assert!(insert_result.is_some());
    }

    // Step 3: Verify table state
    let stats = manager.get_stats().await;
    assert_eq!(stats.entry_count, 2);
    assert!(stats.current_size > 0);
    assert!(stats.current_size <= stats.max_capacity);

    // Step 4: Test reference tracking
    let first_index = 1; // First inserted entry
    manager.add_reference(first_index, 1).await.unwrap(); // Stream 1 references it

    // Step 5: Encode same headers again (should reference dynamic table)
    let (encoded_data2, instructions2) = encoder.encode_with_management(2, &fields).await.unwrap();
    assert!(!encoded_data2.is_empty());
    assert!(instructions2.is_empty()); // No new insertions needed

    // Step 6: Process acknowledgment
    manager.process_acknowledgment(1, 2).await.unwrap();

    // Verify final state
    let final_stats = manager.get_stats().await;
    assert_eq!(final_stats.entry_count, 2);
    assert_eq!(final_stats.known_decoder_count, 2);
}