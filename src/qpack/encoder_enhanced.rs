//! Enhanced QPACK encoder with dynamic table management
//!
//! This module provides an enhanced encoder that properly manages the dynamic table
//! with insertions, evictions, and synchronization with the decoder.

use crate::{
    error::Result,
    qpack::{
        Config, EncoderInstruction, StringLiteral, StringEncoding,
        field::HeaderField,
        table::{DynamicTable, StaticTable},
        dynamic_table_manager::{DynamicTableManager, InsertionPolicy},
        huffman,
    },
    util::varint::VarInt,
    whathappened::Level,
    protocol_event,
};
use bytes::{Bytes, BytesMut, BufMut};
use std::{
    collections::HashMap,
    sync::Arc,
};
use tokio::sync::RwLock;

/// Enhanced QPACK encoder with dynamic table management
pub struct EnhancedEncoder {
    /// Configuration
    config: Config,
    /// Dynamic table (legacy, kept for compatibility)
    dynamic_table: DynamicTable,
    /// Dynamic table manager
    table_manager: Arc<DynamicTableManager>,
    /// Blocked streams waiting for dynamic table updates
    blocked_streams: Arc<RwLock<HashMap<u64, BlockedStream>>>,
    /// Known received count at decoder
    known_received_count: Arc<RwLock<u64>>,
    /// Maximum insert count sent to decoder
    max_sent_insert_count: Arc<RwLock<u64>>,
}

/// Blocked stream information
#[derive(Debug, Clone)]
struct BlockedStream {
    /// Stream ID
    stream_id: u64,
    /// Required insert count for this stream
    required_insert_count: u64,
    /// Fields that reference dynamic table entries
    referenced_indices: Vec<u64>,
}

impl EnhancedEncoder {
    /// Create a new enhanced encoder
    pub fn new(config: Config, insertion_policy: InsertionPolicy) -> Self {
        let table_manager = Arc::new(DynamicTableManager::new(&config, insertion_policy));
        
        Self {
            dynamic_table: DynamicTable::new(config.max_table_capacity),
            table_manager,
            config,
            blocked_streams: Arc::new(RwLock::new(HashMap::new())),
            known_received_count: Arc::new(RwLock::new(0)),
            max_sent_insert_count: Arc::new(RwLock::new(0)),
        }
    }

    /// Encode header fields with dynamic table management
    pub async fn encode_with_management(
        &self,
        stream_id: u64,
        fields: &[HeaderField],
    ) -> Result<(Bytes, Vec<EncoderInstruction>)> {
        let mut buf = BytesMut::new();
        let mut referenced_indices = Vec::new();
        let mut required_insert_count = 0u64;
        let mut instructions = Vec::new();

        // First pass: determine which fields to insert
        for field in fields {
            // Check if field should be inserted
            if self.table_manager.should_insert(field).await {
                // Try to insert into dynamic table
                if let Some(absolute_index) = self.table_manager.insert_field(field.clone()).await? {
                    instructions.extend(self.table_manager.get_pending_instructions().await);
                    referenced_indices.push(absolute_index);
                    required_insert_count = required_insert_count.max(absolute_index + 1);
                }
            }
        }

        // Update max sent insert count
        {
            let mut max_sent = self.max_sent_insert_count.write().await;
            *max_sent = (*max_sent).max(required_insert_count);
        }

        // Encode header block prefix
        self.encode_header_block_prefix(&mut buf, required_insert_count, 0)?;

        // Second pass: encode fields
        for field in fields {
            self.encode_field_enhanced(&mut buf, field, stream_id, &mut referenced_indices).await?;
        }

        // Check if stream should be blocked
        let known_received = *self.known_received_count.read().await;
        if required_insert_count > known_received {
            // Block the stream
            let mut blocked = self.blocked_streams.write().await;
            blocked.insert(stream_id, BlockedStream {
                stream_id,
                required_insert_count,
                referenced_indices: referenced_indices.clone(),
            });

            protocol_event!(
                Level::Debug,
                "Stream blocked waiting for dynamic table";
                "stream_id" => stream_id,
                "required_count" => required_insert_count,
                "known_count" => known_received
            );
        }

        // Add references for this stream
        for idx in &referenced_indices {
            self.table_manager.add_reference(*idx, stream_id).await?;
        }

        Ok((buf.freeze(), instructions))
    }

    /// Encode header block prefix
    fn encode_header_block_prefix(
        &self,
        buf: &mut BytesMut,
        required_insert_count: u64,
        base: u64,
    ) -> Result<()> {
        // Encode required insert count
        let encoded_insert_count = if required_insert_count == 0 {
            0
        } else {
            (required_insert_count % (2 * self.config.max_table_capacity)) + 1
        };

        // Encode sign bit (S) and delta base (ΔBase)
        let sign = 0u8; // Positive delta base
        let delta_base = required_insert_count.saturating_sub(base);

        // First byte: 0|S|6-bit encoded insert count
        let first_byte = (sign << 6) | (encoded_insert_count as u8 & 0x3F);
        buf.put_u8(first_byte);

        // Encode delta base if non-zero
        if delta_base > 0 {
            VarInt(delta_base).encode(buf)?;
        } else {
            buf.put_u8(0);
        }

        Ok(())
    }

    /// Encode a field with enhanced logic
    async fn encode_field_enhanced(
        &self,
        buf: &mut BytesMut,
        field: &HeaderField,
        stream_id: u64,
        referenced_indices: &mut Vec<u64>,
    ) -> Result<()> {
        // Try static table first
        if let Some(index) = StaticTable::find_field(field) {
            // Indexed field line - static table (1xxxxxxx)
            buf.put_u8(0x80 | (index as u8 & 0x7F));
            if index >= 64 {
                VarInt((index - 64) as u64).encode(buf)?;
            }
            return Ok(());
        }

        // Check dynamic table
        let stats = self.table_manager.get_stats().await;
        let base = stats.encoder_insert_count;

        // Search in dynamic table maintained by manager
        // For now, fallback to literal encoding
        // In production, this would search the manager's table

        // Try name in static table
        if let Some(name_index) = StaticTable::find_name(&field.name) {
            // Literal with name reference - static table
            if field.never_index() {
                // Never indexed (0001xxxx)
                buf.put_u8(0x10 | (name_index as u8 & 0x0F));
                if name_index >= 16 {
                    VarInt((name_index - 16) as u64).encode(buf)?;
                }
            } else {
                // Without never index (01xxxxxx)
                buf.put_u8(0x40 | (name_index as u8 & 0x3F));
                if name_index >= 64 {
                    VarInt((name_index - 64) as u64).encode(buf)?;
                }
            }
            // Encode value
            self.encode_string_literal(buf, field.value.as_bytes())?;
        } else {
            // Literal with literal name
            if field.never_index() {
                // Never indexed (0000xxxx)
                buf.put_u8(0x00);
            } else {
                // Without never index (001xxxxx)
                buf.put_u8(0x20);
            }
            // Encode name and value
            self.encode_string_literal(buf, field.name.as_bytes())?;
            self.encode_string_literal(buf, field.value.as_bytes())?;
        }

        Ok(())
    }

    /// Encode a string literal with optional Huffman encoding
    fn encode_string_literal(&self, buf: &mut BytesMut, data: &[u8]) -> Result<()> {
        if self.config.use_huffman {
            let encoded = huffman::encode_string(data);
            let literal = StringLiteral {
                encoding: StringEncoding::Huffman,
                data: Bytes::from(encoded),
            };
            literal.encode(buf)
        } else {
            let literal = StringLiteral {
                encoding: StringEncoding::Raw,
                data: Bytes::copy_from_slice(data),
            };
            literal.encode(buf)
        }
    }

    /// Process decoder acknowledgment
    pub async fn process_acknowledgment(&self, stream_id: u64, insert_count: u64) -> Result<()> {
        // Update known received count
        {
            let mut known = self.known_received_count.write().await;
            *known = (*known).max(insert_count);
        }

        // Unblock stream if applicable
        {
            let mut blocked = self.blocked_streams.write().await;
            if let Some(stream) = blocked.get(&stream_id) {
                if stream.required_insert_count <= insert_count {
                    blocked.remove(&stream_id);
                    
                    protocol_event!(
                        Level::Debug,
                        "Stream unblocked";
                        "stream_id" => stream_id,
                        "insert_count" => insert_count
                    );
                }
            }
        }

        // Process in table manager
        self.table_manager.process_acknowledgment(stream_id, insert_count).await?;

        Ok(())
    }

    /// Process stream cancellation
    pub async fn process_stream_cancellation(&self, stream_id: u64) -> Result<()> {
        // Remove from blocked streams
        {
            let mut blocked = self.blocked_streams.write().await;
            blocked.remove(&stream_id);
        }

        // Remove references in table manager
        self.table_manager.remove_stream_references(stream_id).await?;

        protocol_event!(
            Level::Debug,
            "Stream cancelled";
            "stream_id" => stream_id
        );

        Ok(())
    }

    /// Get encoder statistics
    pub async fn get_stats(&self) -> EncoderStats {
        let table_stats = self.table_manager.get_stats().await;
        let blocked_count = self.blocked_streams.read().await.len();
        let known_received = *self.known_received_count.read().await;

        EncoderStats {
            dynamic_table_size: table_stats.current_size,
            dynamic_table_capacity: table_stats.max_capacity,
            entry_count: table_stats.entry_count,
            insert_count: table_stats.encoder_insert_count,
            known_received_count: known_received,
            blocked_streams: blocked_count,
        }
    }
}

/// Encoder statistics
#[derive(Debug, Clone)]
pub struct EncoderStats {
    /// Current dynamic table size in bytes
    pub dynamic_table_size: usize,
    /// Dynamic table capacity in bytes
    pub dynamic_table_capacity: usize,
    /// Number of entries in dynamic table
    pub entry_count: usize,
    /// Total insertions made
    pub insert_count: u64,
    /// Known received count at decoder
    pub known_received_count: u64,
    /// Number of blocked streams
    pub blocked_streams: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_enhanced_encoder_basic() {
        let config = Config::default();
        let encoder = EnhancedEncoder::new(config, InsertionPolicy::Always);

        let fields = vec![
            HeaderField::new(
                HeaderName::from("content-type"),
                HeaderValue::from("text/html"),
            ),
            HeaderField::new(
                HeaderName::from("x-custom-header"),
                HeaderValue::from("custom-value"),
            ),
        ];

        let (encoded, instructions) = encoder.encode_with_management(123, &fields).await.unwrap();
        assert!(!encoded.is_empty());
        
        // Should have instruction for custom header
        assert!(!instructions.is_empty());
    }

    #[tokio::test]
    async fn test_stream_blocking() {
        let config = Config::default();
        let encoder = EnhancedEncoder::new(config, InsertionPolicy::Always);

        // Create fields that will be inserted
        let fields = vec![
            HeaderField::new(
                HeaderName::from("x-large-header"),
                HeaderValue::from("a".repeat(100)), // Large value to ensure insertion
            ),
        ];

        let (_, _) = encoder.encode_with_management(456, &fields).await.unwrap();

        // Check if stream is blocked
        let stats = encoder.get_stats().await;
        assert!(stats.blocked_streams > 0);

        // Process acknowledgment
        encoder.process_acknowledgment(456, 1).await.unwrap();

        // Stream should be unblocked
        let stats = encoder.get_stats().await;
        assert_eq!(stats.blocked_streams, 0);
    }

    #[tokio::test]
    async fn test_stream_cancellation() {
        let config = Config::default();
        let encoder = EnhancedEncoder::new(config, InsertionPolicy::Always);

        let fields = vec![
            HeaderField::new(
                HeaderName::from("x-temp-header"),
                HeaderValue::from("temporary"),
            ),
        ];

        let (_, _) = encoder.encode_with_management(789, &fields).await.unwrap();

        // Cancel the stream
        encoder.process_stream_cancellation(789).await.unwrap();

        // Verify references are cleaned up
        let stats = encoder.get_stats().await;
        assert_eq!(stats.blocked_streams, 0);
    }
}