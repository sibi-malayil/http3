//! QPACK instruction processing for encoder and decoder streams
//!
//! This module handles the processing of QPACK instructions sent on the
//! encoder and decoder streams according to RFC 9204.

use crate::{
    error::{Error, Result, QpackErrorCode},
    error_context::ErrorConversion,
    qpack::{
        field::{HeaderField, HeaderName, HeaderValue},
        table::{DynamicTable, StaticTable},
        StringLiteral,
        EncoderInstruction,
        DecoderInstruction,
    },
    util::varint::VarInt,
    whathappened::Level,
    protocol_event,
};
use bytes::{Bytes, Buf};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Encoder stream instruction processor
pub struct EncoderInstructionProcessor {
    /// Dynamic table
    dynamic_table: Arc<RwLock<DynamicTable>>,
    /// Maximum table capacity
    max_capacity: u64,
}

impl EncoderInstructionProcessor {
    /// Create a new encoder instruction processor
    pub fn new(dynamic_table: Arc<RwLock<DynamicTable>>, max_capacity: u64) -> Self {
        Self {
            dynamic_table,
            max_capacity,
        }
    }

    /// Process encoder stream data
    pub async fn process_stream(&self, data: &mut Bytes) -> Result<Vec<DecoderInstruction>> {
        let mut instructions = Vec::new();
        
        while !data.is_empty() {
            let instruction = self.decode_instruction(data)?;
            if let Some(response) = self.process_instruction(instruction).await? {
                instructions.push(response);
            }
        }
        
        Ok(instructions)
    }

    /// Decode an encoder instruction from the stream
    fn decode_instruction(&self, buf: &mut Bytes) -> Result<EncoderInstruction> {
        if buf.is_empty() {
            return Err(Error::QpackIncompleteData);
        }

        let first_byte = buf[0];
        
        if (first_byte & 0x80) != 0 {
            // Insert With Name Reference (1xxxxxxx)
            let s_bit = (first_byte & 0x40) != 0; // Static table bit
            let name_index = VarInt::decode_with_prefix(buf, 6)?.0;
            
            let value = StringLiteral::decode(buf)?;
            
            Ok(EncoderInstruction::InsertWithNameReference {
                table: s_bit,
                name_index,
                value: HeaderValue::new(value.data)?,
            })
        } else if (first_byte & 0x40) != 0 {
            // Insert With Literal Name (01xxxxxx)
            buf.advance(1); // Skip the prefix byte
            
            let name = StringLiteral::decode(buf)?;
            let value = StringLiteral::decode(buf)?;
            
            Ok(EncoderInstruction::InsertWithLiteralName {
                name: HeaderName::new(name.data)?,
                value: HeaderValue::new(value.data)?,
            })
        } else if (first_byte & 0x20) != 0 {
            // Set Dynamic Table Capacity (001xxxxx)
            let capacity = VarInt::decode_with_prefix(buf, 5)?.0;
            Ok(EncoderInstruction::SetDynamicTableCapacity { capacity })
        } else {
            // Duplicate (000xxxxx)
            let index = VarInt::decode_with_prefix(buf, 5)?.0;
            Ok(EncoderInstruction::Duplicate { index })
        }
    }

    /// Process an encoder instruction
    async fn process_instruction(&self, instruction: EncoderInstruction) -> Result<Option<DecoderInstruction>> {
        use EncoderInstruction::*;
        
        match instruction {
            InsertWithNameReference { table, name_index, value } => {
                let mut dynamic_table = self.dynamic_table.write().await;
                
                let name = if table {
                    // Static table reference
                    StaticTable::get_name(name_index)
                        .ok_or_else(|| Error::QpackInvalidIndex)?
                } else {
                    // Dynamic table reference
                    dynamic_table.get(name_index)
                        .ok_or_else(|| Error::QpackInvalidIndex)?
                        .name.clone()
                };
                
                let field = HeaderField::new(name, value);
                let insert_count = dynamic_table.insert(field)?;
                
                protocol_event!(
                    Level::Debug,
                    "Processed InsertWithNameReference";
                    "table" => if table { "static" } else { "dynamic" },
                    "name_index" => name_index,
                    "insert_count" => insert_count
                );
                
                // Return insert count increment to notify decoder
                Ok(Some(DecoderInstruction::InsertCountIncrement {
                    increment: 1,
                }))
            }
            
            InsertWithLiteralName { name, value } => {
                let mut dynamic_table = self.dynamic_table.write().await;
                
                let field = HeaderField::new(name, value);
                let insert_count = dynamic_table.insert(field)?;
                
                protocol_event!(
                    Level::Debug,
                    "Processed InsertWithLiteralName";
                    "insert_count" => insert_count
                );
                
                // Return insert count increment
                Ok(Some(DecoderInstruction::InsertCountIncrement {
                    increment: 1,
                }))
            }
            
            SetDynamicTableCapacity { capacity } => {
                if capacity > self.max_capacity {
                    return Err("Dynamic table capacity exceeds maximum"
                        .to_qpack_error(QpackErrorCode::EncoderStreamError));
                }
                
                let mut dynamic_table = self.dynamic_table.write().await;
                dynamic_table.set_capacity(capacity)?;
                
                protocol_event!(
                    Level::Debug,
                    "Set dynamic table capacity";
                    "capacity" => capacity
                );
                
                Ok(None)
            }
            
            Duplicate { index } => {
                let mut dynamic_table = self.dynamic_table.write().await;
                let insert_count = dynamic_table.duplicate(index)?;
                
                protocol_event!(
                    Level::Debug,
                    "Duplicated entry";
                    "index" => index,
                    "insert_count" => insert_count
                );
                
                // Return insert count increment
                Ok(Some(DecoderInstruction::InsertCountIncrement {
                    increment: 1,
                }))
            }
        }
    }
}

/// Decoder stream instruction processor
pub struct DecoderInstructionProcessor {
    /// Callback for section acknowledgments
    section_ack_callback: Arc<dyn Fn(u64) + Send + Sync>,
    /// Callback for stream cancellations
    stream_cancel_callback: Arc<dyn Fn(u64) + Send + Sync>,
    /// Callback for insert count increments
    insert_count_callback: Arc<dyn Fn(u64) + Send + Sync>,
}

impl DecoderInstructionProcessor {
    /// Create a new decoder instruction processor
    pub fn new<F1, F2, F3>(
        section_ack: F1,
        stream_cancel: F2,
        insert_count: F3,
    ) -> Self 
    where
        F1: Fn(u64) + Send + Sync + 'static,
        F2: Fn(u64) + Send + Sync + 'static,
        F3: Fn(u64) + Send + Sync + 'static,
    {
        Self {
            section_ack_callback: Arc::new(section_ack),
            stream_cancel_callback: Arc::new(stream_cancel),
            insert_count_callback: Arc::new(insert_count),
        }
    }

    /// Process decoder stream data
    pub async fn process_stream(&self, data: &mut Bytes) -> Result<()> {
        while !data.is_empty() {
            let instruction = self.decode_instruction(data)?;
            self.process_instruction(instruction)?;
        }
        
        Ok(())
    }

    /// Decode a decoder instruction from the stream
    fn decode_instruction(&self, buf: &mut Bytes) -> Result<DecoderInstruction> {
        if buf.is_empty() {
            return Err(Error::QpackIncompleteData);
        }

        let first_byte = buf[0];
        
        if (first_byte & 0x80) != 0 {
            // Section Acknowledgment (1xxxxxxx)
            let stream_id = VarInt::decode_with_prefix(buf, 7)?.0;
            Ok(DecoderInstruction::SectionAcknowledgment { stream_id })
        } else if (first_byte & 0x40) != 0 {
            // Stream Cancellation (01xxxxxx)
            let stream_id = VarInt::decode_with_prefix(buf, 6)?.0;
            Ok(DecoderInstruction::StreamCancellation { stream_id })
        } else {
            // Insert Count Increment (00xxxxxx)
            let increment = VarInt::decode_with_prefix(buf, 6)?.0;
            Ok(DecoderInstruction::InsertCountIncrement { increment })
        }
    }

    /// Process a decoder instruction
    fn process_instruction(&self, instruction: DecoderInstruction) -> Result<()> {
        use DecoderInstruction::*;
        
        match instruction {
            SectionAcknowledgment { stream_id } => {
                protocol_event!(
                    Level::Debug,
                    "Processing section acknowledgment";
                    "stream_id" => stream_id
                );
                
                (self.section_ack_callback)(stream_id);
                Ok(())
            }
            
            StreamCancellation { stream_id } => {
                protocol_event!(
                    Level::Debug,
                    "Processing stream cancellation";
                    "stream_id" => stream_id
                );
                
                (self.stream_cancel_callback)(stream_id);
                Ok(())
            }
            
            InsertCountIncrement { increment } => {
                protocol_event!(
                    Level::Debug,
                    "Processing insert count increment";
                    "increment" => increment
                );
                
                (self.insert_count_callback)(increment);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[tokio::test]
    async fn test_encoder_instruction_insert_with_name_ref() {
        let table = Arc::new(RwLock::new(DynamicTable::new(1024)));
        let processor = EncoderInstructionProcessor::new(Arc::clone(&table), 1024);
        
        // Create instruction bytes for InsertWithNameReference
        // Static table reference to ":authority" (index 1)
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0xc1]); // 11000001 - static table, index 1
        
        // Value "example.com"
        let value = b"example.com";
        buf.extend_from_slice(&[0x0b]); // Length 11, no huffman
        buf.extend_from_slice(value);
        
        let mut data = buf.freeze();
        let responses = processor.process_stream(&mut data).await.unwrap();
        
        assert_eq!(responses.len(), 1);
        match &responses[0] {
            DecoderInstruction::InsertCountIncrement { increment } => {
                assert_eq!(*increment, 1);
            }
            _ => panic!("Expected InsertCountIncrement"),
        }
        
        // Verify entry was inserted
        let table = table.read().await;
        assert_eq!(table.len(), 1);
        let entry = table.get(0).unwrap();
        assert_eq!(entry.name.as_str(), ":authority");
        assert_eq!(entry.value.as_str().unwrap(), "example.com");
    }

    #[tokio::test]
    async fn test_decoder_instruction_section_ack() {
        let ack_count = Arc::new(AtomicU64::new(0));
        let ack_count_clone = Arc::clone(&ack_count);
        
        let processor = DecoderInstructionProcessor::new(
            move |stream_id| {
                assert_eq!(stream_id, 42);
                ack_count_clone.fetch_add(1, Ordering::SeqCst);
            },
            |_| {},
            |_| {},
        );
        
        // Create instruction bytes for SectionAcknowledgment
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x80 | 42]); // 10101010 - stream ID 42
        
        let mut data = buf.freeze();
        processor.process_stream(&mut data).await.unwrap();
        
        assert_eq!(ack_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_decoder_instruction_insert_count_increment() {
        let count = Arc::new(AtomicU64::new(0));
        let count_clone = Arc::clone(&count);
        
        let processor = DecoderInstructionProcessor::new(
            |_| {},
            |_| {},
            move |increment| {
                count_clone.fetch_add(increment, Ordering::SeqCst);
            },
        );
        
        // Create instruction bytes for InsertCountIncrement
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0x05]); // 00000101 - increment 5
        
        let mut data = buf.freeze();
        processor.process_stream(&mut data).await.unwrap();
        
        assert_eq!(count.load(Ordering::SeqCst), 5);
    }
}