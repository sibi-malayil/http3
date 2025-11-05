//! QPACK encoder implementation per RFC 9204

use crate::error::{Error, Result};
use crate::qpack::{
    Config, EncoderInstruction, StringLiteral,
    field::{HeaderField, HeaderName, HeaderValue},
    table::{DynamicTable, StaticTable},
};
use crate::util::varint::VarInt;
use bytes::{Bytes, BytesMut};
use std::collections::{HashMap, VecDeque};

/// A blocked stream waiting for dynamic table updates
#[derive(Debug, Clone)]
struct BlockedStream {
    stream_id: u64,
    required_insert_count: u64,
}

/// QPACK encoder state
#[derive(Debug)]
pub struct Encoder {
    config: Config,
    dynamic_table: DynamicTable,
    blocked_streams: HashMap<u64, BlockedStream>,
    known_received_count: u64,
    pending_instructions: VecDeque<EncoderInstruction>,
    max_blocked_streams: u64,
}

impl Encoder {
    /// Create a new QPACK encoder with the given configuration
    pub fn new(config: Config) -> Self {
        Self {
            dynamic_table: DynamicTable::new(config.max_table_capacity),
            max_blocked_streams: config.max_blocked_streams,
            config,
            blocked_streams: HashMap::new(),
            known_received_count: 0,
            pending_instructions: VecDeque::new(),
        }
    }
    
    /// Process decoder stream data
    /// 
    /// # Errors
    /// 
    /// Returns an error if instruction decoding or processing fails.
    pub fn process_decoder_stream(&mut self, data: Bytes) -> Result<()> {
        let mut buf = data;
        while !buf.is_empty() {
            let instruction = self.decode_decoder_instruction(&mut buf)?;
            self.process_decoder_instruction(instruction)?;
        }
        Ok(())
    }
    
    /// Update the dynamic table capacity
    /// 
    /// # Errors
    /// 
    /// Returns an error if the capacity update fails.
    pub fn set_capacity(&mut self, capacity: u64) -> Result<()> {
        self.config.max_table_capacity = capacity;
        self.dynamic_table.set_capacity(capacity)?;
        
        // Send capacity update instruction
        self.pending_instructions.push_back(
            EncoderInstruction::SetDynamicTableCapacity { capacity }
        );
        
        Ok(())
    }
    
    /// Encode a list of header fields for a stream
    /// 
    /// # Errors
    /// 
    /// Returns an error if encoding fails or if blocking is not allowed but required.
    pub fn encode_field_section(
        &mut self,
        stream_id: u64,
        fields: &[HeaderField],
        allow_blocking: bool,
    ) -> Result<Bytes> {
        let mut buf = BytesMut::new();
        let required_insert_count = self.calculate_required_insert_count(fields);
        
        // Encode section prefix
        self.encode_section_prefix(&mut buf, required_insert_count)?;
        
        // If this section references dynamic table entries, it might block
        if required_insert_count > self.known_received_count {
            if !allow_blocking {
                return Err(Error::QpackWouldBlock);
            }
            self.blocked_streams.insert(stream_id, BlockedStream {
                stream_id,
                required_insert_count,
            });
        }
        
        // Encode each header field
        for field in fields {
            self.encode_field_line(&mut buf, field, required_insert_count)?;
        }
        
        Ok(buf.freeze())
    }
    
    
    /// Process decoder stream instruction
    /// 
    /// # Errors
    /// 
    /// Returns an error if instruction processing fails.
    pub fn process_decoder_instruction(&mut self, instruction: crate::qpack::DecoderInstruction) -> Result<()> {
        
        use crate::qpack::DecoderInstruction;
        
        match instruction {
            DecoderInstruction::SectionAcknowledgment { stream_id } => {
                // Remove stream from blocked list
                if let Some(blocked_stream) = self.blocked_streams.remove(&stream_id) {
                    self.known_received_count = self.known_received_count.max(blocked_stream.required_insert_count);
                }
            }
            DecoderInstruction::StreamCancellation { stream_id } => {
                // Remove stream from blocked list without updating known_received_count
                self.blocked_streams.remove(&stream_id);
            }
            DecoderInstruction::InsertCountIncrement { increment } => {
                self.known_received_count += increment;
            }
        }
        
        Ok(())
    }
    
    /// Encode a field line representation
    /// 
    /// # Errors
    /// 
    /// Returns an error if field encoding fails.
    fn encode_field_line(
        &mut self,
        buf: &mut BytesMut,
        field: &HeaderField,
        base_index: u64,
    ) -> Result<()> {
        // Try static table first
        if let Some(index) = StaticTable::find_field(field) {
            self.encode_indexed_field_line(buf, true, index)?;
            return Ok(());
        }
        
        // Try dynamic table for full match using encoder's method
        if let Some(index) = self.find_in_dynamic_table(field) {
            let relative_index = index;
            let absolute_index = self.dynamic_table.relative_to_absolute(relative_index).unwrap();

            if absolute_index <= base_index {
                // Use indexed field line
                self.encode_indexed_field_line(buf, false, relative_index)?;
                return Ok(());
            }
            // Use post-base indexed field line
            let post_base_index = absolute_index - base_index - 1;
            self.encode_postbase_indexed_field_line(buf, post_base_index)?;
            return Ok(());
        }

        // Check if we should insert into dynamic table
        if self.should_insert(field) {
            self.send_insert_instruction(field)?;
        }

        // Try name-only matches
        let (name_table, name_index) = if let Some(index) = StaticTable::find_name(&field.name) {
            (true, index)
        } else if let Some(relative_index) = self.find_name_in_dynamic_table(&field.name) {
            let absolute_index = self.dynamic_table.relative_to_absolute(relative_index).unwrap();
            if absolute_index <= base_index {
                (false, relative_index)
            } else {
                // Use post-base name reference
                let post_base_index = absolute_index - base_index - 1;
                return self.encode_literal_with_postbase_name_reference(
                    buf, post_base_index, &field.value, field.never_index()
                );
            }
        } else {
            // No name match, use literal name
            return self.encode_literal_with_literal_name(buf, field, field.never_index());
        };
        
        // Encode literal with name reference
        self.encode_literal_with_name_reference(
            buf, name_table, name_index, &field.value, field.never_index()
        )?;
        
        // Consider adding to dynamic table if beneficial
        if !field.never_index() && self.should_index(field) {
            if self.dynamic_table.insert(field.clone()).is_err() {
                // Table full, ignore error
            } else {
                // Send insert instruction
                if name_table {
                    self.pending_instructions.push_back(
                        EncoderInstruction::InsertWithNameReference {
                            table: name_table,
                            name_index,
                            value: field.value.clone(),
                        }
                    );
                } else {
                    self.pending_instructions.push_back(
                        EncoderInstruction::InsertWithLiteralName {
                            name: field.name.clone(),
                            value: field.value.clone(),
                        }
                    );
                }
            }
        }
        
        Ok(())
    }
    
    /// Encode section prefix with required insert count and base index
    /// 
    /// # Errors
    /// 
    /// Returns an error if encoding fails.
    fn encode_section_prefix(&self, buf: &mut BytesMut, required_insert_count: u64) -> Result<()> {
        // Encode required insert count
        VarInt(required_insert_count).encode(buf)?;
        
        // For simplicity, always use base index = required_insert_count (S=0)
        // In production, this could be optimized
        let delta_base = 0u64;
        let sign_bit = 0u8; // S=0, positive delta
        
        VarInt(delta_base).encode_with_prefix(buf, 7, sign_bit)?;
        
        Ok(())
    }
    
    /// Encode indexed field line (1xxxxxxx for static, 1xxxxxxx with T=0 for dynamic)
    /// 
    /// # Errors
    /// 
    /// Returns an error if encoding fails.
    fn encode_indexed_field_line(&self, buf: &mut BytesMut, is_static: bool, index: u64) -> Result<()> {
        let prefix_mask = if is_static { 0x80 } else { 0x80 };
        VarInt(index).encode_with_prefix(buf, 6, prefix_mask)?;
        Ok(())
    }
    
    /// Encode post-base indexed field line (0001xxxx)
    /// 
    /// # Errors
    /// 
    /// Returns an error if encoding fails.
    fn encode_postbase_indexed_field_line(&self, buf: &mut BytesMut, index: u64) -> Result<()> {
        VarInt(index).encode_with_prefix(buf, 4, 0x10)?;
        Ok(())
    }
    
    /// Encode literal with name reference (01xxxxxx for static, 01xxxxxx with T=0 for dynamic)
    /// 
    /// # Errors
    /// 
    /// Returns an error if encoding fails.
    fn encode_literal_with_name_reference(
        &self,
        buf: &mut BytesMut,
        _is_static: bool,
        name_index: u64,
        value: &HeaderValue,
        never_index: bool,
    ) -> Result<()> {
        let prefix_mask = if never_index { 0x20 } else { 0x40 };
        VarInt(name_index).encode_with_prefix(buf, 4, prefix_mask)?;
        
        let literal = if self.config.use_huffman {
            StringLiteral::huffman(value.as_bytes().to_vec())
        } else {
            StringLiteral::raw(value.as_bytes().to_vec())
        };
        
        literal.encode(buf)?;
        Ok(())
    }
    
    /// Encode literal with literal name (001xxxxx for indexable, 0000xxxx for never-index)
    /// 
    /// # Errors
    /// 
    /// Returns an error if encoding fails.
    fn encode_literal_with_literal_name(
        &self,
        buf: &mut BytesMut,
        field: &HeaderField,
        never_index: bool,
    ) -> Result<()> {
        let prefix_mask = if never_index { 0x00 } else { 0x20 };
        let prefix_bits = if never_index { 4 } else { 3 };
        
        // Encode name
        let name_literal = if self.config.use_huffman {
            StringLiteral::huffman(field.name.as_bytes().to_vec())
        } else {
            StringLiteral::raw(field.name.as_bytes().to_vec())
        };
        
        // First encode a zero-length varint with the appropriate prefix
        VarInt(0).encode_with_prefix(buf, prefix_bits, prefix_mask)?;
        name_literal.encode(buf)?;
        
        // Encode value
        let value_literal = if self.config.use_huffman {
            StringLiteral::huffman(field.value.as_bytes().to_vec())
        } else {
            StringLiteral::raw(field.value.as_bytes().to_vec())
        };
        
        value_literal.encode(buf)?;
        Ok(())
    }
    
    /// Encode literal with post-base name reference (0000xxxx)
    /// 
    /// # Errors
    /// 
    /// Returns an error if encoding fails.
    fn encode_literal_with_postbase_name_reference(
        &self,
        buf: &mut BytesMut,
        name_index: u64,
        value: &HeaderValue,
        _never_index: bool,
    ) -> Result<()> {
        VarInt(name_index).encode_with_prefix(buf, 3, 0x00)?;
        
        let literal = if self.config.use_huffman {
            StringLiteral::huffman(value.as_bytes().to_vec())
        } else {
            StringLiteral::raw(value.as_bytes().to_vec())
        };
        
        literal.encode(buf)?;
        Ok(())
    }
    
    /// Calculate the required insert count for a field section
    fn calculate_required_insert_count(&self, fields: &[HeaderField]) -> u64 {
        let mut max_absolute_index = 0u64;
        
        for field in fields {
            if let Some(relative_index) = self.dynamic_table.find_field(field) {
                if let Some(absolute_index) = self.dynamic_table.relative_to_absolute(relative_index) {
                    max_absolute_index = max_absolute_index.max(absolute_index);
                }
            } else if let Some(relative_index) = self.dynamic_table.find_name(&field.name) {
                if let Some(absolute_index) = self.dynamic_table.relative_to_absolute(relative_index) {
                    max_absolute_index = max_absolute_index.max(absolute_index);
                }
            }
        }
        
        max_absolute_index
    }
    
    /// Determine if a field should be added to the dynamic table
    fn should_index(&self, field: &HeaderField) -> bool {
        // Simple heuristic: index if field is large enough to be worthwhile
        // and not security-sensitive
        !field.never_index() && field.size() >= 64
    }
    
    /// Get the current dynamic table insert count
    pub fn insert_count(&self) -> u64 {
        self.dynamic_table.insert_count()
    }
    
    /// Get the number of blocked streams
    pub fn blocked_streams_count(&self) -> usize {
        self.blocked_streams.len()
    }
}

impl Encoder {
    /// Find field in dynamic table
    fn find_in_dynamic_table(&self, field: &HeaderField) -> Option<u64> {
        // Linear search through dynamic table
        for i in 0..self.dynamic_table.len_u64() {
            if let Some(entry) = self.dynamic_table.get(i) {
                if entry.name == field.name && entry.value == field.value {
                    return Some(i);
                }
            }
        }
        None
    }
    
    /// Find name in dynamic table
    fn find_name_in_dynamic_table(&self, name: &HeaderName) -> Option<u64> {
        for i in 0..self.dynamic_table.len_u64() {
            if let Some(entry) = self.dynamic_table.get(i) {
                if entry.name == *name {
                    return Some(i);
                }
            }
        }
        None
    }
    
    /// Determine if field should be inserted into dynamic table
    fn should_insert(&self, field: &HeaderField) -> bool {
        // Simple heuristic: insert if name is not in static table and table has space
        StaticTable::find_name(&field.name).is_none() && 
        self.dynamic_table.can_insert(field.encoded_size() as usize)
    }
    
    /// Send insert instruction to decoder
    /// 
    /// # Errors
    /// 
    /// Returns an error if instruction creation fails.
    fn send_insert_instruction(&mut self, field: &HeaderField) -> Result<()> {
        // Check if name exists in static table
        if let Some(name_index) = StaticTable::find_name(&field.name) {
            self.pending_instructions.push_back(EncoderInstruction::InsertWithNameReference {
                table: true, // Static table
                name_index,
                value: field.value.clone(),
            });
        } else if let Some(name_index) = self.find_name_in_dynamic_table(&field.name) {
            self.pending_instructions.push_back(EncoderInstruction::InsertWithNameReference {
                table: false, // Dynamic table
                name_index,
                value: field.value.clone(),
            });
        } else {
            self.pending_instructions.push_back(EncoderInstruction::InsertWithLiteralName {
                name: field.name.clone(),
                value: field.value.clone(),
            });
        }
        Ok(())
    }

    /// Take pending encoder instructions
    pub fn take_encoder_instructions(&mut self) -> Option<Vec<EncoderInstruction>> {
        if self.pending_instructions.is_empty() {
            None
        } else {
            Some(self.pending_instructions.drain(..).collect())
        }
    }

    /// Get acknowledgment info after processing decoder stream
    pub fn get_acknowledgment_info(&self) -> Option<AcknowledgmentInfo> {
        // Return info about acknowledged streams
        Some(AcknowledgmentInfo {
            insert_count: self.known_received_count,
            acknowledged_streams: vec![], // Would track acknowledged streams
        })
    }
}

/// Information about acknowledged streams
pub struct AcknowledgmentInfo {
    /// Current known received insert count
    pub insert_count: u64,
    /// List of stream IDs that have been acknowledged
    pub acknowledged_streams: Vec<u64>,
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qpack::field::HeaderName;
    
    #[test]
    fn encoder_creation() {
        let encoder = Encoder::default();
        assert_eq!(encoder.insert_count(), 0);
        assert_eq!(encoder.blocked_streams_count(), 0);
    }
    
    #[test]
    fn encode_static_table_field() {
        let mut encoder = Encoder::default();
        
        let fields = vec![
            HeaderField::new(
                HeaderName::new(":method").unwrap(),
                HeaderValue::new("GET").unwrap(),
            )
        ];
        
        let encoded = encoder.encode_field_section(1, &fields, false).unwrap();
        assert!(!encoded.is_empty());
    }
    
    #[test]
    fn encode_literal_field() {
        let mut encoder = Encoder::default();
        
        let fields = vec![
            HeaderField::new(
                HeaderName::new("custom-header").unwrap(),
                HeaderValue::new("custom-value").unwrap(),
            )
        ];
        
        let encoded = encoder.encode_field_section(1, &fields, false).unwrap();
        assert!(!encoded.is_empty());
    }
    
    #[test]
    fn capacity_update() {
        let mut encoder = Encoder::default();
        encoder.set_capacity(8192).unwrap();
        
        let instructions = encoder.take_encoder_instructions().unwrap();
        assert_eq!(instructions.len(), 1);
        
        match &instructions[0] {
            EncoderInstruction::SetDynamicTableCapacity { capacity } => {
                assert_eq!(*capacity, 8192);
            }
            _ => panic!("Expected capacity update instruction"),
        }
    }
}

impl Encoder {
    /// Decode a decoder instruction from the stream
    /// 
    /// # Errors
    /// 
    /// Returns an error if decoding fails or data is incomplete.
    fn decode_decoder_instruction(&self, buf: &mut Bytes) -> Result<crate::qpack::DecoderInstruction> {
        if buf.is_empty() {
            return Err(Error::Incomplete);
        }
        
        let first_byte = buf[0];
        
        if (first_byte & 0x80) != 0 {
            // Section Acknowledgment (1xxxxxxx)
            let stream_id = VarInt::decode_with_prefix(buf, 7)?;
            Ok(crate::qpack::DecoderInstruction::SectionAcknowledgment {
                stream_id: stream_id.into(),
            })
        } else if (first_byte & 0x40) != 0 {
            // Stream Cancellation (01xxxxxx)
            let stream_id = VarInt::decode_with_prefix(buf, 6)?;
            Ok(crate::qpack::DecoderInstruction::StreamCancellation {
                stream_id: stream_id.into(),
            })
        } else {
            // Insert Count Increment (00xxxxxx)
            let increment = VarInt::decode_with_prefix(buf, 6)?;
            Ok(crate::qpack::DecoderInstruction::InsertCountIncrement {
                increment: increment.into(),
            })
        }
    }
    
}