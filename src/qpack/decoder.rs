//! QPACK decoder implementation per RFC 9204

use crate::error::{Error, Result};
use crate::qpack::{
    Config, DecoderInstruction, EncoderInstruction, StringLiteral,
    field::{HeaderField, HeaderName, HeaderValue},
    table::{DynamicTable, StaticTable},
};
use crate::util::varint::VarInt;
use bytes::Bytes;
use std::collections::{HashMap, VecDeque};

/// QPACK decoder state
#[derive(Debug)]
pub struct Decoder {
    config: Config,
    dynamic_table: DynamicTable,
    blocked_sections: HashMap<u64, BlockedSection>, // stream_id -> blocked section
    pending_instructions: VecDeque<DecoderInstruction>,
    max_blocked_streams: u64,
}

/// A blocked field section waiting for dynamic table updates
#[derive(Debug)]
struct BlockedSection {
    stream_id: u64,
    required_insert_count: u64,
    base_index: u64,
    encoded_data: Bytes,
}

impl Decoder {
    /// Create a new QPACK decoder with the given configuration
    pub fn new(config: Config) -> Self {
        Self {
            dynamic_table: DynamicTable::new(config.max_table_capacity),
            max_blocked_streams: config.max_blocked_streams,
            config,
            blocked_sections: HashMap::new(),
            pending_instructions: VecDeque::new(),
        }
    }
    
    /// Process encoder stream data
    pub fn process_encoder_stream(&mut self, data: Bytes) -> Result<()> {
        let mut buf = data;
        while !buf.is_empty() {
            let instruction = self.decode_encoder_instruction(&mut buf)?;
            self.process_encoder_instruction(instruction)?;
        }
        Ok(())
    }
    
    /// Process an encoder stream instruction
    pub fn process_encoder_instruction(&mut self, instruction: EncoderInstruction) -> Result<()> {
        match instruction {
            EncoderInstruction::SetDynamicTableCapacity { capacity } => {
                self.dynamic_table.set_capacity(capacity)?;
            }
            EncoderInstruction::InsertWithNameReference { table, name_index, value } => {
                let name = if table {
                    StaticTable::get_name(name_index)
                        .ok_or(Error::QpackInvalidIndex)?
                } else {
                    self.dynamic_table.get(name_index)
                        .map(|field| field.name.clone())
                        .ok_or(Error::QpackInvalidIndex)?
                };
                
                let field = HeaderField::new(name, value);
                self.dynamic_table.insert(field)?;
            }
            EncoderInstruction::InsertWithLiteralName { name, value } => {
                let field = HeaderField::new(name, value);
                self.dynamic_table.insert(field)?;
            }
            EncoderInstruction::Duplicate { index } => {
                self.dynamic_table.duplicate(index)?;
            }
        }
        
        // Check if any blocked sections can now be decoded
        self.process_blocked_sections()?;
        
        Ok(())
    }
    
    /// Decode a field section
    pub fn decode_field_section(
        &mut self,
        stream_id: u64,
        data: Bytes,
    ) -> Result<Option<Vec<HeaderField>>> {
        let mut buf = data.as_ref();
        
        // Decode section prefix
        let (required_insert_count, base_index) = self.decode_section_prefix(&mut buf)?;
        
        // Check if we can decode this section immediately
        if required_insert_count > self.dynamic_table.insert_count() {
            // Section is blocked - store it for later
            if self.blocked_sections.len() >= self.max_blocked_streams as usize {
                return Err(Error::QpackTooManyBlockedStreams);
            }
            
            self.blocked_sections.insert(stream_id, BlockedSection {
                stream_id,
                required_insert_count,
                base_index,
                encoded_data: data,
            });
            
            return Ok(None); // Blocked
        }
        
        // Decode field lines
        let fields = self.decode_field_lines(&mut buf, base_index)?;
        
        // Send section acknowledgment
        self.pending_instructions.push_back(
            DecoderInstruction::SectionAcknowledgment { stream_id }
        );
        
        Ok(Some(fields))
    }
    
    /// Cancel a stream (remove from blocked sections)
    pub fn cancel_stream(&mut self, stream_id: u64) -> Result<()> {
        if self.blocked_sections.remove(&stream_id).is_some() {
            self.pending_instructions.push_back(
                DecoderInstruction::StreamCancellation { stream_id }
            );
        }
        Ok(())
    }
    
    /// Get pending decoder stream instructions
    pub fn take_decoder_instructions(&mut self) -> Vec<DecoderInstruction> {
        self.pending_instructions.drain(..).collect()
    }
    
    /// Decode section prefix (required insert count and base index)
    fn decode_section_prefix(&self, buf: &mut &[u8]) -> Result<(u64, u64)> {
        let required_insert_count = VarInt::decode(buf)?.0;
        
        let delta_base_with_sign = VarInt::decode_with_prefix(buf, 7)?;
        let delta_base = delta_base_with_sign.0 & 0x7F;
        let sign = (delta_base_with_sign.0 & 0x80) != 0;
        
        let base_index = if sign {
            required_insert_count.saturating_sub(delta_base + 1)
        } else {
            required_insert_count + delta_base
        };
        
        Ok((required_insert_count, base_index))
    }
    
    /// Decode field lines from the encoded data
    fn decode_field_lines(&self, buf: &mut &[u8], base_index: u64) -> Result<Vec<HeaderField>> {
        let mut fields = Vec::new();
        
        while !buf.is_empty() {
            let field = self.decode_field_line(buf, base_index)?;
            fields.push(field);
        }
        
        Ok(fields)
    }
    
    /// Decode a single field line
    fn decode_field_line(&self, buf: &mut &[u8], base_index: u64) -> Result<HeaderField> {
        if buf.is_empty() {
            return Err(Error::QpackIncompleteData);
        }
        
        let first_byte = buf[0];
        
        match first_byte {
            // Indexed Field Line (1xxxxxxx)
            b if (b & 0x80) != 0 => {
                let index = VarInt::decode_with_prefix(buf, 6)?.0;
                let table_bit = (first_byte & 0x40) != 0;
                
                if table_bit {
                    // Static table
                    StaticTable::get(index).ok_or(Error::QpackInvalidIndex)
                } else {
                    // Dynamic table
                    self.dynamic_table.get_by_absolute_index(base_index - index)
                        .cloned()
                        .ok_or(Error::QpackInvalidIndex)
                }
            }
            
            // Literal with Name Reference (01xxxxxx)
            b if (b & 0xC0) == 0x40 => {
                let _never_index = (b & 0x20) != 0;
                let table_bit = (b & 0x10) != 0;
                let name_index = VarInt::decode_with_prefix(buf, 4)?.0;
                let value_literal = StringLiteral::decode(buf)?;
                
                let name = if table_bit {
                    // Static table
                    StaticTable::get_name(name_index)
                        .ok_or(Error::QpackInvalidIndex)?
                } else {
                    // Dynamic table
                    self.dynamic_table.get_by_absolute_index(base_index - name_index)
                        .map(|field| field.name.clone())
                        .ok_or(Error::QpackInvalidIndex)?
                };
                
                let value = HeaderValue::new(value_literal.data)?;
                Ok(HeaderField::new(name, value))
            }
            
            // Literal with Literal Name (001xxxxx)
            b if (b & 0xE0) == 0x20 => {
                VarInt::decode_with_prefix(buf, 3)?; // Skip length prefix
                let name_literal = StringLiteral::decode(buf)?;
                let value_literal = StringLiteral::decode(buf)?;
                
                let name = HeaderName::new(name_literal.data)?;
                let value = HeaderValue::new(value_literal.data)?;
                Ok(HeaderField::new(name, value))
            }
            
            // Post-Base Indexed (0001xxxx)
            b if (b & 0xF0) == 0x10 => {
                let index = VarInt::decode_with_prefix(buf, 4)?.0;
                let absolute_index = base_index + index + 1;
                
                self.dynamic_table.get_by_absolute_index(absolute_index)
                    .cloned()
                    .ok_or(Error::QpackInvalidIndex)
            }
            
            // Literal with Post-Base Name Reference (0000xxxx)
            b if (b & 0xF0) == 0x00 => {
                let _never_index = (b & 0x08) != 0;
                let name_index = VarInt::decode_with_prefix(buf, 3)?.0;
                let value_literal = StringLiteral::decode(buf)?;
                
                let absolute_index = base_index + name_index + 1;
                let name = self.dynamic_table.get_by_absolute_index(absolute_index)
                    .map(|field| field.name.clone())
                    .ok_or(Error::QpackInvalidIndex)?;
                
                let value = HeaderValue::new(value_literal.data)?;
                Ok(HeaderField::new(name, value))
            }
            
            _ => Err(Error::QpackInvalidFieldLine),
        }
    }
    
    /// Process blocked sections that may now be decodable
    fn process_blocked_sections(&mut self) -> Result<()> {
        let current_insert_count = self.dynamic_table.insert_count();
        let mut unblocked_streams = Vec::new();
        
        for (stream_id, section) in &self.blocked_sections {
            if section.required_insert_count <= current_insert_count {
                unblocked_streams.push(*stream_id);
            }
        }
        
        for stream_id in unblocked_streams {
            if let Some(section) = self.blocked_sections.remove(&stream_id) {
                // Attempt to decode the section
                let mut buf = section.encoded_data.as_ref();
                
                // Skip section prefix (already parsed)
                VarInt::decode(&mut buf)?; // required_insert_count
                VarInt::decode_with_prefix(&mut buf, 7)?; // base_index
                
                // Decode field lines
                match self.decode_field_lines(&mut buf, section.base_index) {
                    Ok(_fields) => {
                        // Section successfully decoded
                        self.pending_instructions.push_back(
                            DecoderInstruction::SectionAcknowledgment { 
                                stream_id: section.stream_id 
                            }
                        );
                    }
                    Err(_) => {
                        // Re-block the section if it still can't be decoded
                        self.blocked_sections.insert(stream_id, section);
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Get the current dynamic table insert count
    pub fn insert_count(&self) -> u64 {
        self.dynamic_table.insert_count()
    }
    
    /// Get the number of blocked streams
    pub fn blocked_streams_count(&self) -> usize {
        self.blocked_sections.len()
    }
    
    /// Check if a stream is blocked
    pub fn is_stream_blocked(&self, stream_id: u64) -> bool {
        self.blocked_sections.contains_key(&stream_id)
    }

    /// Get unblocked streams after processing encoder instructions
    pub fn get_unblocked_streams(&mut self) -> Vec<u64> {
        let mut unblocked = Vec::new();
        let current_insert_count = self.dynamic_table.insert_count();
        
        // Check which blocked sections can now be decoded
        let blocked_ids: Vec<u64> = self.blocked_sections.keys().cloned().collect();
        for stream_id in blocked_ids {
            if let Some(section) = self.blocked_sections.get(&stream_id) {
                if section.required_insert_count <= current_insert_count {
                    unblocked.push(stream_id);
                }
            }
        }
        
        unblocked
    }

    /// Get pending acknowledgment for a stream
    pub fn get_pending_acknowledgment(&self, stream_id: u64) -> Option<u64> {
        // Would check if this stream needs acknowledgment
        // For now, always acknowledge
        Some(stream_id)
    }

    /// Get pending insert count increment
    pub fn get_pending_insert_count_increment(&self) -> Option<u64> {
        // Would calculate if we need to send increment
        // For now, return None
        None
    }

    /// Get decoder configuration
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Get maximum table capacity from config
    pub fn max_table_capacity(&self) -> usize {
        self.config.max_table_capacity as usize
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qpack::encoder::Encoder;
    
    #[test]
    fn decoder_creation() {
        let decoder = Decoder::default();
        assert_eq!(decoder.insert_count(), 0);
        assert_eq!(decoder.blocked_streams_count(), 0);
    }
    
    #[test]
    fn decode_static_table_field() {
        let mut decoder = Decoder::default();
        
        // Encode a field using static table
        let mut encoder = Encoder::default();
        let fields = vec![
            HeaderField::new(
                HeaderName::new(":method").unwrap(),
                HeaderValue::new("GET").unwrap(),
            )
        ];
        
        let encoded = encoder.encode_field_section(1, &fields, false).unwrap();
        let decoded = decoder.decode_field_section(1, encoded).unwrap();
        
        assert!(decoded.is_some());
        let decoded_fields = decoded.unwrap();
        assert_eq!(decoded_fields.len(), 1);
        assert_eq!(decoded_fields[0].name.as_str(), ":method");
        assert_eq!(decoded_fields[0].value.as_str().unwrap(), "GET");
    }
    
    #[test]
    fn roundtrip_encoding_decoding() {
        let mut encoder = Encoder::default();
        let mut decoder = Decoder::default();
        
        let original_fields = vec![
            HeaderField::new(
                HeaderName::new(":method").unwrap(),
                HeaderValue::new("POST").unwrap(),
            ),
            HeaderField::new(
                HeaderName::new("content-type").unwrap(),
                HeaderValue::new("application/json").unwrap(),
            ),
            HeaderField::new(
                HeaderName::new("custom-header").unwrap(),
                HeaderValue::new("custom-value").unwrap(),
            ),
        ];
        
        let encoded = encoder.encode_field_section(1, &original_fields, false).unwrap();
        let decoded = decoder.decode_field_section(1, encoded).unwrap();
        
        assert!(decoded.is_some());
        let decoded_fields = decoded.unwrap();
        assert_eq!(decoded_fields.len(), original_fields.len());
        
        for (original, decoded) in original_fields.iter().zip(decoded_fields.iter()) {
            assert_eq!(original.name, decoded.name);
            assert_eq!(original.value, decoded.value);
        }
    }
    
    #[test]
    fn stream_cancellation() {
        let mut decoder = Decoder::default();
        
        decoder.cancel_stream(42).unwrap();
        let instructions = decoder.take_decoder_instructions();
        
        // Should not generate instruction for non-blocked stream
        assert!(instructions.is_empty());
    }
}

impl Decoder {
    /// Decode an encoder instruction from the stream
    fn decode_encoder_instruction(&self, buf: &mut Bytes) -> Result<EncoderInstruction> {
        if buf.is_empty() {
            return Err(Error::Incomplete);
        }
        
        let first_byte = buf[0];
        
        if (first_byte & 0x80) != 0 {
            // Insert With Name Reference (1xxxxxxx)
            let table = (first_byte & 0x40) != 0;
            let name_index = VarInt::decode_with_prefix(buf, 6)?;
            let value = StringLiteral::decode(buf)?;
            Ok(EncoderInstruction::InsertWithNameReference {
                table,
                name_index: name_index.into(),
                value: HeaderValue::from(value.into_string()?),
            })
        } else if (first_byte & 0x40) != 0 {
            // Insert With Literal Name (01xxxxxx)
            let name = StringLiteral::decode(buf)?;
            let value = StringLiteral::decode(buf)?;
            Ok(EncoderInstruction::InsertWithLiteralName { 
                name: HeaderName::from(name.into_string()?),
                value: HeaderValue::from(value.into_string()?),
            })
        } else if (first_byte & 0x20) != 0 {
            // Set Dynamic Table Capacity (001xxxxx)
            let capacity = VarInt::decode_with_prefix(buf, 5)?;
            Ok(EncoderInstruction::SetDynamicTableCapacity {
                capacity: capacity.into(),
            })
        } else {
            // Duplicate (000xxxxx)
            let index = VarInt::decode_with_prefix(buf, 5)?;
            Ok(EncoderInstruction::Duplicate {
                index: index.into(),
            })
        }
    }
}