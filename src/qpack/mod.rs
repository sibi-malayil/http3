//! QPACK header compression implementation per RFC 9204
//!
//! This module implements QPACK (RFC 9204) header compression for HTTP/3.
//! QPACK uses a combination of static and dynamic tables to compress HTTP headers,
//! with special handling for HTTP/3's stream-based delivery model.

use crate::error::{Error, Result};
use crate::util::varint::VarInt;
use bytes::{Buf, BufMut, Bytes, BytesMut};

pub mod encoder;
pub mod encoder_enhanced;
pub mod decoder;
pub mod table;
pub mod field;
pub mod huffman;
pub mod huffman_complete;
pub mod huffman_production;
pub mod stream_manager;
pub mod dynamic_table_manager;
pub mod instruction_processor;

pub use encoder::{Encoder, AcknowledgmentInfo};
pub use decoder::Decoder;
pub use field::{HeaderField, HeaderName, HeaderValue};
pub use table::{DynamicTable, StaticTable};
pub use stream_manager::{QpackStreamManager, QpackStreamType, QpackStats};

/// QPACK instruction types for encoder stream
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncoderInstruction {
    /// Set Dynamic Table Capacity (001xxxxx)
    SetDynamicTableCapacity { 
        /// New capacity for the dynamic table
        capacity: u64 
    },
    /// Insert With Name Reference (1xxxxxxx)
    InsertWithNameReference {
        /// Table type: true for static, false for dynamic
        table: bool,
        /// Index of the name in the specified table
        name_index: u64,
        /// Header field value
        value: HeaderValue,
    },
    /// Insert With Literal Name (01xxxxxx)
    InsertWithLiteralName {
        /// Header field name
        name: HeaderName,
        /// Header field value
        value: HeaderValue,
    },
    /// Duplicate (000xxxxx)
    Duplicate { 
        /// Index of entry to duplicate
        index: u64 
    },
}

/// QPACK instruction types for decoder stream
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecoderInstruction {
    /// Section Acknowledgment (1xxxxxxx)
    SectionAcknowledgment { 
        /// Stream ID that completed header decoding
        stream_id: u64 
    },
    /// Stream Cancellation (01xxxxxx)
    StreamCancellation { 
        /// Stream ID being cancelled
        stream_id: u64 
    },
    /// Insert Count Increment (00xxxxxx)
    InsertCountIncrement { 
        /// Number of entries to increment
        increment: u64 
    },
}

/// QPACK field line representation types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldLineRepresentation {
    /// Indexed Field Line (1xxxxxxx)
    Indexed {
        /// Table type: true for static, false for dynamic
        table: bool,
        /// Index in the specified table
        index: u64,
    },
    /// Literal Field Line With Name Reference (01xxxxxx or 0001xxxx)
    LiteralWithNameReference {
        /// Table type: true for static, false for dynamic
        table: bool,
        /// Index of the name in the specified table
        index: u64,
        /// Header field value
        value: HeaderValue,
        /// Whether this field should never be indexed
        never_index: bool,
    },
    /// Literal Field Line With Literal Name (001xxxxx or 0000xxxx)
    LiteralWithLiteralName {
        /// Header field name
        name: HeaderName,
        /// Header field value
        value: HeaderValue,
        /// Whether this field should never be indexed
        never_index: bool,
    },
    /// Postbase Indexed Field Line (0001xxxx)
    PostbaseIndexed { 
        /// Post-base index value
        index: u64 
    },
    /// Literal Field Line With Postbase Name Reference (0000xxxx)
    LiteralWithPostbaseNameReference {
        /// Post-base index for the name
        index: u64,
        /// Header field value
        value: HeaderValue,
        /// Whether this field should never be indexed
        never_index: bool,
    },
}

/// QPACK configuration parameters
#[derive(Debug, Clone)]
pub struct Config {
    /// Maximum dynamic table capacity in bytes
    pub max_table_capacity: u64,
    /// Maximum number of blocked streams
    pub max_blocked_streams: u64,
    /// Enable huffman encoding for string literals
    pub use_huffman: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_table_capacity: 4096,  // 4KB default
            max_blocked_streams: 16,   // Conservative default
            use_huffman: true,         // Enable compression
        }
    }
}

/// QPACK string encoding types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringEncoding {
    /// Raw string (H=0)
    Raw,
    /// Huffman-encoded string (H=1) 
    Huffman,
}

/// QPACK string literal with encoding information
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringLiteral {
    /// String encoding type (raw or Huffman)
    pub encoding: StringEncoding,
    /// String data bytes
    pub data: Bytes,
}

impl StringLiteral {
    /// Create a new raw string literal
    pub fn raw(data: impl Into<Bytes>) -> Self {
        Self {
            encoding: StringEncoding::Raw,
            data: data.into(),
        }
    }
    
    /// Create a new huffman-encoded string literal
    pub fn huffman(data: impl Into<Bytes>) -> Self {
        Self {
            encoding: StringEncoding::Huffman,
            data: data.into(),
        }
    }
    
    /// Encode this string literal to bytes
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        let length = self.data.len();
        if length > VarInt::MAX.0 as usize {
            return Err(Error::QpackStringTooLong);
        }
        
        // Encode length with huffman bit
        let length_with_huffman = match self.encoding {
            StringEncoding::Raw => length as u64,
            StringEncoding::Huffman => (length as u64) | 0x8000_0000_0000_0000,
        };
        
        VarInt(length_with_huffman).encode(buf)?;
        buf.put_slice(&self.data);
        Ok(())
    }
    
    /// Decode a string literal from bytes
    pub fn decode(buf: &mut impl Buf) -> Result<Self> {
        let length_with_huffman = VarInt::decode(buf)?.0;
        let huffman = (length_with_huffman & 0x8000_0000_0000_0000) != 0;
        let length = (length_with_huffman & 0x7FFF_FFFF_FFFF_FFFF) as usize;
        
        if buf.remaining() < length {
            return Err(Error::QpackIncompleteData);
        }
        
        let mut data = BytesMut::with_capacity(length);
        data.put(buf.take(length));
        
        Ok(Self {
            encoding: if huffman { StringEncoding::Huffman } else { StringEncoding::Raw },
            data: data.freeze(),
        })
    }
    
    /// Convert this string literal to a string
    pub fn into_string(self) -> Result<String> {
        match self.encoding {
            StringEncoding::Raw => {
                String::from_utf8(self.data.to_vec())
                    .map_err(|_| Error::QpackInvalidHeaderValue)
            }
            StringEncoding::Huffman => {
                let decoded_bytes = huffman::decode_string(&self.data)?;
                String::from_utf8(decoded_bytes)
                    .map_err(|_| Error::QpackInvalidHeaderValue)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn string_literal_raw_encoding() {
        let literal = StringLiteral::raw(&b"test"[..]);
        let mut buf = BytesMut::new();
        literal.encode(&mut buf).unwrap();
        
        let mut cursor = buf.as_ref();
        let decoded = StringLiteral::decode(&mut cursor).unwrap();
        
        assert_eq!(decoded.encoding, StringEncoding::Raw);
        assert_eq!(decoded.data, b"test"[..]);
    }
    
    #[test]
    fn string_literal_huffman_encoding() {
        let literal = StringLiteral::huffman(&b"test"[..]);
        let mut buf = BytesMut::new();
        literal.encode(&mut buf).unwrap();
        
        let mut cursor = buf.as_ref();
        let decoded = StringLiteral::decode(&mut cursor).unwrap();
        
        assert_eq!(decoded.encoding, StringEncoding::Huffman);
        assert_eq!(decoded.data, b"test"[..]);
    }
    
    #[test]
    fn config_defaults() {
        let config = Config::default();
        assert_eq!(config.max_table_capacity, 4096);
        assert_eq!(config.max_blocked_streams, 16);
        assert!(config.use_huffman);
    }
}