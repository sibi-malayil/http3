//! Production-grade Huffman coding implementation for QPACK per RFC 7541 Appendix B
//! 
//! This module provides a complete, efficient, and secure implementation of Huffman 
//! encoding and decoding for HTTP/3 header compression.
//!
//! # Security Features
//! - Input size limits to prevent DoS attacks
//! - Strict padding validation per RFC 7541
//! - Memory-safe operations with bounds checking
//! - Protection against malformed input
//!
//! # Performance Features  
//! - Fast 8-bit lookup table for common cases
//! - Optimized bit manipulation
//! - Zero-copy where possible
//! - Pre-computed encoding table
//! - Thread-safe global instances
//!
//! # Production Features
//! - Comprehensive error handling
//! - Detailed error messages for debugging
//! - Metrics and instrumentation hooks
//! - RFC-compliant implementation

use crate::error::{Error, Result};
use crate::{debug};
use std::sync::LazyLock;

/// Maximum allowed input size for Huffman operations (1MB)
/// This prevents DoS attacks through memory exhaustion
const MAX_INPUT_SIZE: usize = 1024 * 1024;

/// Maximum allowed encoded size (2MB) 
/// Accounts for worst-case expansion (rare but possible)
const MAX_ENCODED_SIZE: usize = 2 * 1024 * 1024;

/// Minimum compression ratio to warn about inefficient encoding
const MIN_COMPRESSION_RATIO: f64 = 0.95;

/// Huffman symbol entry in the encoding table
#[derive(Debug, Clone, Copy)]
struct HuffmanSymbol {
    /// The Huffman code for this symbol
    code: u32,
    /// Number of bits in the code (5-30 bits per RFC 7541)
    bits: u8,
}

/// Huffman decoder node for tree-based decoding
#[derive(Debug, Clone)]
struct HuffmanNode {
    /// Symbol value if this is a leaf node (None for internal nodes)
    symbol: Option<u8>,
    /// Left child (bit 0)
    left: Option<Box<HuffmanNode>>,
    /// Right child (bit 1)  
    right: Option<Box<HuffmanNode>>,
}

impl HuffmanNode {
    /// Create a new internal node
    fn new_internal() -> Self {
        Self {
            symbol: None,
            left: None,
            right: None,
        }
    }

    /// Create a new leaf node
    fn new_leaf(symbol: u8) -> Self {
        Self {
            symbol: Some(symbol),
            left: None,
            right: None,
        }
    }
}

/// Fast decode table entry for 8-bit prefixes
#[derive(Debug, Clone, Copy)]
struct FastDecodeEntry {
    /// The decoded symbol
    symbol: u8,
    /// Number of bits consumed (1-8)
    bits_consumed: u8,
}

/// Production-grade Huffman decoder with security and performance optimizations
pub struct HuffmanDecoder {
    /// Root of the Huffman tree
    root: HuffmanNode,
    /// Fast lookup table for 8-bit prefixes
    fast_table: [Option<FastDecodeEntry>; 256],
}

impl HuffmanDecoder {
    /// Create a new Huffman decoder with the RFC 7541 table
    fn new() -> Self {
        let mut root = HuffmanNode::new_internal();
        let mut fast_table = [None; 256];
        
        // Build the Huffman tree from the encoding table
        for (symbol, entry) in HUFFMAN_ENCODE_TABLE.iter().enumerate() {
            if symbol > 256 {
                break; // Skip EOS symbol for tree building
            }
            
            if symbol <= 255 {
                Self::insert_symbol(&mut root, symbol as u8, entry.code, entry.bits);
                
                // Build fast table entries for codes <= 8 bits
                if entry.bits <= 8 {
                    let prefix_start = (entry.code as u8) << (8 - entry.bits);
                    let prefix_count = 1 << (8 - entry.bits);
                    
                    for i in 0..prefix_count {
                        let prefix = prefix_start | i;
                        fast_table[prefix as usize] = Some(FastDecodeEntry {
                            symbol: symbol as u8,
                            bits_consumed: entry.bits,
                        });
                    }
                }
            }
        }
        
        Self { root, fast_table }
    }
    
    /// Insert a symbol into the Huffman tree
    fn insert_symbol(root: &mut HuffmanNode, symbol: u8, code: u32, bits: u8) {
        let mut current = root;
        
        for i in (0..bits).rev() {
            let bit = (code >> i) & 1;
            
            if i == 0 {
                // Last bit - create leaf node
                if bit == 0 {
                    current.left = Some(Box::new(HuffmanNode::new_leaf(symbol)));
                } else {
                    current.right = Some(Box::new(HuffmanNode::new_leaf(symbol)));
                }
            } else {
                // Internal node - navigate or create
                let next = if bit == 0 {
                    current.left.get_or_insert_with(|| Box::new(HuffmanNode::new_internal()))
                } else {
                    current.right.get_or_insert_with(|| Box::new(HuffmanNode::new_internal()))
                };
                current = next;
            }
        }
    }
    
    /// Decode Huffman-encoded data with production-grade error handling
    pub fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        if encoded.is_empty() {
            return Ok(Vec::new());
        }
        
        // Security: Prevent DoS through large inputs
        if encoded.len() > MAX_ENCODED_SIZE {
            debug!("Huffman decode rejected: input size {} exceeds maximum {}", 
                   encoded.len(), MAX_ENCODED_SIZE);
            return Err(Error::QpackStringTooLong);
        }
        
        // Performance: Pre-allocate with reasonable capacity
        let estimated_size = (encoded.len() as f64 * 1.5) as usize;
        let capacity = estimated_size.min(MAX_INPUT_SIZE);
        let mut result = Vec::with_capacity(capacity);
        
        let mut bit_offset = 0;
        let total_bits = encoded.len() * 8;
        
        while bit_offset < total_bits {
            // Fast path: Try 8-bit lookup first
            if bit_offset % 8 == 0 && bit_offset + 8 <= total_bits {
                let byte_idx = bit_offset / 8;
                let byte = encoded[byte_idx];
                
                if let Some(entry) = self.fast_table[byte as usize] {
                    // Security: Check output size
                    if result.len() >= MAX_INPUT_SIZE {
                        debug!("Huffman decode rejected: output size exceeds maximum");
                        return Err(Error::QpackStringTooLong);
                    }
                    
                    result.push(entry.symbol);
                    bit_offset += entry.bits_consumed as usize;
                    continue;
                }
            }
            
            // Slow path: Bit-by-bit tree traversal
            let decoded_symbol = self.decode_symbol(encoded, &mut bit_offset, total_bits)?;
            
            // Check if we hit padding
            if decoded_symbol.is_none() {
                break;
            }
            
            // Security: Check output size
            if result.len() >= MAX_INPUT_SIZE {
                debug!("Huffman decode rejected: output size exceeds maximum");
                return Err(Error::QpackStringTooLong);
            }
            
            result.push(decoded_symbol.unwrap());
        }
        
        // Log compression ratio for monitoring
        let compression_ratio = encoded.len() as f64 / result.len().max(1) as f64;
        if compression_ratio > MIN_COMPRESSION_RATIO {
            debug!("Poor Huffman compression ratio: {:.2}", compression_ratio);
        }
        
        Ok(result)
    }
    
    /// Decode a single symbol from the bit stream
    fn decode_symbol(&self, encoded: &[u8], bit_offset: &mut usize, total_bits: usize) -> Result<Option<u8>> {
        let mut node = &self.root;
        let start_offset = *bit_offset;
        
        while *bit_offset < total_bits {
            let byte_idx = *bit_offset / 8;
            let bit_idx = 7 - (*bit_offset % 8);
            let bit = (encoded[byte_idx] >> bit_idx) & 1;
            *bit_offset += 1;
            
            node = if bit == 0 {
                match &node.left {
                    Some(n) => n,
                    None => {
                        // Invalid code - check if it's valid padding
                        *bit_offset = start_offset; // Rewind
                        if self.is_valid_padding(encoded, start_offset, total_bits) {
                            return Ok(None); // Valid padding
                        }
                        return Err(Error::QpackHuffmanError);
                    }
                }
            } else {
                match &node.right {
                    Some(n) => n,
                    None => {
                        // Invalid code - check if it's valid padding
                        *bit_offset = start_offset; // Rewind
                        if self.is_valid_padding(encoded, start_offset, total_bits) {
                            return Ok(None); // Valid padding
                        }
                        return Err(Error::QpackHuffmanError);
                    }
                }
            };
            
            if let Some(symbol) = node.symbol {
                return Ok(Some(symbol));
            }
        }
        
        // Reached end of input without completing a symbol
        // Check if remaining bits form valid padding
        *bit_offset = start_offset; // Rewind
        if self.is_valid_padding(encoded, start_offset, total_bits) {
            Ok(None) // Valid padding
        } else {
            Err(Error::QpackHuffmanError)
        }
    }
    
    /// Check if the remaining bits form valid EOS padding
    fn is_valid_padding(&self, encoded: &[u8], bit_offset: usize, total_bits: usize) -> bool {
        if bit_offset >= total_bits {
            return true; // No padding needed
        }
        
        let padding_bits = total_bits - bit_offset;
        if padding_bits > 7 {
            return false; // Too much padding
        }
        
        // EOS symbol is 0x3FFFFFFF (30 ones)
        // Valid padding must be a prefix of this
        let byte_idx = bit_offset / 8;
        let bit_idx = bit_offset % 8;
        let mask = (0xFF >> bit_idx) as u8;
        let expected = mask; // All ones
        
        (encoded[byte_idx] & mask) == expected
    }
}

/// Production-grade Huffman encoder with security and performance optimizations
pub struct HuffmanEncoder;

impl HuffmanEncoder {
    /// Encode data using Huffman coding with production-grade error handling
    pub fn encode(data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        
        // Security: Prevent DoS through large inputs
        if data.len() > MAX_INPUT_SIZE {
            debug!("Huffman encode rejected: input size {} exceeds maximum {}", 
                   data.len(), MAX_INPUT_SIZE);
            return Err(Error::QpackStringTooLong);
        }
        
        // Calculate exact output size
        let output_bits = Self::calculate_output_bits(data);
        let output_bytes = (output_bits + 7) / 8;
        
        // Security: Check output size limit
        if output_bytes > MAX_ENCODED_SIZE {
            debug!("Huffman encode rejected: output size {} exceeds maximum {}", 
                   output_bytes, MAX_ENCODED_SIZE);
            return Err(Error::QpackStringTooLong);
        }
        
        // Allocate exact size to avoid reallocation
        let mut result = vec![0u8; output_bytes];
        let mut bit_offset = 0;
        
        // Encode each byte
        for &byte in data {
            let entry = &HUFFMAN_ENCODE_TABLE[byte as usize];
            Self::write_bits(&mut result, &mut bit_offset, entry.code, entry.bits);
        }
        
        // Add EOS padding if necessary
        let padding_bits = (8 - (output_bits % 8)) % 8;
        if padding_bits > 0 {
            // EOS symbol is all ones - write padding_bits ones
            let padding = (1u32 << padding_bits) - 1;
            Self::write_bits(&mut result, &mut bit_offset, padding, padding_bits as u8);
        }
        
        // Log compression ratio for monitoring
        let compression_ratio = result.len() as f64 / data.len() as f64;
        if compression_ratio > MIN_COMPRESSION_RATIO {
            debug!("Poor Huffman compression ratio: {:.2}", compression_ratio);
        }
        
        Ok(result)
    }
    
    /// Calculate the total output bits for encoding
    fn calculate_output_bits(data: &[u8]) -> usize {
        let mut total_bits = 0;
        for &byte in data {
            total_bits += HUFFMAN_ENCODE_TABLE[byte as usize].bits as usize;
        }
        total_bits
    }
    
    /// Write bits to the output buffer with optimized bit manipulation
    #[inline(always)]
    fn write_bits(output: &mut [u8], bit_offset: &mut usize, mut value: u32, bits: u8) {
        let mut remaining_bits = bits as usize;
        
        while remaining_bits > 0 {
            let byte_idx = *bit_offset / 8;
            let bit_idx = *bit_offset % 8;
            let bits_available = 8 - bit_idx;
            let bits_to_write = remaining_bits.min(bits_available);
            
            // Extract and write bits
            let shift = remaining_bits - bits_to_write;
            let mask = (1u32 << bits_to_write) - 1;
            let bits_value = ((value >> shift) & mask) as u8;
            
            output[byte_idx] |= bits_value << (bits_available - bits_to_write);
            
            *bit_offset += bits_to_write;
            remaining_bits -= bits_to_write;
            value &= (1u32 << shift) - 1;
        }
    }
    
    /// Calculate the encoded size for a given input
    /// Returns None if the encoded size would exceed limits
    pub fn encoded_size(data: &[u8]) -> Option<usize> {
        if data.len() > MAX_INPUT_SIZE {
            return None;
        }
        
        let output_bits = Self::calculate_output_bits(data);
        let size = (output_bits + 7) / 8;
        
        if size > MAX_ENCODED_SIZE {
            None
        } else {
            Some(size)
        }
    }
}

/// Global Huffman decoder instance  
static HUFFMAN_DECODER: LazyLock<HuffmanDecoder> = LazyLock::new(HuffmanDecoder::new);

/// Production-grade API: Encode data using Huffman coding
/// 
/// # Arguments
/// * `data` - The data to encode
/// 
/// # Returns
/// * `Ok(Vec<u8>)` - The encoded data
/// * `Err(Error)` - If encoding fails (e.g., input too large)
/// 
/// # Examples
/// ```
/// let encoded = huffman::encode(b"hello world")?;
/// ```
pub fn encode(data: &[u8]) -> Result<Vec<u8>> {
    HuffmanEncoder::encode(data)
}

/// Production-grade API: Decode Huffman-encoded data
/// 
/// # Arguments
/// * `encoded` - The Huffman-encoded data
/// 
/// # Returns
/// * `Ok(Vec<u8>)` - The decoded data
/// * `Err(Error)` - If decoding fails (e.g., invalid encoding)
/// 
/// # Examples
/// ```
/// let decoded = huffman::decode(&encoded)?;
/// ```
pub fn decode(encoded: &[u8]) -> Result<Vec<u8>> {
    HUFFMAN_DECODER.decode(encoded)
}

/// Production-grade API: Calculate encoded size without encoding
/// 
/// # Arguments
/// * `data` - The data to calculate size for
/// 
/// # Returns
/// * `Some(usize)` - The encoded size in bytes
/// * `None` - If the encoded size would exceed limits
pub fn encoded_size(data: &[u8]) -> Option<usize> {
    HuffmanEncoder::encoded_size(data)
}

/// RFC 7541 Appendix B: Huffman Code Table
/// Complete table with all 257 entries (256 bytes + EOS)
const HUFFMAN_ENCODE_TABLE: [HuffmanSymbol; 257] = [
    // Generated from RFC 7541 Appendix B
    HuffmanSymbol { code: 0x1ff8, bits: 13 },     // 0
    HuffmanSymbol { code: 0x7fffd8, bits: 23 },   // 1
    HuffmanSymbol { code: 0xfffffe2, bits: 28 },  // 2
    HuffmanSymbol { code: 0xfffffe3, bits: 28 },  // 3
    HuffmanSymbol { code: 0xfffffe4, bits: 28 },  // 4
    HuffmanSymbol { code: 0xfffffe5, bits: 28 },  // 5
    HuffmanSymbol { code: 0xfffffe6, bits: 28 },  // 6
    HuffmanSymbol { code: 0xfffffe7, bits: 28 },  // 7
    HuffmanSymbol { code: 0xfffffe8, bits: 28 },  // 8
    HuffmanSymbol { code: 0xffffea, bits: 24 },   // 9 '\t'
    HuffmanSymbol { code: 0x3ffffffc, bits: 30 }, // 10 '\n'
    HuffmanSymbol { code: 0xfffffe9, bits: 28 },  // 11
    HuffmanSymbol { code: 0xfffffea, bits: 28 },  // 12
    HuffmanSymbol { code: 0x3ffffffd, bits: 30 }, // 13 '\r'
    HuffmanSymbol { code: 0xfffffeb, bits: 28 },  // 14
    HuffmanSymbol { code: 0xfffffec, bits: 28 },  // 15
    HuffmanSymbol { code: 0xfffffed, bits: 28 },  // 16
    HuffmanSymbol { code: 0xfffffee, bits: 28 },  // 17
    HuffmanSymbol { code: 0xfffffef, bits: 28 },  // 18
    HuffmanSymbol { code: 0xffffff0, bits: 28 },  // 19
    HuffmanSymbol { code: 0xffffff1, bits: 28 },  // 20
    HuffmanSymbol { code: 0xffffff2, bits: 28 },  // 21
    HuffmanSymbol { code: 0x3ffffffe, bits: 30 }, // 22
    HuffmanSymbol { code: 0xffffff3, bits: 28 },  // 23
    HuffmanSymbol { code: 0xffffff4, bits: 28 },  // 24
    HuffmanSymbol { code: 0xffffff5, bits: 28 },  // 25
    HuffmanSymbol { code: 0xffffff6, bits: 28 },  // 26
    HuffmanSymbol { code: 0xffffff7, bits: 28 },  // 27
    HuffmanSymbol { code: 0xffffff8, bits: 28 },  // 28
    HuffmanSymbol { code: 0xffffff9, bits: 28 },  // 29
    HuffmanSymbol { code: 0xffffffa, bits: 28 },  // 30
    HuffmanSymbol { code: 0xffffffb, bits: 28 },  // 31
    HuffmanSymbol { code: 0x14, bits: 6 },        // 32 ' '
    HuffmanSymbol { code: 0x3f8, bits: 10 },      // 33 '!'
    HuffmanSymbol { code: 0x3f9, bits: 10 },      // 34 '"'
    HuffmanSymbol { code: 0xffa, bits: 12 },      // 35 '#'
    HuffmanSymbol { code: 0x1ff9, bits: 13 },     // 36 '$'
    HuffmanSymbol { code: 0x15, bits: 6 },        // 37 '%'
    HuffmanSymbol { code: 0xf8, bits: 8 },        // 38 '&'
    HuffmanSymbol { code: 0x7fa, bits: 11 },      // 39 '\''
    HuffmanSymbol { code: 0x3fa, bits: 10 },      // 40 '('
    HuffmanSymbol { code: 0x3fb, bits: 10 },      // 41 ')'
    HuffmanSymbol { code: 0xf9, bits: 8 },        // 42 '*'
    HuffmanSymbol { code: 0x7fb, bits: 11 },      // 43 '+'
    HuffmanSymbol { code: 0xfa, bits: 8 },        // 44 ','
    HuffmanSymbol { code: 0x16, bits: 6 },        // 45 '-'
    HuffmanSymbol { code: 0x17, bits: 6 },        // 46 '.'
    HuffmanSymbol { code: 0x18, bits: 6 },        // 47 '/'
    HuffmanSymbol { code: 0x0, bits: 5 },         // 48 '0'
    HuffmanSymbol { code: 0x1, bits: 5 },         // 49 '1'
    HuffmanSymbol { code: 0x2, bits: 5 },         // 50 '2'
    HuffmanSymbol { code: 0x19, bits: 6 },        // 51 '3'
    HuffmanSymbol { code: 0x1a, bits: 6 },        // 52 '4'
    HuffmanSymbol { code: 0x1b, bits: 6 },        // 53 '5'
    HuffmanSymbol { code: 0x1c, bits: 6 },        // 54 '6'
    HuffmanSymbol { code: 0x1d, bits: 6 },        // 55 '7'
    HuffmanSymbol { code: 0x1e, bits: 6 },        // 56 '8'
    HuffmanSymbol { code: 0x1f, bits: 6 },        // 57 '9'
    HuffmanSymbol { code: 0x5c, bits: 7 },        // 58 ':'
    HuffmanSymbol { code: 0xfb, bits: 8 },        // 59 ';'
    HuffmanSymbol { code: 0x7ffc, bits: 15 },     // 60 '<'
    HuffmanSymbol { code: 0x20, bits: 6 },        // 61 '='
    HuffmanSymbol { code: 0xffb, bits: 12 },      // 62 '>'
    HuffmanSymbol { code: 0x3fc, bits: 10 },      // 63 '?'
    HuffmanSymbol { code: 0x1ffa, bits: 13 },     // 64 '@'
    HuffmanSymbol { code: 0x21, bits: 6 },        // 65 'A'
    HuffmanSymbol { code: 0x5d, bits: 7 },        // 66 'B'
    HuffmanSymbol { code: 0x5e, bits: 7 },        // 67 'C'
    HuffmanSymbol { code: 0x5f, bits: 7 },        // 68 'D'
    HuffmanSymbol { code: 0x60, bits: 7 },        // 69 'E'
    HuffmanSymbol { code: 0x61, bits: 7 },        // 70 'F'
    HuffmanSymbol { code: 0x62, bits: 7 },        // 71 'G'
    HuffmanSymbol { code: 0x63, bits: 7 },        // 72 'H'
    HuffmanSymbol { code: 0x64, bits: 7 },        // 73 'I'
    HuffmanSymbol { code: 0x65, bits: 7 },        // 74 'J'
    HuffmanSymbol { code: 0x66, bits: 7 },        // 75 'K'
    HuffmanSymbol { code: 0x67, bits: 7 },        // 76 'L'
    HuffmanSymbol { code: 0x68, bits: 7 },        // 77 'M'
    HuffmanSymbol { code: 0x69, bits: 7 },        // 78 'N'
    HuffmanSymbol { code: 0x6a, bits: 7 },        // 79 'O'
    HuffmanSymbol { code: 0x6b, bits: 7 },        // 80 'P'
    HuffmanSymbol { code: 0x6c, bits: 7 },        // 81 'Q'
    HuffmanSymbol { code: 0x6d, bits: 7 },        // 82 'R'
    HuffmanSymbol { code: 0x6e, bits: 7 },        // 83 'S'
    HuffmanSymbol { code: 0x6f, bits: 7 },        // 84 'T'
    HuffmanSymbol { code: 0x70, bits: 7 },        // 85 'U'
    HuffmanSymbol { code: 0x71, bits: 7 },        // 86 'V'
    HuffmanSymbol { code: 0x72, bits: 7 },        // 87 'W'
    HuffmanSymbol { code: 0xfc, bits: 8 },        // 88 'X'
    HuffmanSymbol { code: 0x73, bits: 7 },        // 89 'Y'
    HuffmanSymbol { code: 0xfd, bits: 8 },        // 90 'Z'
    HuffmanSymbol { code: 0x1ffb, bits: 13 },     // 91 '['
    HuffmanSymbol { code: 0x7fff0, bits: 19 },    // 92 '\\'
    HuffmanSymbol { code: 0x1ffc, bits: 13 },     // 93 ']'
    HuffmanSymbol { code: 0x3ffc, bits: 14 },     // 94 '^'
    HuffmanSymbol { code: 0x22, bits: 6 },        // 95 '_'
    HuffmanSymbol { code: 0x7ffd, bits: 15 },     // 96 '`'
    HuffmanSymbol { code: 0x3, bits: 5 },         // 97 'a'
    HuffmanSymbol { code: 0x23, bits: 6 },        // 98 'b'
    HuffmanSymbol { code: 0x4, bits: 5 },         // 99 'c'
    HuffmanSymbol { code: 0x24, bits: 6 },        // 100 'd'
    HuffmanSymbol { code: 0x5, bits: 5 },         // 101 'e'
    HuffmanSymbol { code: 0x25, bits: 6 },        // 102 'f'
    HuffmanSymbol { code: 0x26, bits: 6 },        // 103 'g'
    HuffmanSymbol { code: 0x27, bits: 6 },        // 104 'h'
    HuffmanSymbol { code: 0x6, bits: 5 },         // 105 'i'
    HuffmanSymbol { code: 0x74, bits: 7 },        // 106 'j'
    HuffmanSymbol { code: 0x75, bits: 7 },        // 107 'k'
    HuffmanSymbol { code: 0x28, bits: 6 },        // 108 'l'
    HuffmanSymbol { code: 0x29, bits: 6 },        // 109 'm'
    HuffmanSymbol { code: 0x2a, bits: 6 },        // 110 'n'
    HuffmanSymbol { code: 0x7, bits: 5 },         // 111 'o'
    HuffmanSymbol { code: 0x2b, bits: 6 },        // 112 'p'
    HuffmanSymbol { code: 0x76, bits: 7 },        // 113 'q'
    HuffmanSymbol { code: 0x2c, bits: 6 },        // 114 'r'
    HuffmanSymbol { code: 0x8, bits: 5 },         // 115 's'
    HuffmanSymbol { code: 0x9, bits: 5 },         // 116 't'
    HuffmanSymbol { code: 0x2d, bits: 6 },        // 117 'u'
    HuffmanSymbol { code: 0x77, bits: 7 },        // 118 'v'
    HuffmanSymbol { code: 0x78, bits: 7 },        // 119 'w'
    HuffmanSymbol { code: 0x79, bits: 7 },        // 120 'x'
    HuffmanSymbol { code: 0x7a, bits: 7 },        // 121 'y'
    HuffmanSymbol { code: 0x7b, bits: 7 },        // 122 'z'
    HuffmanSymbol { code: 0x7ffe, bits: 15 },     // 123 '{'
    HuffmanSymbol { code: 0x7fc, bits: 11 },      // 124 '|'
    HuffmanSymbol { code: 0x3ffd, bits: 14 },     // 125 '}'
    HuffmanSymbol { code: 0x1ffd, bits: 13 },     // 126 '~'
    HuffmanSymbol { code: 0xffffffc, bits: 28 },  // 127
    HuffmanSymbol { code: 0xfffe6, bits: 20 },    // 128
    HuffmanSymbol { code: 0x3fffd2, bits: 22 },   // 129
    HuffmanSymbol { code: 0xfffe7, bits: 20 },    // 130
    HuffmanSymbol { code: 0xfffe8, bits: 20 },    // 131
    HuffmanSymbol { code: 0x3fffd3, bits: 22 },   // 132
    HuffmanSymbol { code: 0x3fffd4, bits: 22 },   // 133
    HuffmanSymbol { code: 0x3fffd5, bits: 22 },   // 134
    HuffmanSymbol { code: 0x7fffd9, bits: 23 },   // 135
    HuffmanSymbol { code: 0x3fffd6, bits: 22 },   // 136
    HuffmanSymbol { code: 0x7fffda, bits: 23 },   // 137
    HuffmanSymbol { code: 0x7fffdb, bits: 23 },   // 138
    HuffmanSymbol { code: 0x7fffdc, bits: 23 },   // 139
    HuffmanSymbol { code: 0x7fffdd, bits: 23 },   // 140
    HuffmanSymbol { code: 0x7fffde, bits: 23 },   // 141
    HuffmanSymbol { code: 0xffffeb, bits: 24 },   // 142
    HuffmanSymbol { code: 0x7fffdf, bits: 23 },   // 143
    HuffmanSymbol { code: 0xffffec, bits: 24 },   // 144
    HuffmanSymbol { code: 0xffffed, bits: 24 },   // 145
    HuffmanSymbol { code: 0x3fffd7, bits: 22 },   // 146
    HuffmanSymbol { code: 0x7fffe0, bits: 23 },   // 147
    HuffmanSymbol { code: 0xffffee, bits: 24 },   // 148
    HuffmanSymbol { code: 0x7fffe1, bits: 23 },   // 149
    HuffmanSymbol { code: 0x7fffe2, bits: 23 },   // 150
    HuffmanSymbol { code: 0x7fffe3, bits: 23 },   // 151
    HuffmanSymbol { code: 0x7fffe4, bits: 23 },   // 152
    HuffmanSymbol { code: 0x1fffdc, bits: 21 },   // 153
    HuffmanSymbol { code: 0x3fffd8, bits: 22 },   // 154
    HuffmanSymbol { code: 0x7fffe5, bits: 23 },   // 155
    HuffmanSymbol { code: 0x3fffd9, bits: 22 },   // 156
    HuffmanSymbol { code: 0x7fffe6, bits: 23 },   // 157
    HuffmanSymbol { code: 0x7fffe7, bits: 23 },   // 158
    HuffmanSymbol { code: 0xffffef, bits: 24 },   // 159
    HuffmanSymbol { code: 0x3fffda, bits: 22 },   // 160
    HuffmanSymbol { code: 0x1fffdd, bits: 21 },   // 161
    HuffmanSymbol { code: 0xfffe9, bits: 20 },    // 162
    HuffmanSymbol { code: 0x3fffdb, bits: 22 },   // 163
    HuffmanSymbol { code: 0x3fffdc, bits: 22 },   // 164
    HuffmanSymbol { code: 0x7fffe8, bits: 23 },   // 165
    HuffmanSymbol { code: 0x7fffe9, bits: 23 },   // 166
    HuffmanSymbol { code: 0x1fffde, bits: 21 },   // 167
    HuffmanSymbol { code: 0x7fffea, bits: 23 },   // 168
    HuffmanSymbol { code: 0x3fffdd, bits: 22 },   // 169
    HuffmanSymbol { code: 0x3fffde, bits: 22 },   // 170
    HuffmanSymbol { code: 0xfffff0, bits: 24 },   // 171
    HuffmanSymbol { code: 0x1fffdf, bits: 21 },   // 172
    HuffmanSymbol { code: 0x3fffdf, bits: 22 },   // 173
    HuffmanSymbol { code: 0x7fffeb, bits: 23 },   // 174
    HuffmanSymbol { code: 0x7fffec, bits: 23 },   // 175
    HuffmanSymbol { code: 0x1fffe0, bits: 21 },   // 176
    HuffmanSymbol { code: 0x1fffe1, bits: 21 },   // 177
    HuffmanSymbol { code: 0x3fffe0, bits: 22 },   // 178
    HuffmanSymbol { code: 0x1fffe2, bits: 21 },   // 179
    HuffmanSymbol { code: 0x7fffed, bits: 23 },   // 180
    HuffmanSymbol { code: 0x3fffe1, bits: 22 },   // 181
    HuffmanSymbol { code: 0x7fffee, bits: 23 },   // 182
    HuffmanSymbol { code: 0x7fffef, bits: 23 },   // 183
    HuffmanSymbol { code: 0xfffea, bits: 20 },    // 184
    HuffmanSymbol { code: 0x3fffe2, bits: 22 },   // 185
    HuffmanSymbol { code: 0x3fffe3, bits: 22 },   // 186
    HuffmanSymbol { code: 0x3fffe4, bits: 22 },   // 187
    HuffmanSymbol { code: 0x7ffff0, bits: 23 },   // 188
    HuffmanSymbol { code: 0x3fffe5, bits: 22 },   // 189
    HuffmanSymbol { code: 0x3fffe6, bits: 22 },   // 190
    HuffmanSymbol { code: 0x7ffff1, bits: 23 },   // 191
    HuffmanSymbol { code: 0x3ffffe0, bits: 26 },  // 192
    HuffmanSymbol { code: 0x3ffffe1, bits: 26 },  // 193
    HuffmanSymbol { code: 0xfffeb, bits: 20 },    // 194
    HuffmanSymbol { code: 0x7fff1, bits: 19 },    // 195
    HuffmanSymbol { code: 0x3fffe7, bits: 22 },   // 196
    HuffmanSymbol { code: 0x7ffff2, bits: 23 },   // 197
    HuffmanSymbol { code: 0x3fffe8, bits: 22 },   // 198
    HuffmanSymbol { code: 0x1ffffec, bits: 25 },  // 199
    HuffmanSymbol { code: 0x3ffffe2, bits: 26 },  // 200
    HuffmanSymbol { code: 0x3ffffe3, bits: 26 },  // 201
    HuffmanSymbol { code: 0x3ffffe4, bits: 26 },  // 202
    HuffmanSymbol { code: 0x7ffffde, bits: 27 },  // 203
    HuffmanSymbol { code: 0x7ffffdf, bits: 27 },  // 204
    HuffmanSymbol { code: 0x3ffffe5, bits: 26 },  // 205
    HuffmanSymbol { code: 0xfffff1, bits: 24 },   // 206
    HuffmanSymbol { code: 0x1ffffed, bits: 25 },  // 207
    HuffmanSymbol { code: 0x7fff2, bits: 19 },    // 208
    HuffmanSymbol { code: 0x1fffe3, bits: 21 },   // 209
    HuffmanSymbol { code: 0x3ffffe6, bits: 26 },  // 210
    HuffmanSymbol { code: 0x7ffffe0, bits: 27 },  // 211
    HuffmanSymbol { code: 0x7ffffe1, bits: 27 },  // 212
    HuffmanSymbol { code: 0x3ffffe7, bits: 26 },  // 213
    HuffmanSymbol { code: 0x7ffffe2, bits: 27 },  // 214
    HuffmanSymbol { code: 0xfffff2, bits: 24 },   // 215
    HuffmanSymbol { code: 0x1fffe4, bits: 21 },   // 216
    HuffmanSymbol { code: 0x1fffe5, bits: 21 },   // 217
    HuffmanSymbol { code: 0x3ffffe8, bits: 26 },  // 218
    HuffmanSymbol { code: 0x3ffffe9, bits: 26 },  // 219
    HuffmanSymbol { code: 0xffffffd, bits: 28 },  // 220
    HuffmanSymbol { code: 0x7ffffe3, bits: 27 },  // 221
    HuffmanSymbol { code: 0x7ffffe4, bits: 27 },  // 222
    HuffmanSymbol { code: 0x7ffffe5, bits: 27 },  // 223
    HuffmanSymbol { code: 0xfffec, bits: 20 },    // 224
    HuffmanSymbol { code: 0xfffff3, bits: 24 },   // 225
    HuffmanSymbol { code: 0xfffed, bits: 20 },    // 226
    HuffmanSymbol { code: 0x1fffe6, bits: 21 },   // 227
    HuffmanSymbol { code: 0x3fffe9, bits: 22 },   // 228
    HuffmanSymbol { code: 0x1fffe7, bits: 21 },   // 229
    HuffmanSymbol { code: 0x1fffe8, bits: 21 },   // 230
    HuffmanSymbol { code: 0x7ffff3, bits: 23 },   // 231
    HuffmanSymbol { code: 0x3fffea, bits: 22 },   // 232
    HuffmanSymbol { code: 0x3fffeb, bits: 22 },   // 233
    HuffmanSymbol { code: 0x1ffffee, bits: 25 },  // 234
    HuffmanSymbol { code: 0x1ffffef, bits: 25 },  // 235
    HuffmanSymbol { code: 0xfffff4, bits: 24 },   // 236
    HuffmanSymbol { code: 0xfffff5, bits: 24 },   // 237
    HuffmanSymbol { code: 0x3ffffea, bits: 26 },  // 238
    HuffmanSymbol { code: 0x7ffff4, bits: 23 },   // 239
    HuffmanSymbol { code: 0x3ffffeb, bits: 26 },  // 240
    HuffmanSymbol { code: 0x7ffffe6, bits: 27 },  // 241
    HuffmanSymbol { code: 0x3ffffec, bits: 26 },  // 242
    HuffmanSymbol { code: 0x3ffffed, bits: 26 },  // 243
    HuffmanSymbol { code: 0x7ffffe7, bits: 27 },  // 244
    HuffmanSymbol { code: 0x7ffffe8, bits: 27 },  // 245
    HuffmanSymbol { code: 0x7ffffe9, bits: 27 },  // 246
    HuffmanSymbol { code: 0x7ffffea, bits: 27 },  // 247
    HuffmanSymbol { code: 0x7ffffeb, bits: 27 },  // 248
    HuffmanSymbol { code: 0xffffffe, bits: 28 },  // 249
    HuffmanSymbol { code: 0x7ffffec, bits: 27 },  // 250
    HuffmanSymbol { code: 0x7ffffed, bits: 27 },  // 251
    HuffmanSymbol { code: 0x7ffffee, bits: 27 },  // 252
    HuffmanSymbol { code: 0x7ffffef, bits: 27 },  // 253
    HuffmanSymbol { code: 0x7fffff0, bits: 27 },  // 254
    HuffmanSymbol { code: 0x3ffffee, bits: 26 },  // 255
    HuffmanSymbol { code: 0x3fffffff, bits: 30 }, // 256 EOS
];

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encode_decode_roundtrip() {
        let test_cases: Vec<&[u8]> = vec![
            b"",
            b"a",
            b"hello world",
            b"The quick brown fox jumps over the lazy dog",
            b"HTTP/3",
            b"content-type: application/json",
        ];
        
        for case in test_cases {
            let encoded = encode(case).unwrap();
            let decoded = decode(&encoded).unwrap();
            assert_eq!(decoded, case);
        }
    }
    
    #[test]
    fn test_size_limits() {
        // Test input size limit
        let large_input = vec![b'a'; MAX_INPUT_SIZE + 1];
        assert!(encode(&large_input).is_err());
        
        // Test encoded size limit  
        let large_encoded = vec![0xFF; MAX_ENCODED_SIZE + 1];
        assert!(decode(&large_encoded).is_err());
    }
    
    #[test]
    fn test_padding_validation() {
        // Test that a string with valid padding decodes correctly
        let data = b"a"; // Single character
        let encoded = encode(data).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, data);
        
        // Test that invalid padding in the middle of a sequence is rejected
        // This creates an invalid Huffman sequence that should fail
        let invalid_sequence = vec![0x00, 0x00]; // Invalid Huffman codes
        assert!(decode(&invalid_sequence).is_err());
    }
    
    #[test]
    fn test_encoded_size_calculation() {
        let data = b"hello";
        let encoded = encode(data).unwrap();
        let calculated_size = encoded_size(data).unwrap();
        assert_eq!(encoded.len(), calculated_size);
    }
    
    #[test]
    fn test_compression_ratio() {
        // Common strings should compress well
        let common = b"www.example.com";
        let encoded = encode(common).unwrap();
        let ratio = encoded.len() as f64 / common.len() as f64;
        assert!(ratio < 0.9); // Should achieve at least 10% compression
    }
}