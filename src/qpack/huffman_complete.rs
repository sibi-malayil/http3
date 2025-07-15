//! Production-grade Huffman coding implementation for QPACK per RFC 7541 Appendix B
//! 
//! This module provides a complete, efficient implementation of Huffman encoding and
//! decoding for HTTP/3 header compression. It includes:
//! - Full RFC 7541 Huffman table
//! - Optimized encoding with bit-packing
//! - Fast decoding with lookup tables
//! - Comprehensive error handling
//! - Thread-safe global instances
//! - Production-grade performance optimizations

use crate::error::{Error, Result};
use std::sync::LazyLock;

/// Huffman symbol entry in the encoding table
#[derive(Debug, Clone, Copy)]
struct HuffmanSymbol {
    /// The Huffman code for this symbol
    code: u32,
    /// Number of bits in the code
    bits: u8,
}

/// Huffman decoder node for tree-based decoding
#[derive(Debug, Clone)]
struct HuffmanNode {
    /// Symbol value if this is a leaf node
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

/// Huffman decoder using a tree structure for efficient decoding
pub struct HuffmanDecoder {
    /// Root of the Huffman tree
    root: HuffmanNode,
    /// Fast lookup table for common prefixes (8-bit)
    fast_table: [Option<FastDecodeEntry>; 256],
}

/// Fast decode table entry
#[derive(Debug, Clone, Copy)]
struct FastDecodeEntry {
    /// The decoded symbol
    symbol: u8,
    /// Number of bits consumed
    bits_consumed: u8,
}

impl HuffmanDecoder {
    /// Create a new Huffman decoder with the RFC 7541 table
    fn new() -> Self {
        let mut root = HuffmanNode::new_internal();
        let mut fast_table = [None; 256];
        
        // Build the Huffman tree from the encoding table
        for (symbol, entry) in HUFFMAN_ENCODE_TABLE.iter().enumerate() {
            if symbol > 255 {
                break; // Skip EOS symbol
            }
            
            let mut current = &mut root;
            let code = entry.code;
            let bits = entry.bits;
            
            // Navigate/build the tree based on the code bits
            for i in (0..bits).rev() {
                let bit = (code >> i) & 1;
                
                if i == 0 {
                    // Last bit - create leaf node
                    if bit == 0 {
                        current.left = Some(Box::new(HuffmanNode::new_leaf(symbol as u8)));
                    } else {
                        current.right = Some(Box::new(HuffmanNode::new_leaf(symbol as u8)));
                    }
                } else {
                    // Internal node - navigate or create
                    let next_node = if bit == 0 {
                        &mut current.left
                    } else {
                        &mut current.right
                    };
                    
                    if next_node.is_none() {
                        *next_node = Some(Box::new(HuffmanNode::new_internal()));
                    }
                    
                    current = next_node.as_mut().unwrap();
                }
            }
            
            // Populate fast lookup table for codes up to 8 bits
            if bits <= 8 {
                let shift = 8 - bits;
                let base = (code as u8) << shift;
                let count = 1u8 << shift;
                
                for i in 0..count {
                    fast_table[(base | i) as usize] = Some(FastDecodeEntry {
                        symbol: symbol as u8,
                        bits_consumed: bits,
                    });
                }
            }
        }
        
        Self { root, fast_table }
    }
    
    /// Decode Huffman-encoded data
    pub fn decode(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        if encoded.is_empty() {
            return Ok(Vec::new());
        }
        
        let mut result = Vec::with_capacity(encoded.len());
        let mut bit_offset = 0;
        let total_bits = encoded.len() * 8;
        
        while bit_offset < total_bits {
            // Try fast path first
            if bit_offset % 8 == 0 && bit_offset + 8 <= total_bits {
                let byte_idx = bit_offset / 8;
                let byte = encoded[byte_idx];
                
                if let Some(entry) = self.fast_table[byte as usize] {
                    if bit_offset + entry.bits_consumed as usize <= total_bits {
                        result.push(entry.symbol);
                        bit_offset += entry.bits_consumed as usize;
                        continue;
                    }
                }
            }
            
            // Slow path - traverse the tree
            let mut node = &self.root;
            let start_bit_offset = bit_offset;
            
            loop {
                if bit_offset >= total_bits {
                    // Check if we're at a valid padding position
                    if Self::is_valid_padding(&encoded[start_bit_offset / 8..], start_bit_offset % 8) {
                        return Ok(result);
                    }
                    return Err(Error::QpackHuffmanError);
                }
                
                let byte_idx = bit_offset / 8;
                let bit_idx = 7 - (bit_offset % 8);
                let bit = (encoded[byte_idx] >> bit_idx) & 1;
                bit_offset += 1;
                
                node = if bit == 0 {
                    match &node.left {
                        Some(n) => n,
                        None => return Err(Error::QpackHuffmanError),
                    }
                } else {
                    match &node.right {
                        Some(n) => n,
                        None => return Err(Error::QpackHuffmanError),
                    }
                };
                
                if let Some(symbol) = node.symbol {
                    result.push(symbol);
                    break;
                }
            }
        }
        
        // Validate any remaining bits are proper padding
        if bit_offset < total_bits {
            let last_byte_idx = (bit_offset - 1) / 8;
            let bits_in_last_byte = 8 - (bit_offset % 8);
            
            if bits_in_last_byte > 0 && bits_in_last_byte < 8 {
                if !Self::is_valid_padding(&encoded[last_byte_idx..], 8 - bits_in_last_byte) {
                    return Err(Error::QpackHuffmanError);
                }
            }
        }
        
        Ok(result)
    }
    
    /// Check if the remaining bits form valid EOS padding
    fn is_valid_padding(data: &[u8], start_bit: usize) -> bool {
        if data.is_empty() || start_bit >= 8 {
            return true;
        }
        
        // EOS symbol is 0x3FFFFFFF (30 bits of 1s)
        // Valid padding must be a prefix of this
        let first_byte = data[0];
        let mask = (1u8 << (8 - start_bit)) - 1;
        let padding_bits = first_byte & mask;
        
        // All padding bits should be 1
        padding_bits == mask
    }
}

/// Huffman encoder for efficient encoding
pub struct HuffmanEncoder;

impl HuffmanEncoder {
    /// Encode data using Huffman coding
    pub fn encode(data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }
        
        // Calculate the exact output size
        let mut total_bits = 0;
        for &byte in data {
            total_bits += HUFFMAN_ENCODE_TABLE[byte as usize].bits as usize;
        }
        
        // Add padding bits if necessary
        let padding_bits = if total_bits % 8 != 0 { 8 - (total_bits % 8) } else { 0 };
        total_bits += padding_bits;
        
        let mut result = vec![0u8; total_bits / 8];
        let mut bit_offset = 0;
        
        // Encode each byte
        for &byte in data {
            let entry = HUFFMAN_ENCODE_TABLE[byte as usize];
            Self::write_bits(&mut result, &mut bit_offset, entry.code, entry.bits);
        }
        
        // Add EOS padding if necessary
        if padding_bits > 0 {
            // EOS symbol is 0x3FFFFFFF (30 bits)
            // We need only the most significant 'padding_bits' of it
            let padding = 0x3FFF_FFFF >> (30 - padding_bits);
            Self::write_bits(&mut result, &mut bit_offset, padding, padding_bits as u8);
        }
        
        result
    }
    
    /// Write bits to the output buffer
    #[inline]
    fn write_bits(output: &mut [u8], bit_offset: &mut usize, mut value: u32, bits: u8) {
        let mut remaining_bits = bits as usize;
        
        while remaining_bits > 0 {
            let byte_idx = *bit_offset / 8;
            let bit_idx = *bit_offset % 8;
            let bits_available = 8 - bit_idx;
            let bits_to_write = remaining_bits.min(bits_available);
            
            // Extract the bits to write
            let shift = remaining_bits - bits_to_write;
            let bits_value = ((value >> shift) & ((1 << bits_to_write) - 1)) as u8;
            
            // Write to the output buffer
            output[byte_idx] |= bits_value << (bits_available - bits_to_write);
            
            *bit_offset += bits_to_write;
            remaining_bits -= bits_to_write;
            value &= (1 << shift) - 1;
        }
    }
    
    /// Calculate the encoded size for a given input
    pub fn encoded_size(data: &[u8]) -> usize {
        let mut total_bits = 0;
        for &byte in data {
            total_bits += HUFFMAN_ENCODE_TABLE[byte as usize].bits as usize;
        }
        (total_bits + 7) / 8 // Round up to nearest byte
    }
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
    HuffmanSymbol { code: 0xffffea, bits: 24 },   // 9
    HuffmanSymbol { code: 0x3ffffffc, bits: 30 }, // 10
    HuffmanSymbol { code: 0xfffffe9, bits: 28 },  // 11
    HuffmanSymbol { code: 0xfffffea, bits: 28 },  // 12
    HuffmanSymbol { code: 0x3ffffffd, bits: 30 }, // 13
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
    HuffmanSymbol { code: 0x7fff0, bits: 19 },    // 92 '\'
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
    HuffmanSymbol { code: 0x3fffffff, bits: 30 }, // 256 (EOS)
];

/// Global Huffman decoder instance
static HUFFMAN_DECODER: LazyLock<HuffmanDecoder> = LazyLock::new(HuffmanDecoder::new);

/// Encode a byte slice using Huffman coding
pub fn encode(data: &[u8]) -> Vec<u8> {
    HuffmanEncoder::encode(data)
}

/// Decode Huffman-encoded data
pub fn decode(encoded: &[u8]) -> Result<Vec<u8>> {
    HUFFMAN_DECODER.decode(encoded)
}

/// Calculate the encoded size for given data without encoding
pub fn encoded_size(data: &[u8]) -> usize {
    HuffmanEncoder::encoded_size(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_string() {
        let input = b"";
        let encoded = encode(input);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, input);
        assert_eq!(encoded.len(), 0);
    }

    #[test]
    fn test_single_byte() {
        for byte in 0u8..=255 {
            let input = [byte];
            let encoded = encode(&input);
            let decoded = decode(&encoded).unwrap();
            assert_eq!(decoded, input);
        }
    }

    #[test]
    fn test_common_strings() {
        let test_cases: Vec<&[u8]> = vec![
            b"www.example.com",
            b"no-cache",
            b"custom-key",
            b"custom-value",
            b"/index.html",
            b"application/json",
            b"gzip, deflate, br",
            b"Mozilla/5.0 (compatible)",
        ];

        for case in test_cases {
            let encoded = encode(case);
            let decoded = decode(&encoded).unwrap();
            assert_eq!(decoded, case);
        }
    }

    #[test]
    fn test_padding_validation() {
        // Test that invalid padding is rejected
        let invalid_padding = vec![0xFF, 0x00]; // Invalid EOS padding
        assert!(decode(&invalid_padding).is_err());
    }

    #[test]
    fn test_compression_efficiency() {
        // Common strings should compress well
        let input = b"aaaaaaaaaaaaaaa"; // 15 'a' characters
        let encoded = encode(input);
        assert!(encoded.len() < input.len());
    }

    #[test]
    fn test_large_data() {
        let large_input: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
        let encoded = encode(&large_input);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded, large_input);
    }

    #[test]
    fn test_encoded_size_calculation() {
        let test_data = b"test data";
        let actual_encoded = encode(test_data);
        let calculated_size = encoded_size(test_data);
        assert_eq!(actual_encoded.len(), calculated_size);
    }
}