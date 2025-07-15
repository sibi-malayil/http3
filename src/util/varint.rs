use bytes::{Buf, BufMut};
use std::fmt;
use thiserror::Error;

#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
#[error("value {value} out of range for varint encoding")]
/// Error when a variable integer value exceeds maximum bounds
pub struct VarIntBoundsExceeded {
    /// The value that exceeded bounds
    pub value: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
/// Variable-length integer encoding for QUIC and HTTP/3
/// 
/// Encodes integers from 0 to 2^62-1 using 1, 2, 4, or 8 bytes.
pub struct VarInt(pub u64);

impl VarInt {
    /// Maximum value that can be encoded as a VarInt
    pub const MAX: VarInt = VarInt((1 << 62) - 1);
    /// Zero value constant
    pub const ZERO: VarInt = VarInt(0);

    #[inline]
    /// Create a VarInt from a u32 value
    #[must_use]
    pub const fn from_u32(value: u32) -> Self {
        VarInt(value as u64)
    }

    #[inline]
    /// Create a VarInt from a u64 value, checking bounds
    /// 
    /// # Errors
    /// 
    /// Returns an error if the value exceeds the maximum VarInt value.
    pub const fn from_u64(value: u64) -> Result<Self, VarIntBoundsExceeded> {
        if value <= Self::MAX.0 {
            Ok(VarInt(value))
        } else {
            Err(VarIntBoundsExceeded { value })
        }
    }

    #[inline]
    /// Extract the inner u64 value
    #[must_use]
    pub const fn into_inner(self) -> u64 {
        self.0
    }

    #[inline]
    /// Get the number of bytes this VarInt will encode to
    #[must_use]
    pub const fn size(self) -> usize {
        let x = self.0;
        if x < 2_u64.pow(6) {
            1
        } else if x < 2_u64.pow(14) {
            2
        } else if x < 2_u64.pow(30) {
            4
        } else {
            8
        }
    }

    /// Decode a VarInt from a buffer
    /// 
    /// # Errors
    /// 
    /// Returns an error if the buffer has insufficient data or contains invalid encoding.
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self, VarIntDecodeError> {
        if !buf.has_remaining() {
            return Err(VarIntDecodeError::UnexpectedEnd);
        }

        let first_byte = buf.get_u8();
        let tag = first_byte >> 6;
        let first_byte = first_byte & 0x3F;

        let value = match tag {
            0b00 => first_byte as u64,
            0b01 => {
                if buf.remaining() < 1 {
                    return Err(VarIntDecodeError::UnexpectedEnd);
                }
                ((first_byte as u64) << 8) | (buf.get_u8() as u64)
            }
            0b10 => {
                if buf.remaining() < 3 {
                    return Err(VarIntDecodeError::UnexpectedEnd);
                }
                ((first_byte as u64) << 24)
                    | ((buf.get_u8() as u64) << 16)
                    | ((buf.get_u8() as u64) << 8)
                    | (buf.get_u8() as u64)
            }
            0b11 => {
                if buf.remaining() < 7 {
                    return Err(VarIntDecodeError::UnexpectedEnd);
                }
                ((first_byte as u64) << 56)
                    | ((buf.get_u8() as u64) << 48)
                    | ((buf.get_u8() as u64) << 40)
                    | ((buf.get_u8() as u64) << 32)
                    | ((buf.get_u8() as u64) << 24)
                    | ((buf.get_u8() as u64) << 16)
                    | ((buf.get_u8() as u64) << 8)
                    | (buf.get_u8() as u64)
            }
            _ => unreachable!(),
        };

        Ok(VarInt(value))
    }

    /// Encode this VarInt into a buffer
    /// 
    /// # Errors
    /// 
    /// Returns an error if the value is too large to encode.
    pub fn encode<B: BufMut>(self, buf: &mut B) -> Result<(), VarIntBoundsExceeded> {
        let x = self.0;
        if x < 2_u64.pow(6) {
            buf.put_u8(x as u8);
        } else if x < 2_u64.pow(14) {
            buf.put_u8(0x40 | (x >> 8) as u8);
            buf.put_u8(x as u8);
        } else if x < 2_u64.pow(30) {
            buf.put_u8(0x80 | (x >> 24) as u8);
            buf.put_u8((x >> 16) as u8);
            buf.put_u8((x >> 8) as u8);
            buf.put_u8(x as u8);
        } else {
            buf.put_u8(0xC0 | (x >> 56) as u8);
            buf.put_u8((x >> 48) as u8);
            buf.put_u8((x >> 40) as u8);
            buf.put_u8((x >> 32) as u8);
            buf.put_u8((x >> 24) as u8);
            buf.put_u8((x >> 16) as u8);
            buf.put_u8((x >> 8) as u8);
            buf.put_u8(x as u8);
        }
        Ok(())
    }

    /// Encode with a custom prefix pattern (for QPACK field line representations)
    /// 
    /// # Errors
    /// 
    /// Returns an error if prefix_bits is greater than 8.
    pub fn encode_with_prefix<B: BufMut>(
        self, 
        buf: &mut B, 
        prefix_bits: u8, 
        prefix_pattern: u8
    ) -> Result<(), VarIntBoundsExceeded> {
        if prefix_bits > 8 {
            return Err(VarIntBoundsExceeded { value: prefix_bits as u64 });
        }
        
        let x = self.0;
        let mask = (1u64 << prefix_bits) - 1;
        let max_in_prefix = mask;
        
        if x < max_in_prefix {
            // Value fits in the prefix bits
            buf.put_u8(prefix_pattern | (x as u8));
        } else {
            // Value requires continuation
            buf.put_u8(prefix_pattern | mask as u8);
            let remaining = x - max_in_prefix;
            let _ = VarInt(remaining).encode(buf);
        }
        Ok(())
    }
    
    /// Decode with a custom prefix pattern (for QPACK field line representations)
    /// 
    /// # Errors
    /// 
    /// Returns an error if the buffer has insufficient data or contains invalid encoding.
    pub fn decode_with_prefix<B: Buf>(buf: &mut B, prefix_bits: u8) -> Result<Self, VarIntDecodeError> {
        if !buf.has_remaining() {
            return Err(VarIntDecodeError::UnexpectedEnd);
        }
        
        let first_byte = buf.get_u8();
        let mask = (1u8 << prefix_bits) - 1;
        let prefix_value = first_byte & mask;
        
        if prefix_value < mask {
            // Value is entirely in the prefix
            Ok(VarInt(prefix_value as u64))
        } else {
            // Value continues with varint encoding
            let continuation = VarInt::decode(buf)?;
            Ok(VarInt(prefix_value as u64 + continuation.0))
        }
    }

    /// Get the encoded size of a VarInt from its first byte
    /// 
    /// # Errors
    /// 
    /// Returns an error if the buffer is empty.
    pub fn encoded_size(buf: &[u8]) -> Result<usize, VarIntDecodeError> {
        if buf.is_empty() {
            return Err(VarIntDecodeError::UnexpectedEnd);
        }

        Ok(match buf[0] >> 6 {
            0b00 => 1,
            0b01 => 2,
            0b10 => 4,
            0b11 => 8,
            _ => unreachable!(),
        })
    }
}

#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
/// Error types for VarInt decoding
pub enum VarIntDecodeError {
    /// Input buffer ended unexpectedly
    #[error("unexpected end of buffer")]
    UnexpectedEnd,
}

impl From<u8> for VarInt {
    fn from(value: u8) -> Self {
        VarInt(value as u64)
    }
}

impl From<u16> for VarInt {
    fn from(value: u16) -> Self {
        VarInt(value as u64)
    }
}

impl From<u32> for VarInt {
    fn from(value: u32) -> Self {
        VarInt(value as u64)
    }
}

impl TryFrom<u64> for VarInt {
    type Error = VarIntBoundsExceeded;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        VarInt::from_u64(value)
    }
}

impl TryFrom<usize> for VarInt {
    type Error = VarIntBoundsExceeded;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        VarInt::from_u64(value as u64)
    }
}

impl From<VarInt> for u64 {
    fn from(value: VarInt) -> Self {
        value.0
    }
}

impl fmt::Display for VarInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn varint_encoding_roundtrip() {
        let test_values = [0, 63, 64, 16383, 16384, 1_073_741_823, 1_073_741_824, VarInt::MAX.0];

        for &value in &test_values {
            let varint = VarInt::from_u64(value).unwrap();
            let mut buf = BytesMut::new();
            varint.encode(&mut buf);
            
            let mut buf = buf.freeze();
            let decoded = VarInt::decode(&mut buf).unwrap();
            
            assert_eq!(decoded, varint);
            assert_eq!(decoded.into_inner(), value);
        }
    }

    #[test]
    fn varint_size_calculation() {
        assert_eq!(VarInt::from_u64(0).unwrap().size(), 1);
        assert_eq!(VarInt::from_u64(63).unwrap().size(), 1);
        assert_eq!(VarInt::from_u64(64).unwrap().size(), 2);
        assert_eq!(VarInt::from_u64(16383).unwrap().size(), 2);
        assert_eq!(VarInt::from_u64(16384).unwrap().size(), 4);
        assert_eq!(VarInt::from_u64(1_073_741_823).unwrap().size(), 4);
        assert_eq!(VarInt::from_u64(1_073_741_824).unwrap().size(), 8);
        assert_eq!(VarInt::MAX.size(), 8);
    }

    #[test]
    fn varint_bounds_check() {
        assert!(VarInt::from_u64(VarInt::MAX.0).is_ok());
        assert!(VarInt::from_u64(VarInt::MAX.0 + 1).is_err());
        assert!(VarInt::from_u64(u64::MAX).is_err());
    }
}