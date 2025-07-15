//! QUIC packet structure and parsing
//!
//! Implements packet format from RFC 9000 Section 12.

use crate::{
    error::{Error, Result},
    util::{varint::VarInt, buffer::{BufExt, BufMutExt}},
};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::{fmt, net::SocketAddr};

/// A QUIC packet with header and payload
#[derive(Debug, Clone)]
pub struct Packet {
    /// The packet header
    pub header: PacketHeader,
    /// The packet payload (may be encrypted)
    pub payload: Bytes,
    /// Source address of the packet
    pub src: SocketAddr,
    /// Destination address of the packet  
    pub dst: SocketAddr,
}

impl Packet {
    /// Creates a new packet
    pub fn new(header: PacketHeader, payload: Bytes, src: SocketAddr, dst: SocketAddr) -> Self {
        Self {
            header,
            payload,
            src,
            dst,
        }
    }

    /// Encodes the packet into bytes
    /// 
    /// # Errors
    /// 
    /// Returns an error if header encoding fails.
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        self.header.encode(buf)?;
        buf.put(self.payload.as_ref());
        Ok(())
    }

    /// Decodes a packet from bytes
    /// 
    /// # Errors
    /// 
    /// Returns an error if the packet format is invalid or decoding fails.
    pub fn decode(mut buf: Bytes, src: SocketAddr, dst: SocketAddr) -> Result<Self> {
        let header = PacketHeader::decode(&mut buf)?;
        Ok(Self {
            header,
            payload: buf,
            src,
            dst,
        })
    }

    /// Returns the packet type
    pub fn packet_type(&self) -> PacketType {
        self.header.packet_type()
    }

    /// Returns true if this is a long header packet
    pub fn is_long_header(&self) -> bool {
        matches!(self.header, PacketHeader::Long(_))
    }

    /// Returns the destination connection ID
    pub fn dst_cid(&self) -> &ConnectionId {
        match &self.header {
            PacketHeader::Long(h) => &h.dst_cid,
            PacketHeader::Short(h) => &h.dst_cid,
        }
    }

    /// Returns the source connection ID for long header packets
    pub fn src_cid(&self) -> Option<&ConnectionId> {
        match &self.header {
            PacketHeader::Long(h) => Some(&h.src_cid),
            PacketHeader::Short(_) => None,
        }
    }
    
    /// Returns the packet header
    pub fn header(&self) -> &PacketHeader {
        &self.header
    }
    
    /// Returns the packet payload
    pub fn payload(&self) -> &Bytes {
        &self.payload
    }
}

/// QUIC packet header variants
#[derive(Debug, Clone)]
pub enum PacketHeader {
    /// Long header format for Initial, 0-RTT, Handshake, and Retry packets
    Long(LongHeader),
    /// Short header format for 1-RTT packets
    Short(ShortHeader),
}

impl PacketHeader {
    /// Encodes the header into bytes
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        match self {
            Self::Long(h) => h.encode(buf),
            Self::Short(h) => h.encode(buf),
        }
    }

    /// Decodes a header from bytes
    pub fn decode(buf: &mut Bytes) -> Result<Self> {
        if buf.is_empty() {
            return Err(Error::InvalidPacket("Empty packet".to_string()));
        }

        let first_byte = buf.peek_u8().unwrap();
        if first_byte & 0x80 != 0 {
            // Long header
            Ok(Self::Long(LongHeader::decode(buf)?))
        } else {
            // Short header
            Ok(Self::Short(ShortHeader::decode(buf)?))
        }
    }

    /// Get the destination connection ID
    pub fn destination_cid(&self) -> &ConnectionId {
        match self {
            Self::Long(h) => &h.dst_cid,
            Self::Short(h) => &h.dst_cid,
        }
    }

    /// Get the source connection ID (only for long headers)
    pub fn source_cid(&self) -> Option<&ConnectionId> {
        match self {
            Self::Long(h) => Some(&h.src_cid),
            Self::Short(_) => None,
        }
    }

    /// Returns the packet type
    pub fn packet_type(&self) -> PacketType {
        match self {
            Self::Long(h) => h.packet_type,
            Self::Short(_) => PacketType::OneRtt,
        }
    }

    /// Get the packet number
    pub fn packet_number(&self) -> Option<u32> {
        match self {
            Self::Long(h) => h.type_specific.packet_number(),
            Self::Short(h) => Some(h.packet_number),
        }
    }
}

/// Long header format (RFC 9000 Section 17.2)
#[derive(Debug, Clone)]
pub struct LongHeader {
    /// Packet type
    pub packet_type: PacketType,
    /// Version field
    pub version: u32,
    /// Destination connection ID
    pub dst_cid: ConnectionId,
    /// Source connection ID
    pub src_cid: ConnectionId,
    /// Type-specific data
    pub type_specific: TypeSpecificData,
}

impl LongHeader {
    /// Creates a new long header
    pub fn new(
        packet_type: PacketType,
        version: u32,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        type_specific: TypeSpecificData,
    ) -> Self {
        Self {
            packet_type,
            version,
            dst_cid,
            src_cid,
            type_specific,
        }
    }

    /// Encodes the long header
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        // First byte: Header Form (1) + Fixed Bit (1) + Packet Type (2) + Reserved (2) + Packet Number Length (2)
        
        // Always use 4-byte packet numbers for consistency
        let pn_length = 4;
        
        let first_byte = 0x80 // Header Form = 1 (long header)
            | 0x40 // Fixed Bit = 1
            | ((self.packet_type as u8) << 4)
            | ((pn_length - 1) as u8); // Packet Number Length - 1

        buf.put_u8(first_byte);
        buf.put_u32(self.version);

        // Connection ID lengths
        buf.put_u8(self.dst_cid.len() as u8);
        buf.put(self.dst_cid.as_bytes());
        buf.put_u8(self.src_cid.len() as u8);
        buf.put(self.src_cid.as_bytes());

        // Type-specific data
        self.type_specific.encode(buf)?;

        Ok(())
    }

    /// Decodes a long header
    pub fn decode(buf: &mut Bytes) -> Result<Self> {
        if buf.remaining() < 6 {
            return Err(Error::InvalidPacket("Insufficient data for long header".to_string()));
        }

        let first_byte = buf.get_u8();
        
        // Validate header form and fixed bit
        if first_byte & 0x80 == 0 {
            return Err(Error::InvalidPacket("Invalid header form for long header".to_string()));
        }
        if first_byte & 0x40 == 0 {
            return Err(Error::InvalidPacket("Invalid fixed bit".to_string()));
        }

        let packet_type = PacketType::try_from((first_byte >> 4) & 0x03)?;
        let version = buf.get_u32();

        // Decode connection IDs
        let dst_cid_len = buf.get_u8() as usize;
        if dst_cid_len > crate::quic::MAX_CID_LEN {
            return Err(Error::InvalidPacket("Destination CID too long".to_string()));
        }
        
        if buf.remaining() < dst_cid_len {
            return Err(Error::InvalidPacket("Insufficient data for destination CID".to_string()));
        }
        let dst_cid = ConnectionId::from_bytes(buf.get_bytes(dst_cid_len).unwrap())?;

        let src_cid_len = buf.get_u8() as usize;
        if src_cid_len > crate::quic::MAX_CID_LEN {
            return Err(Error::InvalidPacket("Source CID too long".to_string()));
        }
        
        if buf.remaining() < src_cid_len {
            return Err(Error::InvalidPacket("Insufficient data for source CID".to_string()));
        }
        let src_cid = ConnectionId::from_bytes(buf.get_bytes(src_cid_len).unwrap())?;

        // Decode type-specific data
        let type_specific = TypeSpecificData::decode(packet_type, buf)?;

        Ok(Self {
            packet_type,
            version,
            dst_cid,
            src_cid,
            type_specific,
        })
    }
}

/// Short header format (RFC 9000 Section 17.3)
#[derive(Debug, Clone)]
pub struct ShortHeader {
    /// Spin bit for latency measurement
    pub spin_bit: bool,
    /// Key phase bit for key rotation
    pub key_phase: bool,
    /// Destination connection ID
    pub dst_cid: ConnectionId,
    /// Packet number
    pub packet_number: u32,
}

impl ShortHeader {
    /// Creates a new short header
    pub fn new(spin_bit: bool, key_phase: bool, dst_cid: ConnectionId, packet_number: u32) -> Self {
        Self {
            spin_bit,
            key_phase,
            dst_cid,
            packet_number,
        }
    }

    /// Encodes the short header
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        // First byte: Header Form (0) + Fixed Bit (1) + Spin Bit (1) + Reserved (2) + Key Phase (1) + Packet Number Length (2)
        let first_byte = 0x40 // Fixed Bit = 1
            | if self.spin_bit { 0x20 } else { 0x00 }
            | if self.key_phase { 0x04 } else { 0x00 }
            | 0x03; // Packet Number Length - 1 (4 bytes)

        buf.put_u8(first_byte);
        buf.put(self.dst_cid.as_bytes());
        buf.put_u32(self.packet_number);

        Ok(())
    }

    /// Decodes a short header
    pub fn decode(buf: &mut Bytes) -> Result<Self> {
        if buf.is_empty() {
            return Err(Error::InvalidPacket("Empty buffer for short header".to_string()));
        }

        let first_byte = buf.get_u8();
        
        // Validate header form and fixed bit
        if first_byte & 0x80 != 0 {
            return Err(Error::InvalidPacket("Invalid header form for short header".to_string()));
        }
        if first_byte & 0x40 == 0 {
            return Err(Error::InvalidPacket("Invalid fixed bit".to_string()));
        }

        let spin_bit = (first_byte & 0x20) != 0;
        let key_phase = (first_byte & 0x04) != 0;

        // For short headers, we need to know the CID length from connection state
        // This is a simplified implementation assuming a fixed length
        let dst_cid = ConnectionId::from_bytes(buf.get_bytes(8).ok_or_else(|| {
            Error::InvalidPacket("Insufficient data for destination CID".to_string())
        })?)?;

        let packet_number = buf.get_u32();

        Ok(Self {
            spin_bit,
            key_phase,
            dst_cid,
            packet_number,
        })
    }
}

/// QUIC packet types (RFC 9000 Section 17.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PacketType {
    /// Initial packet for connection establishment
    Initial = 0x00,
    /// 0-RTT packet for early data
    ZeroRtt = 0x01,
    /// Handshake packet for TLS handshake
    Handshake = 0x02,
    /// Retry packet for address validation
    Retry = 0x03,
    /// 1-RTT packet for application data (short header only)
    OneRtt,
}

impl PacketType {
    /// Returns true if this packet type uses long header format
    pub fn is_long_header(self) -> bool {
        !matches!(self, Self::OneRtt)
    }

    /// Returns true if this packet type can carry application data
    pub fn can_carry_app_data(self) -> bool {
        matches!(self, Self::ZeroRtt | Self::OneRtt)
    }
}

impl TryFrom<u8> for PacketType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(Self::Initial),
            0x01 => Ok(Self::ZeroRtt),
            0x02 => Ok(Self::Handshake),
            0x03 => Ok(Self::Retry),
            _ => Err(Error::InvalidPacket(format!("Unknown packet type: {value:#x}"))),
        }
    }
}

/// Type-specific data for long header packets
#[derive(Debug, Clone)]
pub enum TypeSpecificData {
    /// Initial packet data
    Initial {
        /// Token for address validation
        token: Bytes,
        /// Length of packet number + payload
        length: VarInt,
        /// Packet number
        packet_number: u32,
    },
    /// 0-RTT packet data
    ZeroRtt {
        /// Length of packet number + payload
        length: VarInt,
        /// Packet number
        packet_number: u32,
    },
    /// Handshake packet data
    Handshake {
        /// Length of packet number + payload
        length: VarInt,
        /// Packet number
        packet_number: u32,
    },
    /// Retry packet data
    Retry {
        /// Retry token
        retry_token: Bytes,
        /// Retry integrity tag
        retry_integrity_tag: [u8; 16],
    },
}

impl TypeSpecificData {
    /// Encodes type-specific data
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        match self {
            Self::Initial { token, length, packet_number } => {
                buf.put_var(VarInt::try_from(token.len())?);
                buf.put(token.as_ref());
                buf.put_var(*length);
                // Encode packet number with appropriate length
                Self::encode_packet_number(buf, *packet_number);
            }
            Self::ZeroRtt { length, packet_number } => {
                buf.put_var(*length);
                Self::encode_packet_number(buf, *packet_number);
            }
            Self::Handshake { length, packet_number } => {
                buf.put_var(*length);
                Self::encode_packet_number(buf, *packet_number);
            }
            Self::Retry { retry_token, retry_integrity_tag } => {
                buf.put(retry_token.as_ref());
                buf.put_slice(retry_integrity_tag);
            }
        }
        Ok(())
    }
    
    /// Encode packet number with variable length
    fn encode_packet_number(buf: &mut BytesMut, packet_number: u32) {
        // Always use 4 bytes for consistency with header protection
        buf.put_u32(packet_number);
    }

    /// Decodes type-specific data
    pub fn decode(packet_type: PacketType, buf: &mut Bytes) -> Result<Self> {
        match packet_type {
            PacketType::Initial => {
                let token_len = buf.get_var()?.into_inner() as usize;
                let token = buf.get_bytes(token_len).ok_or_else(|| {
                    Error::InvalidPacket("Insufficient data for token".to_string())
                })?;
                let length = buf.get_var()?;
                let packet_number = buf.get_u32();
                
                Ok(Self::Initial { token, length, packet_number })
            }
            PacketType::ZeroRtt => {
                let length = buf.get_var()?;
                let packet_number = buf.get_u32();
                
                Ok(Self::ZeroRtt { length, packet_number })
            }
            PacketType::Handshake => {
                let length = buf.get_var()?;
                let packet_number = buf.get_u32();
                
                Ok(Self::Handshake { length, packet_number })
            }
            PacketType::Retry => {
                if buf.remaining() < 16 {
                    return Err(Error::InvalidPacket("Insufficient data for retry packet".to_string()));
                }
                
                let retry_token_len = buf.remaining() - 16;
                let retry_token = buf.get_bytes(retry_token_len).unwrap();
                
                let mut retry_integrity_tag = [0u8; 16];
                buf.copy_to_slice(&mut retry_integrity_tag);
                
                Ok(Self::Retry { retry_token, retry_integrity_tag })
            }
            PacketType::OneRtt => {
                Err(Error::InvalidPacket("1-RTT packets don't use type-specific data".to_string()))
            }
        }
    }

    /// Returns the packet number if applicable
    pub fn packet_number(&self) -> Option<u32> {
        match self {
            Self::Initial { packet_number, .. } |
            Self::ZeroRtt { packet_number, .. } |
            Self::Handshake { packet_number, .. } => Some(*packet_number),
            Self::Retry { .. } => None,
        }
    }
}

/// Connection ID used to identify QUIC connections
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionId {
    bytes: Bytes,
}

impl ConnectionId {
    /// Creates a new connection ID from bytes
    pub fn from_bytes(bytes: Bytes) -> Result<Self> {
        if bytes.len() > crate::quic::MAX_CID_LEN {
            return Err(Error::InvalidPacket("Connection ID too long".to_string()));
        }
        Ok(Self { bytes })
    }

    /// Creates an empty connection ID
    pub fn empty() -> Self {
        Self {
            bytes: Bytes::new(),
        }
    }
    
    /// Creates a connection ID from a slice
    pub fn from_slice(slice: &[u8]) -> Self {
        Self {
            bytes: Bytes::copy_from_slice(slice),
        }
    }

    /// Generates a random connection ID
    pub fn random(len: usize) -> Result<Self> {
        if len > crate::quic::MAX_CID_LEN {
            return Err(Error::InvalidPacket("Connection ID too long".to_string()));
        }
        
        // Use cryptographically secure random number generation
        let mut bytes = vec![0u8; len];
        use ring::rand::SecureRandom;
        ring::rand::SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| Error::CryptoError("Failed to generate random connection ID".to_string()))?;
        
        Ok(Self {
            bytes: Bytes::from(bytes),
        })
    }

    /// Returns the connection ID as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the length of the connection ID
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns true if the connection ID is empty
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.bytes {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl From<&[u8]> for ConnectionId {
    fn from(bytes: &[u8]) -> Self {
        Self {
            bytes: Bytes::copy_from_slice(bytes),
        }
    }
}

impl From<Vec<u8>> for ConnectionId {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Bytes::from(bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn connection_id_creation() {
        let cid = ConnectionId::from_bytes(Bytes::from_static(b"test")).unwrap();
        assert_eq!(cid.len(), 4);
        assert_eq!(cid.as_bytes(), b"test");
        assert!(!cid.is_empty());

        let empty_cid = ConnectionId::empty();
        assert_eq!(empty_cid.len(), 0);
        assert!(empty_cid.is_empty());
    }

    #[test]
    fn connection_id_random() {
        let cid1 = ConnectionId::random(8).unwrap();
        let cid2 = ConnectionId::random(8).unwrap();
        assert_eq!(cid1.len(), 8);
        assert_eq!(cid2.len(), 8);
        assert_ne!(cid1, cid2); // Should be different (very high probability)
    }

    #[test]
    fn packet_type_properties() {
        assert!(PacketType::Initial.is_long_header());
        assert!(PacketType::ZeroRtt.is_long_header());
        assert!(PacketType::Handshake.is_long_header());
        assert!(PacketType::Retry.is_long_header());
        assert!(!PacketType::OneRtt.is_long_header());

        assert!(!PacketType::Initial.can_carry_app_data());
        assert!(PacketType::ZeroRtt.can_carry_app_data());
        assert!(!PacketType::Handshake.can_carry_app_data());
        assert!(!PacketType::Retry.can_carry_app_data());
        assert!(PacketType::OneRtt.can_carry_app_data());
    }

    #[test]
    fn long_header_encoding_roundtrip() {
        let dst_cid = ConnectionId::from_bytes(Bytes::from_static(b"dest_cid")).unwrap();
        let src_cid = ConnectionId::from_bytes(Bytes::from_static(b"src_cid")).unwrap();
        let type_specific = TypeSpecificData::Initial {
            token: Bytes::from_static(b"token"),
            length: VarInt::from_u32(100),
            packet_number: 12345,
        };

        let header = LongHeader::new(
            PacketType::Initial,
            crate::quic::VERSION_1,
            dst_cid,
            src_cid,
            type_specific,
        );

        let mut buf = BytesMut::new();
        header.encode(&mut buf).unwrap();

        let mut bytes = buf.freeze();
        let decoded = LongHeader::decode(&mut bytes).unwrap();

        assert_eq!(decoded.packet_type, PacketType::Initial);
        assert_eq!(decoded.version, crate::quic::VERSION_1);
        assert_eq!(decoded.dst_cid.as_bytes(), b"dest_cid");
        assert_eq!(decoded.src_cid.as_bytes(), b"src_cid");

        if let TypeSpecificData::Initial { token, length, packet_number } = decoded.type_specific {
            assert_eq!(token.as_ref(), b"token");
            assert_eq!(length.into_inner(), 100);
            assert_eq!(packet_number, 12345);
        } else {
            panic!("Wrong type-specific data");
        }
    }

    #[test]
    fn short_header_encoding_roundtrip() {
        let dst_cid = ConnectionId::from_bytes(Bytes::from_static(b"short_id")).unwrap();
        let header = ShortHeader::new(true, false, dst_cid, 67890);

        let mut buf = BytesMut::new();
        header.encode(&mut buf).unwrap();

        let bytes = buf.freeze();
        // Pad to ensure we have enough bytes for the CID
        let mut padded = BytesMut::from(bytes.as_ref());
        padded.resize(20, 0);
        let mut padded_bytes = padded.freeze();
        
        let decoded = ShortHeader::decode(&mut padded_bytes).unwrap();

        assert_eq!(decoded.spin_bit, true);
        assert_eq!(decoded.key_phase, false);
        assert_eq!(decoded.packet_number, 67890);
    }

    #[test]
    fn packet_creation() {
        let dst_cid = ConnectionId::from_bytes(Bytes::from_static(b"test")).unwrap();
        let src_cid = ConnectionId::from_bytes(Bytes::from_static(b"test2")).unwrap();
        let type_specific = TypeSpecificData::Initial {
            token: Bytes::new(),
            length: VarInt::from_u32(50),
            packet_number: 1,
        };

        let long_header = LongHeader::new(
            PacketType::Initial,
            crate::quic::VERSION_1,
            dst_cid,
            src_cid,
            type_specific,
        );

        let header = PacketHeader::Long(long_header);
        let payload = Bytes::from_static(b"test payload");
        let src_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 12345);
        let dst_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);

        let packet = Packet::new(header, payload, src_addr, dst_addr);

        assert_eq!(packet.packet_type(), PacketType::Initial);
        assert!(packet.is_long_header());
        assert_eq!(packet.dst_cid().as_bytes(), b"test");
        assert_eq!(packet.src_cid().unwrap().as_bytes(), b"test2");
    }
}