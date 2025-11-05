//! QUIC packet protection and encryption implementation
//!
//! Implements packet protection according to RFC 9001 Section 5.

use crate::{
    error::{Error, Result},
    quic::packet::{Packet, PacketHeader, PacketType},
    crypto::rustls_impl::{EncryptionLevel, PacketKey, HeaderKey, TlsState},
    whathappened::Level,
    crypto_event,
};
use bytes::{Bytes, BytesMut, Buf, BufMut};
use std::collections::HashMap;

/// Packet number spaces as defined in RFC 9000 Section 12.3
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketSpace {
    /// Initial packet space (used for Initial packets)
    Initial,
    /// Handshake packet space (used for Handshake packets)
    Handshake,
    /// Application data packet space (used for 0-RTT and 1-RTT packets)
    ApplicationData,
}

impl PacketSpace {
    /// Returns the encryption level for this packet space
    pub fn encryption_level(self) -> EncryptionLevel {
        match self {
            Self::Initial => EncryptionLevel::Initial,
            Self::Handshake => EncryptionLevel::Handshake,
            Self::ApplicationData => EncryptionLevel::Application,
        }
    }

    /// Returns packet space from packet type
    pub fn from_packet_type(packet_type: PacketType) -> Self {
        match packet_type {
            PacketType::Initial => Self::Initial,
            PacketType::ZeroRtt => Self::ApplicationData,
            PacketType::Handshake => Self::Handshake,
            PacketType::Retry => Self::Initial, // Retry packets use Initial space
            PacketType::OneRtt => Self::ApplicationData,
        }
    }
}

/// Packet number state for a single packet space
#[derive(Debug, Clone)]
pub struct PacketNumberSpace {
    /// Next packet number to send
    next_packet_number: u64,
    /// Largest received packet number
    largest_received_packet_number: Option<u64>,
    /// Largest acknowledged packet number
    largest_acked_packet_number: Option<u64>,
    /// Packet number to length mapping for sent packets
    sent_packet_numbers: HashMap<u64, PacketNumberLength>,
}

impl Default for PacketNumberSpace {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketNumberSpace {
    /// Creates a new packet number space
    pub fn new() -> Self {
        Self {
            next_packet_number: 0,
            largest_received_packet_number: None,
            largest_acked_packet_number: None,
            sent_packet_numbers: HashMap::new(),
        }
    }

    /// Gets the next packet number to send
    pub fn next_packet_number(&self) -> u64 {
        self.next_packet_number
    }

    /// Allocates and returns the next packet number
    pub fn allocate_packet_number(&mut self) -> u64 {
        let pn = self.next_packet_number;
        self.next_packet_number += 1;
        pn
    }

    /// Records a sent packet number with its encoded length
    pub fn record_sent_packet(&mut self, packet_number: u64, length: PacketNumberLength) {
        self.sent_packet_numbers.insert(packet_number, length);
    }

    /// Updates largest received packet number
    pub fn update_largest_received(&mut self, packet_number: u64) {
        self.largest_received_packet_number = Some(
            self.largest_received_packet_number
                .map(|largest| largest.max(packet_number))
                .unwrap_or(packet_number)
        );
    }

    /// Updates largest acknowledged packet number
    pub fn update_largest_acked(&mut self, packet_number: u64) {
        self.largest_acked_packet_number = Some(
            self.largest_acked_packet_number
                .map(|largest| largest.max(packet_number))
                .unwrap_or(packet_number)
        );
    }

    /// Gets the packet number length to use for encoding
    pub fn packet_number_length(&self) -> PacketNumberLength {
        // Calculate based on the difference between next packet number and largest acked
        let unacked_range = match self.largest_acked_packet_number {
            Some(largest_acked) => self.next_packet_number.saturating_sub(largest_acked),
            None => self.next_packet_number,
        };

        PacketNumberLength::from_range(unacked_range)
    }
}

/// Packet number encoding length
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketNumberLength {
    /// 1 byte packet number
    One,
    /// 2 byte packet number
    Two,
    /// 3 byte packet number (reserved)
    Three,
    /// 4 byte packet number
    Four,
}

impl PacketNumberLength {
    /// Returns the length in bytes
    pub fn bytes(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Three => 3,
            Self::Four => 4,
        }
    }

    /// Returns packet number length needed for a given range
    pub fn from_range(range: u64) -> Self {
        if range < (1 << 8) {
            Self::One
        } else if range < (1 << 16) {
            Self::Two
        } else if range < (1 << 24) {
            Self::Three
        } else {
            Self::Four
        }
    }

    /// Encodes a packet number with this length
    pub fn encode(self, packet_number: u64, buf: &mut BytesMut) {
        match self {
            Self::One => buf.put_u8(packet_number as u8),
            Self::Two => buf.put_u16(packet_number as u16),
            Self::Three => {
                buf.put_u8((packet_number >> 16) as u8);
                buf.put_u16(packet_number as u16);
            }
            Self::Four => buf.put_u32(packet_number as u32),
        }
    }

    /// Decodes a packet number with this length
    pub fn decode(self, buf: &mut Bytes) -> Result<u64> {
        if buf.remaining() < self.bytes() {
            return Err(Error::InvalidPacket("Insufficient data for packet number".to_string()));
        }

        let truncated = match self {
            Self::One => buf.get_u8() as u64,
            Self::Two => buf.get_u16() as u64,
            Self::Three => {
                let high = buf.get_u8() as u64;
                let low = buf.get_u16() as u64;
                (high << 16) | low
            }
            Self::Four => buf.get_u32() as u64,
        };

        Ok(truncated)
    }

    /// Reconstructs full packet number from truncated value
    pub fn reconstruct(self, truncated: u64, largest_received: Option<u64>) -> u64 {
        let expected = largest_received.map(|x| x + 1).unwrap_or(0);
        let win_size = 1u64 << (self.bytes() * 8);
        let half_win = win_size / 2;

        let candidate = (expected & !(win_size - 1)) | truncated;

        if candidate <= expected.saturating_sub(half_win) && candidate < (1u64 << 62) - win_size {
            candidate + win_size
        } else if candidate > expected + half_win && candidate >= win_size {
            candidate - win_size
        } else {
            candidate
        }
    }
}

/// Packet protection manager
pub struct PacketProtection {
    /// Packet number spaces
    spaces: HashMap<PacketSpace, PacketNumberSpace>,
    /// Packet keys for encryption/decryption
    packet_keys: HashMap<(EncryptionLevel, bool), PacketKey>,
    /// Header keys for header protection
    header_keys: HashMap<EncryptionLevel, HeaderKey>,
    /// Whether we are a client (affects key selection)
    is_client: bool,
}

impl PacketProtection {
    /// Creates a new packet protection manager
    pub fn new(is_client: bool) -> Self {
        let mut spaces = HashMap::new();
        spaces.insert(PacketSpace::Initial, PacketNumberSpace::new());
        spaces.insert(PacketSpace::Handshake, PacketNumberSpace::new());
        spaces.insert(PacketSpace::ApplicationData, PacketNumberSpace::new());

        Self {
            spaces,
            packet_keys: HashMap::new(),
            header_keys: HashMap::new(),
            is_client,
        }
    }

    /// Installs keys for an encryption level
    pub fn install_keys(
        &mut self, 
        level: EncryptionLevel, 
        tls_state: &TlsState
    ) -> Result<()> {
        // Install packet keys for both directions
        let client_key = tls_state.create_packet_key(level, true)?;
        let server_key = tls_state.create_packet_key(level, false)?;
        
        self.packet_keys.insert((level, true), client_key);
        self.packet_keys.insert((level, false), server_key);

        // Install header key
        let header_key = tls_state.create_header_key(level)?;
        self.header_keys.insert(level, header_key);

        Ok(())
    }

    /// Gets packet number space for a packet space
    pub fn get_space(&self, space: PacketSpace) -> &PacketNumberSpace {
        &self.spaces[&space]
    }

    /// Gets mutable packet number space
    pub fn get_space_mut(&mut self, space: PacketSpace) -> &mut PacketNumberSpace {
        self.spaces.get_mut(&space).unwrap()
    }

    /// Protects (encrypts) an outbound packet
    pub fn protect_packet(
        &mut self,
        packet: &mut Packet,
        payload_frames: &[u8],
    ) -> Result<()> {
        let packet_space = PacketSpace::from_packet_type(packet.packet_type());
        let encryption_level = packet_space.encryption_level();
        
        // Get packet number space
        let space = self.get_space_mut(packet_space);
        let packet_number = space.allocate_packet_number();
        let pn_length = space.packet_number_length();
        space.record_sent_packet(packet_number, pn_length);

        // Update packet header with packet number
        self.update_packet_header_with_number(&mut packet.header, packet_number, pn_length)?;

        // Get encryption keys
        let packet_key = self.packet_keys.get(&(encryption_level, self.is_client))
            .ok_or_else(|| Error::Crypto("No packet key for encryption level".to_string()))?;
        let header_key = self.header_keys.get(&encryption_level)
            .ok_or_else(|| Error::Crypto("No header key for encryption level".to_string()))?;

        // Serialize header for AAD
        let mut header_buf = BytesMut::new();
        packet.header.encode(&mut header_buf)?;
        
        // Encrypt payload
        let mut payload = payload_frames.to_vec();
        let aad = &header_buf[..];
        packet_key.encrypt(packet_number, aad, &mut payload)?;

        // Apply header protection
        if payload.len() >= 4 {
            let sample_offset = 4 - pn_length.bytes();
            if sample_offset + 16 <= payload.len() {
                let mut sample = [0u8; 16];
                sample.copy_from_slice(&payload[sample_offset..sample_offset + 16]);
                
                let mask = header_key.mask(&sample)?;
                self.apply_header_protection(&mut header_buf, &mask, pn_length)?;
            }
        }

        // Update packet with protected data
        packet.payload = Bytes::copy_from_slice(&payload);
        
        Ok(())
    }

    /// Unprotects (decrypts) an inbound packet
    pub fn unprotect_packet(
        &mut self,
        header: &mut PacketHeader,
        payload: &mut [u8],
    ) -> Result<(u64, Bytes)> {
        let packet_space = PacketSpace::from_packet_type(header.packet_type());
        let encryption_level = packet_space.encryption_level();

        // Remove header protection
        if payload.len() >= 4 {
            let sample_offset = 4; // Assume 4-byte packet number for sample calculation
            if sample_offset + 16 <= payload.len() {
                let mut sample = [0u8; 16];
                sample.copy_from_slice(&payload[sample_offset..sample_offset + 16]);
                
                if let Some(header_key) = self.header_keys.get(&encryption_level) {
                    let mask = header_key.mask(&sample)?;
                    let mut header_buf = BytesMut::new();
                    header.encode(&mut header_buf)?;
                    self.remove_header_protection(&mut header_buf, &mask)?;
                    
                    // Re-parse header to get actual packet number length
                    let mut header_bytes = header_buf.freeze();
                    *header = PacketHeader::decode(&mut header_bytes)?;
                } else {
                    return Err(Error::Crypto("No header key for decryption".to_string()));
                }
            }
        }

        // Extract packet number
        let (packet_number, pn_length) = self.extract_packet_number(header)?;
        
        // Reconstruct full packet number and update space
        let full_packet_number = {
            let space = self.get_space_mut(packet_space);
            let full_pn = pn_length.reconstruct(
                packet_number, 
                space.largest_received_packet_number
            );
            space.update_largest_received(full_pn);
            full_pn
        };

        // Serialize header for AAD (without packet number)
        let mut aad_buf = BytesMut::new();
        header.encode(&mut aad_buf)?;
        
        // Decrypt payload
        let plaintext = if let Some(packet_key) = self.packet_keys.get(&(encryption_level, !self.is_client)) {
            packet_key.decrypt(full_packet_number, &aad_buf, payload)?
        } else {
            return Err(Error::Crypto("No packet key for decryption".to_string()));
        };
        
        Ok((full_packet_number, Bytes::copy_from_slice(plaintext)))
    }

    fn update_packet_header_with_number(
        &self,
        header: &mut PacketHeader,
        packet_number: u64,
        pn_length: PacketNumberLength,
    ) -> Result<()> {
        match header {
            PacketHeader::Long(long_header) => {
                // For long headers, packet number is stored separately
                // Log the packet number encoding for debugging
                crypto_event!(Level::Trace, "Encoding packet number {} with length {:?} in long header", packet_number, pn_length);
                let _ = long_header; // Header structure doesn't need modification in this simplified implementation
                Ok(())
            }
            PacketHeader::Short(short_header) => {
                // For short headers, packet number is part of the header
                // Log the packet number encoding for debugging
                crypto_event!(Level::Trace, "Encoding packet number {} with length {:?} in short header", packet_number, pn_length);
                let _ = short_header; // Header structure doesn't need modification in this simplified implementation
                Ok(())
            }
        }
    }

    fn apply_header_protection(
        &self,
        header: &mut BytesMut,
        mask: &[u8; 5],
        pn_length: PacketNumberLength,
    ) -> Result<()> {
        if header.is_empty() {
            return Err(Error::InvalidPacket("Empty header".to_string()));
        }

        // Apply mask to first byte (protecting header form and other flags)
        let first_byte_mask = if header[0] & 0x80 != 0 {
            // Long header
            0x0f
        } else {
            // Short header
            0x1f
        };
        header[0] ^= mask[0] & first_byte_mask;

        // Apply mask to packet number bytes
        let pn_offset = header.len() - pn_length.bytes();
        for i in 0..pn_length.bytes() {
            if pn_offset + i < header.len() {
                header[pn_offset + i] ^= mask[1 + i];
            }
        }

        Ok(())
    }

    fn remove_header_protection(
        &self,
        header: &mut BytesMut,
        mask: &[u8; 5],
    ) -> Result<()> {
        if header.is_empty() {
            return Err(Error::InvalidPacket("Empty header".to_string()));
        }

        // Remove mask from first byte
        let first_byte_mask = if header[0] & 0x80 != 0 {
            // Long header
            0x0f
        } else {
            // Short header  
            0x1f
        };
        header[0] ^= mask[0] & first_byte_mask;

        // Determine packet number length from unprotected first byte
        let pn_length = PacketNumberLength::from_range((header[0] & 0x03) as u64 + 1);

        // Remove mask from packet number bytes
        let pn_offset = header.len() - pn_length.bytes();
        for i in 0..pn_length.bytes() {
            if pn_offset + i < header.len() {
                header[pn_offset + i] ^= mask[1 + i];
            }
        }

        Ok(())
    }

    fn extract_packet_number(&self, _header: &PacketHeader) -> Result<(u64, PacketNumberLength)> {
        // This is a simplified implementation
        // In a real implementation, this would extract the packet number from the header
        // based on the packet number length field in the header
        Ok((0, PacketNumberLength::One))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_number_length_encoding() {
        let mut buf = BytesMut::new();
        
        PacketNumberLength::One.encode(0x42, &mut buf);
        assert_eq!(buf.as_ref(), &[0x42]);
        
        buf.clear();
        PacketNumberLength::Two.encode(0x1234, &mut buf);
        assert_eq!(buf.as_ref(), &[0x12, 0x34]);
        
        buf.clear();
        PacketNumberLength::Four.encode(0x1234_5678, &mut buf);
        assert_eq!(buf.as_ref(), &[0x12, 0x34, 0x56, 0x78]);
    }

    #[test]
    fn packet_number_reconstruction() {
        let pn_len = PacketNumberLength::One;
        
        // Test basic reconstruction
        assert_eq!(pn_len.reconstruct(0x01, Some(0x00)), 0x01);
        assert_eq!(pn_len.reconstruct(0x01, Some(0x01)), 0x01);
        
        // Test wrap-around
        assert_eq!(pn_len.reconstruct(0x00, Some(0xff)), 0x100);
        assert_eq!(pn_len.reconstruct(0xff, Some(0x00)), 0xff);
    }

    #[test]
    fn packet_number_space_operations() {
        let mut space = PacketNumberSpace::new();
        
        assert_eq!(space.next_packet_number(), 0);
        assert_eq!(space.allocate_packet_number(), 0);
        assert_eq!(space.next_packet_number(), 1);
        
        space.update_largest_received(5);
        assert_eq!(space.largest_received_packet_number, Some(5));
        
        space.update_largest_acked(3);
        assert_eq!(space.largest_acked_packet_number, Some(3));
    }

    #[test]
    fn packet_space_from_type() {
        assert_eq!(PacketSpace::from_packet_type(PacketType::Initial), PacketSpace::Initial);
        assert_eq!(PacketSpace::from_packet_type(PacketType::Handshake), PacketSpace::Handshake);
        assert_eq!(PacketSpace::from_packet_type(PacketType::OneRtt), PacketSpace::ApplicationData);
        assert_eq!(PacketSpace::from_packet_type(PacketType::ZeroRtt), PacketSpace::ApplicationData);
    }

    #[test]
    fn encryption_level_mapping() {
        assert_eq!(PacketSpace::Initial.encryption_level(), EncryptionLevel::Initial);
        assert_eq!(PacketSpace::Handshake.encryption_level(), EncryptionLevel::Handshake);
        assert_eq!(PacketSpace::ApplicationData.encryption_level(), EncryptionLevel::Application);
    }
}