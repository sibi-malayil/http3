//! QUIC version negotiation implementation
//!
//! This module implements version negotiation as specified in RFC 9000 Section 6
//! and RFC 9368 (Compatible Version Negotiation).

use crate::{
    error::{Error, Result},
    quic::{
        packet::{ConnectionId, PacketHeader, LongHeader},
        VERSION_1,
    },
    whathappened::Level,
    protocol_event,
};
use bytes::{Buf, BufMut, BytesMut};
use std::collections::HashSet;

/// QUIC version negotiation packet indicator (0x00000000)
pub const VERSION_NEGOTIATION: u32 = 0x00000000;

/// Draft version prefix for experimental versions
pub const DRAFT_VERSION_PREFIX: u32 = 0xff000000;

/// Supported QUIC versions in order of preference
pub const SUPPORTED_VERSIONS: &[u32] = &[
    VERSION_1,           // RFC 9000 QUIC v1
    0x6b3343cf,         // QUIC v2 (RFC 9369)
    0x709a50c4,         // QUIC v2 draft
];

/// Version negotiation configuration
#[derive(Debug, Clone)]
pub struct VersionConfig {
    /// Supported versions
    pub supported_versions: Vec<u32>,
    /// Whether to support version negotiation
    pub enable_version_negotiation: bool,
    /// Whether to support compatible version negotiation (RFC 9368)
    pub enable_compatible_negotiation: bool,
    /// Preferred version for outgoing connections
    pub preferred_version: u32,
}

impl Default for VersionConfig {
    fn default() -> Self {
        Self {
            supported_versions: SUPPORTED_VERSIONS.to_vec(),
            enable_version_negotiation: true,
            enable_compatible_negotiation: true,
            preferred_version: VERSION_1,
        }
    }
}

/// Version negotiation packet
#[derive(Debug, Clone)]
pub struct VersionNegotiationPacket {
    /// Random value for the unused fields
    pub random: u8,
    /// Destination connection ID (from triggering packet)
    pub dst_cid: ConnectionId,
    /// Source connection ID (from triggering packet)
    pub src_cid: ConnectionId,
    /// List of supported versions
    pub supported_versions: Vec<u32>,
}

impl VersionNegotiationPacket {
    /// Create a new version negotiation packet
    pub fn new(
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
        supported_versions: Vec<u32>,
    ) -> Self {
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut random = [0u8; 1];
        let _ = rng.fill(&mut random);
        
        Self {
            random: random[0] | 0x80, // Set fixed bit
            dst_cid,
            src_cid,
            supported_versions,
        }
    }

    /// Encode version negotiation packet
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        // First byte with fixed bit set and random bits
        buf.put_u8(self.random);
        
        // Version field (always 0 for version negotiation)
        buf.put_u32(VERSION_NEGOTIATION);
        
        // Destination connection ID
        buf.put_u8(self.dst_cid.len() as u8);
        buf.put_slice(self.dst_cid.as_bytes());
        
        // Source connection ID
        buf.put_u8(self.src_cid.len() as u8);
        buf.put_slice(self.src_cid.as_bytes());
        
        // Supported versions
        for version in &self.supported_versions {
            buf.put_u32(*version);
        }
        
        Ok(())
    }

    /// Decode version negotiation packet
    pub fn decode(mut buf: &[u8]) -> Result<Self> {
        if buf.remaining() < 1 + 4 + 2 {
            return Err(Error::PacketTooShort);
        }
        
        let random = buf.get_u8();
        
        // Check fixed bit
        if (random & 0x80) == 0 {
            return Err(Error::InvalidPacketFormat);
        }
        
        let version = buf.get_u32();
        if version != VERSION_NEGOTIATION {
            return Err(Error::InvalidPacketFormat);
        }
        
        // Decode connection IDs
        let dst_cid_len = buf.get_u8() as usize;
        if buf.remaining() < dst_cid_len {
            return Err(Error::PacketTooShort);
        }
        let dst_cid = ConnectionId::from_slice(&buf[..dst_cid_len]);
        buf.advance(dst_cid_len);
        
        let src_cid_len = buf.get_u8() as usize;
        if buf.remaining() < src_cid_len {
            return Err(Error::PacketTooShort);
        }
        let src_cid = ConnectionId::from_slice(&buf[..src_cid_len]);
        buf.advance(src_cid_len);
        
        // Decode supported versions
        let mut supported_versions = Vec::new();
        while buf.remaining() >= 4 {
            supported_versions.push(buf.get_u32());
        }
        
        if supported_versions.is_empty() {
            return Err(Error::InvalidPacketFormat);
        }
        
        Ok(Self {
            random,
            dst_cid,
            src_cid,
            supported_versions,
        })
    }
}

/// Version negotiation handler
#[derive(Debug)]
pub struct VersionNegotiator {
    /// Configuration
    config: VersionConfig,
    /// Set of supported versions for fast lookup
    supported_set: HashSet<u32>,
}

impl VersionNegotiator {
    /// Create a new version negotiator
    pub fn new(config: VersionConfig) -> Self {
        let supported_set = config.supported_versions.iter().cloned().collect();
        Self {
            config,
            supported_set,
        }
    }

    /// Check if a version is supported
    pub fn is_supported(&self, version: u32) -> bool {
        self.supported_set.contains(&version)
    }

    /// Select a compatible version from client's offered version
    pub fn select_version(&self, client_version: u32) -> Option<u32> {
        if self.is_supported(client_version) {
            Some(client_version)
        } else {
            // Try to find a compatible version
            self.find_compatible_version(client_version)
        }
    }

    /// Find a compatible version based on version aliasing rules
    fn find_compatible_version(&self, client_version: u32) -> Option<u32> {
        // Check for draft versions
        if (client_version & DRAFT_VERSION_PREFIX) == DRAFT_VERSION_PREFIX {
            // Extract draft number and find corresponding release version
            let draft_num = client_version & 0x00ffffff;
            
            // Known draft to release mappings
            match draft_num {
                29 => Some(VERSION_1), // draft-29 became v1
                _ => None,
            }
        } else {
            // Check version families (future extension point)
            None
        }
    }

    /// Generate version negotiation packet
    pub fn create_version_negotiation(
        &self,
        dst_cid: ConnectionId,
        src_cid: ConnectionId,
    ) -> VersionNegotiationPacket {
        VersionNegotiationPacket::new(
            dst_cid,
            src_cid,
            self.config.supported_versions.clone(),
        )
    }

    /// Handle received version negotiation packet (client side)
    pub fn handle_version_negotiation(
        &self,
        packet: &VersionNegotiationPacket,
    ) -> Result<u32> {
        // Find the best mutually supported version
        for version in &self.config.supported_versions {
            if packet.supported_versions.contains(version) {
                protocol_event!(
                    Level::Info,
                    "Selected version from negotiation";
                    "version" => format!("0x{:08x}", version)
                );
                return Ok(*version);
            }
        }
        
        Err(Error::VersionNegotiation)
    }

    /// Check if version negotiation is needed
    pub fn needs_negotiation(&self, client_version: u32) -> bool {
        self.config.enable_version_negotiation && !self.is_supported(client_version)
    }

    /// Get preferred version for client connections
    pub fn preferred_version(&self) -> u32 {
        self.config.preferred_version
    }

    /// Get all supported versions
    pub fn supported_versions(&self) -> &[u32] {
        &self.config.supported_versions
    }
}

/// Compatible version negotiation extension (RFC 9368)
#[derive(Debug, Clone)]
pub struct CompatibleVersions {
    /// Current version in use
    pub chosen_version: u32,
    /// Other compatible versions
    pub other_versions: Vec<u32>,
}

impl CompatibleVersions {
    /// Encode for transport parameter
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        buf.put_u32(self.chosen_version);
        for version in &self.other_versions {
            buf.put_u32(*version);
        }
        Ok(())
    }

    /// Decode from transport parameter
    pub fn decode(mut buf: &[u8]) -> Result<Self> {
        if buf.remaining() < 4 {
            return Err(Error::InvalidTransportParameter);
        }
        
        let chosen_version = buf.get_u32();
        let mut other_versions = Vec::new();
        
        while buf.remaining() >= 4 {
            other_versions.push(buf.get_u32());
        }
        
        Ok(Self {
            chosen_version,
            other_versions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_negotiation_packet() {
        let dst_cid = ConnectionId::from_slice(b"client");
        let src_cid = ConnectionId::from_slice(b"server");
        let versions = vec![VERSION_1, 0x6b3343cf];
        
        let packet = VersionNegotiationPacket::new(
            dst_cid.clone(),
            src_cid.clone(),
            versions.clone(),
        );
        
        let mut buf = BytesMut::new();
        packet.encode(&mut buf).unwrap();
        
        let decoded = VersionNegotiationPacket::decode(&buf).unwrap();
        assert_eq!(decoded.dst_cid, dst_cid);
        assert_eq!(decoded.src_cid, src_cid);
        assert_eq!(decoded.supported_versions, versions);
    }

    #[test]
    fn test_version_selection() {
        let config = VersionConfig::default();
        let negotiator = VersionNegotiator::new(config);
        
        // Supported version
        assert_eq!(negotiator.select_version(VERSION_1), Some(VERSION_1));
        
        // Unsupported version
        assert_eq!(negotiator.select_version(0x12345678), None);
        
        // Draft version mapping
        assert_eq!(negotiator.select_version(0xff00001d), Some(VERSION_1));
    }

    #[test]
    fn test_compatible_versions() {
        let compat = CompatibleVersions {
            chosen_version: VERSION_1,
            other_versions: vec![0x6b3343cf],
        };
        
        let mut buf = BytesMut::new();
        compat.encode(&mut buf).unwrap();
        
        let decoded = CompatibleVersions::decode(&buf).unwrap();
        assert_eq!(decoded.chosen_version, compat.chosen_version);
        assert_eq!(decoded.other_versions, compat.other_versions);
    }
}