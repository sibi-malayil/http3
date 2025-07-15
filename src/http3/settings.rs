//! HTTP/3 settings management per RFC 9114

use crate::{error::Result, util::varint::VarInt};
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;

/// HTTP/3 settings per RFC 9114 Section 7.2.4
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// Internal storage of settings as identifier -> value pairs
    settings: HashMap<u64, u64>,
}

impl Default for Settings {
    fn default() -> Self {
        let mut settings = HashMap::new();
        
        // Set default values per RFC 9114
        settings.insert(SettingId::MaxFieldSectionSize.id(), 16384); // 16KB default
        settings.insert(SettingId::QpackMaxTableCapacity.id(), 0);   // No dynamic table by default
        settings.insert(SettingId::QpackBlockedStreams.id(), 0);     // No blocked streams by default
        
        Self { settings }
    }
}

/// HTTP/3 setting identifiers per RFC 9114 Section 7.2.4
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingId {
    /// Reserved (0x00)
    Reserved = 0x00,
    /// QPACK_MAX_TABLE_CAPACITY (0x01)
    QpackMaxTableCapacity = 0x01,
    /// Reserved (0x02-0x05)
    Reserved2 = 0x02,
    /// Reserved identifier (0x03)
    Reserved3 = 0x03,
    /// Reserved identifier (0x04)
    Reserved4 = 0x04,
    /// Reserved identifier (0x05)
    Reserved5 = 0x05,
    /// MAX_FIELD_SECTION_SIZE (0x06)
    MaxFieldSectionSize = 0x06,
    /// QPACK_BLOCKED_STREAMS (0x07)
    QpackBlockedStreams = 0x07,
}

impl SettingId {
    /// Get the numeric identifier for this setting
    pub fn id(self) -> u64 {
        self as u64
    }
    
    /// Create a SettingId from a numeric identifier
    pub fn from_id(id: u64) -> Option<Self> {
        match id {
            0x00 => Some(Self::Reserved),
            0x01 => Some(Self::QpackMaxTableCapacity),
            0x02 => Some(Self::Reserved2),
            0x03 => Some(Self::Reserved3),
            0x04 => Some(Self::Reserved4),
            0x05 => Some(Self::Reserved5),
            0x06 => Some(Self::MaxFieldSectionSize),
            0x07 => Some(Self::QpackBlockedStreams),
            _ => None, // Unknown settings are ignored per RFC 9114
        }
    }
    
    /// Check if this setting is reserved
    pub fn is_reserved(self) -> bool {
        matches!(self, Self::Reserved | Self::Reserved2 | Self::Reserved3 | Self::Reserved4 | Self::Reserved5)
    }
}

impl Settings {
    /// Create new Settings with default values
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Set a setting value
    pub fn set(&mut self, setting_id: SettingId, value: VarInt) {
        if setting_id.is_reserved() {
            // Reserved settings should not be set - ignore per RFC 9114
            return;
        }
        self.settings.insert(setting_id.id(), value.into_inner());
    }
    
    /// Get a setting value
    pub fn get(&self, setting_id: SettingId) -> Option<u64> {
        self.settings.get(&setting_id.id()).copied()
    }
    
    /// Get MAX_FIELD_SECTION_SIZE setting (0x06)
    pub fn max_field_section_size(&self) -> u64 {
        self.get(SettingId::MaxFieldSectionSize).unwrap_or(16384)
    }
    
    /// Get QPACK_MAX_TABLE_CAPACITY setting (0x01)
    pub fn qpack_max_table_capacity(&self) -> u64 {
        self.get(SettingId::QpackMaxTableCapacity).unwrap_or(0)
    }
    
    /// Get QPACK_BLOCKED_STREAMS setting (0x07)
    pub fn qpack_blocked_streams(&self) -> u64 {
        self.get(SettingId::QpackBlockedStreams).unwrap_or(0)
    }
    
    /// Check if settings are valid per RFC 9114
    pub fn validate(&self) -> Result<()> {
        // Validate QPACK settings
        let qpack_capacity = self.qpack_max_table_capacity();
        let qpack_blocked = self.qpack_blocked_streams();
        
        // If dynamic table is disabled, blocked streams should be 0
        if qpack_capacity == 0 && qpack_blocked > 0 {
            return Err(crate::error::Error::Config(
                "QPACK_BLOCKED_STREAMS must be 0 when QPACK_MAX_TABLE_CAPACITY is 0".to_string()
            ));
        }
        
        // Check field section size limit is reasonable
        let max_field_size = self.max_field_section_size();
        if max_field_size == 0 {
            return Err(crate::error::Error::Config(
                "MAX_FIELD_SECTION_SIZE must be greater than 0".to_string()
            ));
        }
        
        Ok(())
    }

    /// Encode settings according to RFC 9114 Section 7.2.4
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        // Encode all non-default settings
        for (&setting_id, &value) in &self.settings {
            // Only encode settings that differ from defaults
            let should_encode = match SettingId::from_id(setting_id) {
                Some(SettingId::MaxFieldSectionSize) => value != 16384,
                Some(SettingId::QpackMaxTableCapacity) => value != 0,
                Some(SettingId::QpackBlockedStreams) => value != 0,
                Some(id) if id.is_reserved() => false, // Never encode reserved settings
                Some(_) => true, // Encode other known settings if non-zero
                None => value != 0, // Encode unknown settings if non-zero
            };
            
            if should_encode {
                VarInt(setting_id).encode(buf)?;
                VarInt(value).encode(buf)?;
            }
        }
        
        Ok(())
    }

    /// Decode settings from buffer per RFC 9114 Section 7.2.4
    pub fn decode(buf: &Bytes) -> Result<Self> {
        let mut settings = Self::default();
        let mut cursor = buf.as_ref();

        while !cursor.is_empty() {
            let setting_id = VarInt::decode(&mut cursor)?.into_inner();
            let setting_value = VarInt::decode(&mut cursor)?.into_inner();

            // Handle known settings and store unknown ones
            if let Some(known_id) = SettingId::from_id(setting_id) {
                if !known_id.is_reserved() {
                    settings.settings.insert(setting_id, setting_value);
                }
                // Reserved settings are ignored per RFC 9114
            } else {
                // Unknown settings are stored for potential future use
                settings.settings.insert(setting_id, setting_value);
            }
        }

        // Validate the decoded settings
        settings.validate()?;
        
        Ok(settings)
    }
}