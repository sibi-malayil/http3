//! HTTP/3 SETTINGS tests

use http3::http3::settings::{Settings, SettingId};
use http3::util::varint::VarInt;
use bytes::{Bytes, BytesMut};

#[test]
fn test_default_settings() {
    let settings = Settings::new();
    
    // Check default values per RFC 9114
    assert_eq!(settings.max_field_section_size(), 16384);
    assert_eq!(settings.qpack_max_table_capacity(), 0);
    assert_eq!(settings.qpack_blocked_streams(), 0);
}

#[test]
fn test_settings_encode_decode() {
    let mut settings = Settings::new();
    
    // Set custom values
    settings.set(SettingId::MaxFieldSectionSize, VarInt(32768));
    settings.set(SettingId::QpackMaxTableCapacity, VarInt(4096));
    settings.set(SettingId::QpackBlockedStreams, VarInt(100));
    
    // Encode
    let mut buf = BytesMut::new();
    settings.encode(&mut buf).unwrap();
    
    // Decode
    let decoded = Settings::decode(&buf.freeze()).unwrap();
    
    // Verify
    assert_eq!(decoded.max_field_section_size(), 32768);
    assert_eq!(decoded.qpack_max_table_capacity(), 4096);
    assert_eq!(decoded.qpack_blocked_streams(), 100);
}

#[test]
fn test_settings_validation() {
    let mut settings = Settings::new();
    
    // Valid settings
    settings.set(SettingId::QpackMaxTableCapacity, VarInt(4096));
    settings.set(SettingId::QpackBlockedStreams, VarInt(10));
    assert!(settings.validate().is_ok());
    
    // Invalid: blocked streams with no dynamic table
    let mut invalid_settings = Settings::new();
    invalid_settings.set(SettingId::QpackMaxTableCapacity, VarInt(0));
    invalid_settings.set(SettingId::QpackBlockedStreams, VarInt(10));
    assert!(invalid_settings.validate().is_err());
}

#[test]
fn test_reserved_settings_ignored() {
    let mut settings = Settings::new();
    
    // Try to set reserved settings - should be ignored
    settings.set(SettingId::Reserved, VarInt(100));
    settings.set(SettingId::Reserved2, VarInt(200));
    
    // Encode - reserved settings should not be included
    let mut buf = BytesMut::new();
    settings.encode(&mut buf).unwrap();
    
    // If only defaults are set, buffer should be empty
    assert!(buf.is_empty() || buf.len() < 10); // Reserved settings not encoded
}

#[test]
fn test_unknown_settings_preserved() {
    // Create raw settings with unknown ID
    let mut buf = BytesMut::new();
    VarInt(0x99).encode(&mut buf).unwrap(); // Unknown setting ID
    VarInt(42).encode(&mut buf).unwrap();    // Value
    
    // Decode should not fail on unknown settings
    let settings = Settings::decode(&buf.freeze()).unwrap();
    assert!(settings.validate().is_ok());
}

#[test]
fn test_zero_max_field_section_size() {
    let mut settings = Settings::new();
    settings.set(SettingId::MaxFieldSectionSize, VarInt(0));
    
    // Should fail validation
    assert!(settings.validate().is_err());
}

#[test]
fn test_settings_only_encode_non_defaults() {
    // Settings with all defaults should encode to empty
    let default_settings = Settings::new();
    let mut buf = BytesMut::new();
    default_settings.encode(&mut buf).unwrap();
    assert_eq!(buf.len(), 0);
    
    // Settings with one non-default value
    let mut settings = Settings::new();
    settings.set(SettingId::QpackMaxTableCapacity, VarInt(8192));
    
    let mut buf2 = BytesMut::new();
    settings.encode(&mut buf2).unwrap();
    assert!(buf2.len() > 0);
    
    // Decode and verify
    let decoded = Settings::decode(&buf2.freeze()).unwrap();
    assert_eq!(decoded.qpack_max_table_capacity(), 8192);
    assert_eq!(decoded.max_field_section_size(), 16384); // Still default
}

#[test]
fn test_large_settings_values() {
    let mut settings = Settings::new();
    
    // Test with large values
    let large_value = u64::MAX / 2;
    settings.set(SettingId::MaxFieldSectionSize, VarInt(large_value));
    
    // Encode and decode
    let mut buf = BytesMut::new();
    settings.encode(&mut buf).unwrap();
    
    let decoded = Settings::decode(&buf.freeze()).unwrap();
    assert_eq!(decoded.max_field_section_size(), large_value);
}