//! Wrapper for rustls QUIC keys
//!
//! This module provides wrappers around rustls's QUIC key interfaces to integrate
//! with our packet encryption/decryption logic.

use crate::error::{Error, Result};
use rustls::quic::{Keys, DirectionalKeys, PacketKey as RustlsPacketKey, HeaderProtectionKey as RustlsHeaderProtectionKey};
use std::sync::Arc;

/// Wrapper around rustls Keys for packet protection
pub struct RustlsKeys {
    /// Keys for local (sending) direction
    pub local: RustlsDirectionalKeys,
    /// Keys for remote (receiving) direction
    pub remote: RustlsDirectionalKeys,
}

/// Wrapper around rustls DirectionalKeys
pub struct RustlsDirectionalKeys {
    /// Packet protection key
    pub packet: Arc<dyn RustlsPacketKey>,
    /// Header protection key
    pub header: Arc<dyn RustlsHeaderProtectionKey>,
}

impl RustlsKeys {
    /// Create from rustls Keys
    pub fn from_rustls(keys: Keys) -> Self {
        Self {
            local: RustlsDirectionalKeys::from_rustls(keys.local),
            remote: RustlsDirectionalKeys::from_rustls(keys.remote),
        }
    }
}

impl RustlsDirectionalKeys {
    /// Create from rustls DirectionalKeys
    fn from_rustls(keys: DirectionalKeys) -> Self {
        Self {
            packet: Arc::from(keys.packet),
            header: Arc::from(keys.header),
        }
    }
    
    /// Encrypt a packet payload
    pub fn encrypt_packet(&self, packet_number: u64, header: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
        eprintln!("Rustls encrypt_packet: packet_number={}, header_len={}, payload_len={}, key_ptr={:p}", 
                 packet_number, header.len(), payload.len(), self.packet.as_ref() as *const _);
        
        // Allocate buffer for ciphertext (payload + tag)
        let mut ciphertext = vec![0u8; payload.len() + self.packet.tag_len()];
        
        // Copy plaintext
        ciphertext[..payload.len()].copy_from_slice(payload);
        
        // Encrypt in place
        self.packet
            .encrypt_in_place(packet_number, header, &mut ciphertext)
            .map_err(|_| Error::CryptoError("Packet encryption failed".to_string()))?;
        
        Ok(ciphertext)
    }
    
    /// Decrypt a packet payload
    pub fn decrypt_packet(&self, packet_number: u64, header: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        eprintln!("Rustls decrypt_packet: packet_number={}, header_len={}, ciphertext_len={}, key_ptr={:p}", 
                 packet_number, header.len(), ciphertext.len(), self.packet.as_ref() as *const _);
        
        if ciphertext.len() < self.packet.tag_len() {
            return Err(Error::CryptoError("Ciphertext too short".to_string()));
        }
        
        // Allocate buffer and copy ciphertext
        let mut plaintext = ciphertext.to_vec();
        
        // Decrypt in place - decrypt_in_place returns a Result<&[u8]> with the plaintext slice
        let plaintext_slice = self.packet
            .decrypt_in_place(packet_number, header, &mut plaintext)
            .map_err(|e| {
                eprintln!("Rustls decrypt_in_place failed: {:?}", e);
                eprintln!("  packet_number: {}", packet_number);
                eprintln!("  header len: {}", header.len());
                eprintln!("  ciphertext len: {}", ciphertext.len());
                eprintln!("  tag len: {}", self.packet.tag_len());
                Error::CryptoError("Packet decryption failed".to_string())
            })?;
        
        // Return only the plaintext portion
        Ok(plaintext_slice.to_vec())
    }
    
    /// Apply header protection
    pub fn protect_header(&self, sample: &[u8], first: &mut u8, packet_number: &mut [u8]) -> Result<()> {
        self.header.encrypt_in_place(sample, first, packet_number)
            .map_err(|e| Error::CryptoError(format!("Header protection failed: {:?}", e)))?;
        Ok(())
    }
    
    /// Remove header protection
    pub fn unprotect_header(&self, sample: &[u8], first: &mut u8, packet_number: &mut [u8]) -> Result<()> {
        self.header.decrypt_in_place(sample, first, packet_number)
            .map_err(|e| Error::CryptoError(format!("Header unprotection failed: {:?}", e)))?;
        Ok(())
    }
}
