//! QUIC transport parameters implementation
//!
//! Implements transport parameter negotiation according to RFC 9000 Section 7.

use crate::{
    error::{Error, Result},
    util::{varint::VarInt, buffer::{BufExt, BufMutExt}},
};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashMap;

/// QUIC transport parameters as defined in RFC 9000 Section 18
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportParameters {
    /// Original destination connection ID
    pub original_destination_connection_id: Option<Bytes>,
    /// Maximum idle timeout in milliseconds
    pub max_idle_timeout: Option<VarInt>,
    /// Stateless reset token
    pub stateless_reset_token: Option<[u8; 16]>,
    /// Maximum UDP payload size
    pub max_udp_payload_size: Option<VarInt>,
    /// Initial maximum data
    pub initial_max_data: Option<VarInt>,
    /// Initial maximum stream data (bidirectional, local)
    pub initial_max_stream_data_bidi_local: Option<VarInt>,
    /// Initial maximum stream data (bidirectional, remote)
    pub initial_max_stream_data_bidi_remote: Option<VarInt>,
    /// Initial maximum stream data (unidirectional)
    pub initial_max_stream_data_uni: Option<VarInt>,
    /// Initial maximum bidirectional streams
    pub initial_max_streams_bidi: Option<VarInt>,
    /// Initial maximum unidirectional streams
    pub initial_max_streams_uni: Option<VarInt>,
    /// ACK delay exponent
    pub ack_delay_exponent: Option<VarInt>,
    /// Maximum ACK delay
    pub max_ack_delay: Option<VarInt>,
    /// Disable active migration
    pub disable_active_migration: bool,
    /// Preferred address
    pub preferred_address: Option<PreferredAddress>,
    /// Active connection ID limit
    pub active_connection_id_limit: Option<VarInt>,
    /// Initial source connection ID
    pub initial_source_connection_id: Option<Bytes>,
    /// Retry source connection ID
    pub retry_source_connection_id: Option<Bytes>,
    /// Additional parameters
    pub additional_params: HashMap<VarInt, Bytes>,
}

impl Default for TransportParameters {
    fn default() -> Self {
        Self {
            original_destination_connection_id: None,
            max_idle_timeout: Some(VarInt::from_u32(30000)), // 30 seconds
            stateless_reset_token: None,
            max_udp_payload_size: Some(VarInt::from_u32(65527)), // Max UDP payload
            initial_max_data: Some(VarInt::from_u32(1024 * 1024)), // 1MB
            initial_max_stream_data_bidi_local: Some(VarInt::from_u32(256 * 1024)), // 256KB
            initial_max_stream_data_bidi_remote: Some(VarInt::from_u32(256 * 1024)), // 256KB
            initial_max_stream_data_uni: Some(VarInt::from_u32(256 * 1024)), // 256KB
            initial_max_streams_bidi: Some(VarInt::from_u32(100)),
            initial_max_streams_uni: Some(VarInt::from_u32(100)),
            ack_delay_exponent: Some(VarInt::from_u32(3)),
            max_ack_delay: Some(VarInt::from_u32(25)), // 25ms
            disable_active_migration: false,
            preferred_address: None,
            active_connection_id_limit: Some(VarInt::from_u32(8)),
            initial_source_connection_id: None,
            retry_source_connection_id: None,
            additional_params: HashMap::new(),
        }
    }
}

impl TransportParameters {
    /// Encodes transport parameters into bytes
    pub fn encode(&self) -> Result<Bytes> {
        let mut buf = BytesMut::new();
        

        // Encode standard parameters
        if let Some(ref odcid) = self.original_destination_connection_id {
            buf.put_var(TransportParameterId::OriginalDestinationConnectionId.into());
            buf.put_var(VarInt::try_from(odcid.len())?);
            buf.put(odcid.as_ref());
        }

        if let Some(ref timeout) = self.max_idle_timeout {
            buf.put_var(TransportParameterId::MaxIdleTimeout.into());
            let mut tmp = BytesMut::new();
            tmp.put_var(*timeout);
            let value_bytes = tmp.freeze();
            buf.put_var(VarInt::try_from(value_bytes.len())?);
            buf.put(value_bytes);
        }

        if let Some(ref token) = self.stateless_reset_token {
            buf.put_var(TransportParameterId::StatelessResetToken.into());
            buf.put_var(VarInt::from_u32(16));
            buf.put_slice(token);
        }

        if let Some(ref size) = self.max_udp_payload_size {
            buf.put_var(TransportParameterId::MaxUdpPayloadSize.into());
            let mut tmp = BytesMut::new();
            tmp.put_var(*size);
            let value_bytes = tmp.freeze();
            buf.put_var(VarInt::try_from(value_bytes.len())?);
            buf.put(value_bytes);
        }

        if let Some(ref data) = self.initial_max_data {
            buf.put_var(TransportParameterId::InitialMaxData.into());
            let mut tmp = BytesMut::new();
            tmp.put_var(*data);
            let value_bytes = tmp.freeze();
            buf.put_var(VarInt::try_from(value_bytes.len())?);
            buf.put(value_bytes);
        }

        if let Some(ref data) = self.initial_max_stream_data_bidi_local {
            buf.put_var(TransportParameterId::InitialMaxStreamDataBidiLocal.into());
            let mut tmp = BytesMut::new();
            tmp.put_var(*data);
            let value_bytes = tmp.freeze();
            buf.put_var(VarInt::try_from(value_bytes.len())?);
            buf.put(value_bytes);
        }

        if let Some(ref data) = self.initial_max_stream_data_bidi_remote {
            buf.put_var(TransportParameterId::InitialMaxStreamDataBidiRemote.into());
            let mut tmp = BytesMut::new();
            tmp.put_var(*data);
            let value_bytes = tmp.freeze();
            buf.put_var(VarInt::try_from(value_bytes.len())?);
            buf.put(value_bytes);
        }

        if let Some(ref data) = self.initial_max_stream_data_uni {
            buf.put_var(TransportParameterId::InitialMaxStreamDataUni.into());
            let mut tmp = BytesMut::new();
            tmp.put_var(*data);
            let value_bytes = tmp.freeze();
            buf.put_var(VarInt::try_from(value_bytes.len())?);
            buf.put(value_bytes);
        }

        if let Some(ref streams) = self.initial_max_streams_bidi {
            buf.put_var(TransportParameterId::InitialMaxStreamsBidi.into());
            let mut tmp = BytesMut::new();
            tmp.put_var(*streams);
            let value_bytes = tmp.freeze();
            buf.put_var(VarInt::try_from(value_bytes.len())?);
            buf.put(value_bytes);
        }

        if let Some(ref streams) = self.initial_max_streams_uni {
            buf.put_var(TransportParameterId::InitialMaxStreamsUni.into());
            let mut tmp = BytesMut::new();
            tmp.put_var(*streams);
            let value_bytes = tmp.freeze();
            buf.put_var(VarInt::try_from(value_bytes.len())?);
            buf.put(value_bytes);
        }

        if let Some(ref exponent) = self.ack_delay_exponent {
            buf.put_var(TransportParameterId::AckDelayExponent.into());
            let mut tmp = BytesMut::new();
            tmp.put_var(*exponent);
            let value_bytes = tmp.freeze();
            buf.put_var(VarInt::try_from(value_bytes.len())?);
            buf.put(value_bytes);
        }

        if let Some(ref delay) = self.max_ack_delay {
            buf.put_var(TransportParameterId::MaxAckDelay.into());
            let mut tmp = BytesMut::new();
            tmp.put_var(*delay);
            let value_bytes = tmp.freeze();
            buf.put_var(VarInt::try_from(value_bytes.len())?);
            buf.put(value_bytes);
        }

        if self.disable_active_migration {
            buf.put_var(TransportParameterId::DisableActiveMigration.into());
            buf.put_var(VarInt::from_u32(0)); // Empty value
        }

        if let Some(ref addr) = self.preferred_address {
            buf.put_var(TransportParameterId::PreferredAddress.into());
            let addr_bytes = addr.encode()?;
            buf.put_var(VarInt::try_from(addr_bytes.len())?);
            buf.put(addr_bytes);
        }

        if let Some(ref limit) = self.active_connection_id_limit {
            buf.put_var(TransportParameterId::ActiveConnectionIdLimit.into());
            let mut tmp = BytesMut::new();
            tmp.put_var(*limit);
            let value_bytes = tmp.freeze();
            buf.put_var(VarInt::try_from(value_bytes.len())?);
            buf.put(value_bytes);
        }

        if let Some(ref iscid) = self.initial_source_connection_id {
            buf.put_var(TransportParameterId::InitialSourceConnectionId.into());
            buf.put_var(VarInt::try_from(iscid.len())?);
            buf.put(iscid.as_ref());
        }

        if let Some(ref rscid) = self.retry_source_connection_id {
            buf.put_var(TransportParameterId::RetrySourceConnectionId.into());
            buf.put_var(VarInt::try_from(rscid.len())?);
            buf.put(rscid.as_ref());
        }

        // Encode additional parameters
        for (param_id, value) in &self.additional_params {
            buf.put_var(*param_id);
            buf.put_var(VarInt::try_from(value.len())?);
            buf.put(value.as_ref());
        }

        Ok(buf.freeze())
    }

    /// Decodes transport parameters from bytes
    pub fn decode(mut data: Bytes) -> Result<Self> {
        let mut params = Self {
            original_destination_connection_id: None,
            max_idle_timeout: None,
            stateless_reset_token: None,
            max_udp_payload_size: None,
            initial_max_data: None,
            initial_max_stream_data_bidi_local: None,
            initial_max_stream_data_bidi_remote: None,
            initial_max_stream_data_uni: None,
            initial_max_streams_bidi: None,
            initial_max_streams_uni: None,
            ack_delay_exponent: None,
            max_ack_delay: None,
            disable_active_migration: false,
            preferred_address: None,
            active_connection_id_limit: None,
            initial_source_connection_id: None,
            retry_source_connection_id: None,
            additional_params: HashMap::new(),
        };

        while data.has_remaining() {
            let param_id = data.get_var()?;
            let param_len = data.get_var()?.into_inner() as usize;
            
            if data.remaining() < param_len {
                return Err(Error::InvalidPacket("Insufficient data for transport parameter".to_string()));
            }

            let param_data = data.get_bytes(param_len).unwrap();
            
            match TransportParameterId::try_from(param_id)? {
                TransportParameterId::OriginalDestinationConnectionId => {
                    params.original_destination_connection_id = Some(param_data);
                }
                TransportParameterId::MaxIdleTimeout => {
                    let mut buf = param_data;
                    params.max_idle_timeout = Some(buf.get_var()?);
                }
                TransportParameterId::StatelessResetToken => {
                    if param_data.len() != 16 {
                        return Err(Error::InvalidPacket("Invalid stateless reset token length".to_string()));
                    }
                    let mut token = [0u8; 16];
                    token.copy_from_slice(&param_data);
                    params.stateless_reset_token = Some(token);
                }
                TransportParameterId::MaxUdpPayloadSize => {
                    let mut buf = param_data;
                    params.max_udp_payload_size = Some(buf.get_var()?);
                }
                TransportParameterId::InitialMaxData => {
                    let mut buf = param_data;
                    params.initial_max_data = Some(buf.get_var()?);
                }
                TransportParameterId::InitialMaxStreamDataBidiLocal => {
                    let mut buf = param_data;
                    params.initial_max_stream_data_bidi_local = Some(buf.get_var()?);
                }
                TransportParameterId::InitialMaxStreamDataBidiRemote => {
                    let mut buf = param_data;
                    params.initial_max_stream_data_bidi_remote = Some(buf.get_var()?);
                }
                TransportParameterId::InitialMaxStreamDataUni => {
                    let mut buf = param_data;
                    params.initial_max_stream_data_uni = Some(buf.get_var()?);
                }
                TransportParameterId::InitialMaxStreamsBidi => {
                    let mut buf = param_data;
                    params.initial_max_streams_bidi = Some(buf.get_var()?);
                }
                TransportParameterId::InitialMaxStreamsUni => {
                    let mut buf = param_data;
                    params.initial_max_streams_uni = Some(buf.get_var()?);
                }
                TransportParameterId::AckDelayExponent => {
                    let mut buf = param_data;
                    params.ack_delay_exponent = Some(buf.get_var()?);
                }
                TransportParameterId::MaxAckDelay => {
                    let mut buf = param_data;
                    params.max_ack_delay = Some(buf.get_var()?);
                }
                TransportParameterId::DisableActiveMigration => {
                    params.disable_active_migration = true;
                }
                TransportParameterId::PreferredAddress => {
                    params.preferred_address = Some(PreferredAddress::decode(param_data)?);
                }
                TransportParameterId::ActiveConnectionIdLimit => {
                    let mut buf = param_data;
                    params.active_connection_id_limit = Some(buf.get_var()?);
                }
                TransportParameterId::InitialSourceConnectionId => {
                    params.initial_source_connection_id = Some(param_data);
                }
                TransportParameterId::RetrySourceConnectionId => {
                    params.retry_source_connection_id = Some(param_data);
                }
                TransportParameterId::Unknown => {
                    // Store unknown parameters
                    params.additional_params.insert(param_id, param_data);
                }
            }
        }

        Ok(params)
    }

    /// Validates transport parameters
    pub fn validate(&self) -> Result<()> {
        // Using Rust 2024 let chains for cleaner validation
        if let Some(exponent) = self.ack_delay_exponent
            && exponent.into_inner() > 20
        {
            return Err(Error::Config("ACK delay exponent too large".to_string()));
        }

        // Validate max ACK delay with let chains
        if let Some(delay) = self.max_ack_delay
            && delay.into_inner() >= (1 << 14)
        {
            return Err(Error::Config("Max ACK delay too large".to_string()));
        }

        // Validate active connection ID limit with let chains
        if let Some(limit) = self.active_connection_id_limit
            && limit.into_inner() < 2
        {
            return Err(Error::Config("Active connection ID limit too small".to_string()));
        }
        
        // Complex validation using multiple conditions in let chains
        if let Some(max_size) = self.max_udp_payload_size
            && let size = max_size.into_inner()
            && (size < 1200 || size > 65527)
        {
            return Err(Error::Config("Max UDP payload size must be between 1200 and 65527".to_string()));
        }

        Ok(())
    }
}

/// Transport parameter identifiers from RFC 9000 Section 18
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportParameterId {
    OriginalDestinationConnectionId = 0x00,
    MaxIdleTimeout = 0x01,
    StatelessResetToken = 0x02,
    MaxUdpPayloadSize = 0x03,
    InitialMaxData = 0x04,
    InitialMaxStreamDataBidiLocal = 0x05,
    InitialMaxStreamDataBidiRemote = 0x06,
    InitialMaxStreamDataUni = 0x07,
    InitialMaxStreamsBidi = 0x08,
    InitialMaxStreamsUni = 0x09,
    AckDelayExponent = 0x0a,
    MaxAckDelay = 0x0b,
    DisableActiveMigration = 0x0c,
    PreferredAddress = 0x0d,
    ActiveConnectionIdLimit = 0x0e,
    InitialSourceConnectionId = 0x0f,
    RetrySourceConnectionId = 0x10,
    Unknown,
}

impl From<TransportParameterId> for VarInt {
    fn from(id: TransportParameterId) -> Self {
        match id {
            TransportParameterId::Unknown => panic!("Cannot convert Unknown parameter ID"),
            _ => VarInt::from_u32(id as u32),
        }
    }
}

impl TryFrom<VarInt> for TransportParameterId {
    type Error = Error;

    fn try_from(value: VarInt) -> Result<Self> {
        match value.into_inner() {
            0x00 => Ok(Self::OriginalDestinationConnectionId),
            0x01 => Ok(Self::MaxIdleTimeout),
            0x02 => Ok(Self::StatelessResetToken),
            0x03 => Ok(Self::MaxUdpPayloadSize),
            0x04 => Ok(Self::InitialMaxData),
            0x05 => Ok(Self::InitialMaxStreamDataBidiLocal),
            0x06 => Ok(Self::InitialMaxStreamDataBidiRemote),
            0x07 => Ok(Self::InitialMaxStreamDataUni),
            0x08 => Ok(Self::InitialMaxStreamsBidi),
            0x09 => Ok(Self::InitialMaxStreamsUni),
            0x0a => Ok(Self::AckDelayExponent),
            0x0b => Ok(Self::MaxAckDelay),
            0x0c => Ok(Self::DisableActiveMigration),
            0x0d => Ok(Self::PreferredAddress),
            0x0e => Ok(Self::ActiveConnectionIdLimit),
            0x0f => Ok(Self::InitialSourceConnectionId),
            0x10 => Ok(Self::RetrySourceConnectionId),
            _ => Ok(Self::Unknown),
        }
    }
}

/// Preferred address parameter from RFC 9000 Section 18.2
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreferredAddress {
    /// IPv4 address (4 bytes) + port (2 bytes)
    pub ipv4: Option<([u8; 4], u16)>,
    /// IPv6 address (16 bytes) + port (2 bytes)
    pub ipv6: Option<([u8; 16], u16)>,
    /// Connection ID length
    pub connection_id_length: u8,
    /// Connection ID
    pub connection_id: Bytes,
    /// Stateless reset token
    pub stateless_reset_token: [u8; 16],
}

impl PreferredAddress {
    /// Encodes preferred address
    pub fn encode(&self) -> Result<Bytes> {
        let mut buf = BytesMut::with_capacity(64);

        // IPv4 address and port
        if let Some((addr, port)) = self.ipv4 {
            buf.put_slice(&addr);
            buf.put_u16(port);
        } else {
            buf.put_slice(&[0u8; 6]); // Zero IPv4 address and port
        }

        // IPv6 address and port
        if let Some((addr, port)) = self.ipv6 {
            buf.put_slice(&addr);
            buf.put_u16(port);
        } else {
            buf.put_slice(&[0u8; 18]); // Zero IPv6 address and port
        }

        // Connection ID
        buf.put_u8(self.connection_id_length);
        buf.put(self.connection_id.as_ref());

        // Stateless reset token
        buf.put_slice(&self.stateless_reset_token);

        Ok(buf.freeze())
    }

    /// Decodes preferred address
    pub fn decode(mut data: Bytes) -> Result<Self> {
        if data.len() < 41 {
            return Err(Error::InvalidPacket("Preferred address too short".to_string()));
        }

        // IPv4 address and port
        let mut ipv4_addr = [0u8; 4];
        data.copy_to_slice(&mut ipv4_addr);
        let ipv4_port = data.get_u16();
        let ipv4 = if ipv4_addr != [0u8; 4] || ipv4_port != 0 {
            Some((ipv4_addr, ipv4_port))
        } else {
            None
        };

        // IPv6 address and port
        let mut ipv6_addr = [0u8; 16];
        data.copy_to_slice(&mut ipv6_addr);
        let ipv6_port = data.get_u16();
        let ipv6 = if ipv6_addr != [0u8; 16] || ipv6_port != 0 {
            Some((ipv6_addr, ipv6_port))
        } else {
            None
        };

        // Connection ID
        let connection_id_length = data.get_u8();
        if data.remaining() < connection_id_length as usize + 16 {
            return Err(Error::InvalidPacket("Insufficient data for preferred address".to_string()));
        }

        let connection_id = data.get_bytes(connection_id_length as usize).unwrap();

        // Stateless reset token
        let mut stateless_reset_token = [0u8; 16];
        data.copy_to_slice(&mut stateless_reset_token);

        Ok(Self {
            ipv4,
            ipv6,
            connection_id_length,
            connection_id,
            stateless_reset_token,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_parameters_default() {
        let params = TransportParameters::default();
        assert!(params.max_idle_timeout.is_some());
        assert!(params.initial_max_data.is_some());
        assert!(!params.disable_active_migration);
        params.validate().unwrap();
    }

    #[test]
    fn transport_parameters_encoding_roundtrip() {
        let mut params = TransportParameters::default();
        params.max_idle_timeout = Some(VarInt::from_u32(60000));
        params.disable_active_migration = true;
        params.additional_params.insert(VarInt::from_u32(0x1000), Bytes::from_static(b"test"));

        let encoded = params.encode().unwrap();
        let decoded = TransportParameters::decode(encoded).unwrap();

        assert_eq!(decoded.max_idle_timeout, params.max_idle_timeout);
        assert_eq!(decoded.disable_active_migration, params.disable_active_migration);
        assert_eq!(decoded.additional_params.get(&VarInt::from_u32(0x1000)), Some(&Bytes::from_static(b"test")));
    }

    #[test]
    fn transport_parameters_validation() {
        let mut params = TransportParameters::default();
        
        // Valid parameters
        params.validate().unwrap();

        // Invalid ACK delay exponent
        params.ack_delay_exponent = Some(VarInt::from_u32(25));
        assert!(params.validate().is_err());

        params.ack_delay_exponent = Some(VarInt::from_u32(3));
        params.validate().unwrap();

        // Invalid active connection ID limit
        params.active_connection_id_limit = Some(VarInt::from_u32(1));
        assert!(params.validate().is_err());
    }

    #[test]
    fn preferred_address_encoding_roundtrip() {
        let addr = PreferredAddress {
            ipv4: Some(([127, 0, 0, 1], 8080)),
            ipv6: Some(([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 8080)),
            connection_id_length: 8,
            connection_id: Bytes::from_static(b"test_cid"),
            stateless_reset_token: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        };

        let encoded = addr.encode().unwrap();
        let decoded = PreferredAddress::decode(encoded).unwrap();

        assert_eq!(decoded.ipv4, addr.ipv4);
        assert_eq!(decoded.ipv6, addr.ipv6);
        assert_eq!(decoded.connection_id_length, addr.connection_id_length);
        assert_eq!(decoded.connection_id, addr.connection_id);
        assert_eq!(decoded.stateless_reset_token, addr.stateless_reset_token);
    }
}