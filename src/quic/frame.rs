//! QUIC frame types and processing
//!
//! Implements frame format from RFC 9000 Section 19.

use crate::{
    error::{Error, Result},
    util::{varint::VarInt, buffer::{BufExt, BufMutExt}},
};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// A QUIC frame
#[derive(Debug, Clone)]
pub struct Frame {
    /// Frame type
    pub frame_type: FrameType,
    /// Frame payload
    pub payload: Bytes,
}

impl Frame {
    /// Creates a new frame
    pub fn new(frame_type: FrameType, payload: Bytes) -> Self {
        Self { frame_type, payload }
    }

    /// Encodes the frame into bytes
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        buf.put_var(VarInt::try_from(self.frame_type as u64).unwrap());
        buf.put(self.payload.as_ref());
        Ok(())
    }

    /// Decodes a frame from bytes
    pub fn decode(buf: &mut Bytes) -> Result<Self> {
        let frame_type_val = buf.get_var()?.into_inner();
        let frame_type = FrameType::try_from(frame_type_val)?;
        
        // For now, treat the rest as payload
        // In a full implementation, each frame type would have specific parsing
        let payload = buf.split_to(buf.remaining());
        
        Ok(Self { frame_type, payload })
    }
}

/// QUIC frame types (RFC 9000 Section 19)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum FrameType {
    /// PADDING frame for packet size adjustment
    Padding = 0x00,
    /// PING frame for connection liveness
    Ping = 0x01,
    /// ACK frame for acknowledgment (without ECN)
    Ack = 0x02,
    /// ACK frame for acknowledgment (with ECN)
    AckEcn = 0x03,
    /// RESET_STREAM frame for abrupt stream termination
    ResetStream = 0x04,
    /// STOP_SENDING frame to request stream termination
    StopSending = 0x05,
    /// CRYPTO frame for TLS handshake data
    Crypto = 0x06,
    /// NEW_TOKEN frame for address validation tokens
    NewToken = 0x07,
    /// STREAM frames for application data (0x08-0x0f)
    Stream = 0x08,
    /// MAX_DATA frame for connection-level flow control
    MaxData = 0x10,
    /// MAX_STREAM_DATA frame for stream-level flow control
    MaxStreamData = 0x11,
    /// MAX_STREAMS frame for bidirectional streams
    MaxStreamsBidi = 0x12,
    /// MAX_STREAMS frame for unidirectional streams
    MaxStreamsUni = 0x13,
    /// DATA_BLOCKED frame for connection-level flow control
    DataBlocked = 0x14,
    /// STREAM_DATA_BLOCKED frame for stream-level flow control
    StreamDataBlocked = 0x15,
    /// STREAMS_BLOCKED frame for bidirectional streams
    StreamsBlockedBidi = 0x16,
    /// STREAMS_BLOCKED frame for unidirectional streams
    StreamsBlockedUni = 0x17,
    /// NEW_CONNECTION_ID frame for connection migration
    NewConnectionId = 0x18,
    /// RETIRE_CONNECTION_ID frame for connection ID retirement
    RetireConnectionId = 0x19,
    /// PATH_CHALLENGE frame for path validation
    PathChallenge = 0x1a,
    /// PATH_RESPONSE frame for path validation
    PathResponse = 0x1b,
    /// CONNECTION_CLOSE frame for connection termination (transport)
    ConnectionCloseTransport = 0x1c,
    /// CONNECTION_CLOSE frame for connection termination (application)
    ConnectionCloseApp = 0x1d,
    /// HANDSHAKE_DONE frame for handshake completion
    HandshakeDone = 0x1e,
}

impl FrameType {
    /// Returns true if this frame type can appear in different packet types
    pub fn is_allowed_in_packet_type(self, packet_type: crate::quic::packet::PacketType) -> bool {
        use crate::quic::packet::PacketType;
        
        match self {
            Self::Padding | Self::Ping | Self::ConnectionCloseTransport | Self::ConnectionCloseApp => true,
            Self::Crypto | Self::Ack | Self::AckEcn => {
                matches!(packet_type, PacketType::Initial | PacketType::Handshake | PacketType::OneRtt)
            }
            Self::NewToken => packet_type == PacketType::OneRtt,
            Self::HandshakeDone => packet_type == PacketType::OneRtt,
            _ => packet_type == PacketType::OneRtt,
        }
    }

    /// Returns true if this frame type is connection-level
    pub fn is_connection_level(self) -> bool {
        !matches!(
            self,
            Self::Stream | Self::ResetStream | Self::StopSending | 
            Self::MaxStreamData | Self::StreamDataBlocked
        )
    }
}

impl TryFrom<u64> for FrameType {
    type Error = Error;

    fn try_from(value: u64) -> Result<Self> {
        match value {
            0x00 => Ok(Self::Padding),
            0x01 => Ok(Self::Ping),
            0x02 => Ok(Self::Ack),
            0x03 => Ok(Self::AckEcn),
            0x04 => Ok(Self::ResetStream),
            0x05 => Ok(Self::StopSending),
            0x06 => Ok(Self::Crypto),
            0x07 => Ok(Self::NewToken),
            0x08..=0x0f => Ok(Self::Stream),
            0x10 => Ok(Self::MaxData),
            0x11 => Ok(Self::MaxStreamData),
            0x12 => Ok(Self::MaxStreamsBidi),
            0x13 => Ok(Self::MaxStreamsUni),
            0x14 => Ok(Self::DataBlocked),
            0x15 => Ok(Self::StreamDataBlocked),
            0x16 => Ok(Self::StreamsBlockedBidi),
            0x17 => Ok(Self::StreamsBlockedUni),
            0x18 => Ok(Self::NewConnectionId),
            0x19 => Ok(Self::RetireConnectionId),
            0x1a => Ok(Self::PathChallenge),
            0x1b => Ok(Self::PathResponse),
            0x1c => Ok(Self::ConnectionCloseTransport),
            0x1d => Ok(Self::ConnectionCloseApp),
            0x1e => Ok(Self::HandshakeDone),
            _ => Err(Error::InvalidFrame {
                frame_type: format!("{value:#x}"),
                reason: "Unknown frame type".to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_type_conversion() {
        assert_eq!(FrameType::try_from(0x00).unwrap(), FrameType::Padding);
        assert_eq!(FrameType::try_from(0x01).unwrap(), FrameType::Ping);
        assert_eq!(FrameType::try_from(0x08).unwrap(), FrameType::Stream);
        assert_eq!(FrameType::try_from(0x0f).unwrap(), FrameType::Stream);
        assert!(FrameType::try_from(0xff).is_err());
    }

    #[test]
    fn frame_encoding_roundtrip() {
        let frame = Frame::new(FrameType::Ping, Bytes::from_static(b"test"));
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        
        let mut bytes = buf.freeze();
        let decoded = Frame::decode(&mut bytes).unwrap();
        
        assert_eq!(decoded.frame_type, FrameType::Ping);
        assert_eq!(decoded.payload.as_ref(), b"test");
    }

    #[test]
    fn frame_type_properties() {
        use crate::quic::packet::PacketType;
        
        assert!(FrameType::Padding.is_allowed_in_packet_type(PacketType::Initial));
        assert!(FrameType::Crypto.is_allowed_in_packet_type(PacketType::Handshake));
        assert!(!FrameType::NewToken.is_allowed_in_packet_type(PacketType::Initial));
        
        assert!(FrameType::MaxData.is_connection_level());
        assert!(!FrameType::Stream.is_connection_level());
    }
}