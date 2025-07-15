//! QUIC frame types implementation
//!
//! Implements all QUIC frame types according to RFC 9000 Section 12.

use crate::{
    error::{Error, Result},
    quic::{
        stream::StreamId,
        packet::ConnectionId,
    },
    util::varint::VarInt,
};
use bytes::{Buf, BufMut, Bytes};

/// QUIC frame types as defined in RFC 9000
#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    /// PADDING frame (0x00)
    Padding,
    
    /// PING frame (0x01)
    Ping,
    
    /// ACK frame (0x02-0x03)
    Ack {
        /// Largest packet number acknowledged
        largest_acknowledged: u64,
        /// ACK delay in microseconds
        ack_delay: u64,
        /// Number of additional ACK ranges
        ack_range_count: u64,
        /// Length of the first ACK range
        first_ack_range: u64,
        /// Additional ACK ranges
        ack_ranges: Vec<AckRange>,
        /// ECN counts if present
        ecn_counts: Option<EcnCounts>,
    },
    
    /// RESET_STREAM frame (0x04)
    ResetStream {
        /// Stream ID to reset
        stream_id: StreamId,
        /// Application-specific error code
        application_error_code: u64,
        /// Final size of the stream
        final_size: u64,
    },
    
    /// STOP_SENDING frame (0x05)
    StopSending {
        /// Stream ID to stop
        stream_id: StreamId,
        /// Application-specific error code
        application_error_code: u64,
    },
    
    /// CRYPTO frame (0x06)
    Crypto {
        /// Offset in the crypto stream
        offset: u64,
        /// Crypto data payload
        data: Bytes,
    },
    
    /// NEW_TOKEN frame (0x07)
    NewToken {
        /// Token data
        token: Bytes,
    },
    
    /// STREAM frame (0x08-0x0f)
    Stream {
        /// Stream identifier
        stream_id: StreamId,
        /// Offset in the stream
        offset: u64,
        /// Length of data (None if implicit)
        length: Option<u64>,
        /// Final frame indicator
        fin: bool,
        /// Stream data payload
        data: Bytes,
    },
    
    /// MAX_DATA frame (0x10)
    MaxData {
        /// Maximum data allowed on connection
        maximum_data: u64,
    },
    
    /// MAX_STREAM_DATA frame (0x11)
    MaxStreamData {
        /// Stream identifier
        stream_id: StreamId,
        /// Maximum data allowed on stream
        maximum_stream_data: u64,
    },
    
    /// MAX_STREAMS frame (0x12-0x13)
    MaxStreams {
        /// Type of streams (bidirectional or unidirectional)
        stream_type: StreamType,
        /// Maximum number of streams allowed
        maximum_streams: u64,
    },
    
    /// DATA_BLOCKED frame (0x14)
    DataBlocked {
        /// Connection-level data limit that caused blocking
        maximum_data: u64,
    },
    
    /// STREAM_DATA_BLOCKED frame (0x15)
    StreamDataBlocked {
        /// Stream that is blocked
        stream_id: StreamId,
        /// Stream-level data limit that caused blocking
        maximum_stream_data: u64,
    },
    
    /// STREAMS_BLOCKED frame (0x16-0x17)
    StreamsBlocked {
        /// Type of streams that are blocked
        stream_type: StreamType,
        /// Stream limit that caused blocking
        maximum_streams: u64,
    },
    
    /// NEW_CONNECTION_ID frame (0x18)
    NewConnectionId {
        /// Sequence number for this connection ID
        sequence_number: u64,
        /// Retire connection IDs with sequence numbers less than this
        retire_prior_to: u64,
        /// New connection identifier
        connection_id: ConnectionId,
        /// Stateless reset token for this connection ID
        stateless_reset_token: [u8; 16],
    },
    
    /// RETIRE_CONNECTION_ID frame (0x19)
    RetireConnectionId {
        /// Sequence number of connection ID to retire
        sequence_number: u64,
    },
    
    /// PATH_CHALLENGE frame (0x1a)
    PathChallenge {
        /// Challenge data
        data: [u8; 8],
    },
    
    /// PATH_RESPONSE frame (0x1b)
    PathResponse {
        /// Response data (echoed from PATH_CHALLENGE)
        data: [u8; 8],
    },
    
    /// CONNECTION_CLOSE frame (0x1c-0x1d)
    ConnectionClose {
        /// Error code for connection termination
        error_code: u64,
        /// Frame type that triggered the error (if applicable)
        frame_type: Option<u64>,
        /// Human-readable error description
        reason_phrase: Bytes,
    },
    
    /// HANDSHAKE_DONE frame (0x1e)
    HandshakeDone,
}

/// ACK range
#[derive(Debug, Clone, PartialEq)]
pub struct AckRange {
    /// Gap before this ACK range
    pub gap: u64,
    /// Length of this ACK range
    pub ack_range_length: u64,
}

/// ECN counts
#[derive(Debug, Clone, PartialEq)]
pub struct EcnCounts {
    /// ECT(0) marked packets count
    pub ect0: u64,
    /// ECT(1) marked packets count
    pub ect1: u64,
    /// ECN-CE marked packets count
    pub ecn_ce: u64,
}

/// Stream type for MAX_STREAMS and STREAMS_BLOCKED frames
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StreamType {
    /// Bidirectional stream
        Bidirectional,
    /// Unidirectional stream
        Unidirectional,
}

impl Frame {
    /// Encode frame to bytes
    pub fn encode<B: BufMut>(&self, buf: &mut B) -> Result<()> {
        match self {
            Frame::Padding => {
                buf.put_u8(0x00);
            }
            
            Frame::Ping => {
                buf.put_u8(0x01);
            }
            
            Frame::Ack { largest_acknowledged, ack_delay, ack_range_count, first_ack_range, ack_ranges, ecn_counts } => {
                let frame_type = if ecn_counts.is_some() { 0x03 } else { 0x02 };
                buf.put_u8(frame_type);
                
                VarInt(*largest_acknowledged).encode(buf)?;
                VarInt(*ack_delay).encode(buf)?;
                VarInt(*ack_range_count).encode(buf)?;
                VarInt(*first_ack_range).encode(buf)?;
                
                for range in ack_ranges {
                    VarInt(range.gap).encode(buf)?;
                    VarInt(range.ack_range_length).encode(buf)?;
                }
                
                if let Some(ecn) = ecn_counts {
                    VarInt(ecn.ect0).encode(buf)?;
                    VarInt(ecn.ect1).encode(buf)?;
                    VarInt(ecn.ecn_ce).encode(buf)?;
                }
            }
            
            Frame::ResetStream { stream_id, application_error_code, final_size } => {
                buf.put_u8(0x04);
                VarInt(stream_id.into_inner()).encode(buf)?;
                VarInt(*application_error_code).encode(buf)?;
                VarInt(*final_size).encode(buf)?;
            }
            
            Frame::StopSending { stream_id, application_error_code } => {
                buf.put_u8(0x05);
                VarInt(stream_id.into_inner()).encode(buf)?;
                VarInt(*application_error_code).encode(buf)?;
            }
            
            Frame::Crypto { offset, data } => {
                buf.put_u8(0x06);
                VarInt(*offset).encode(buf)?;
                VarInt(data.len() as u64).encode(buf)?;
                buf.put_slice(data);
            }
            
            Frame::NewToken { token } => {
                buf.put_u8(0x07);
                VarInt(token.len() as u64).encode(buf)?;
                buf.put_slice(token);
            }
            
            Frame::Stream { stream_id, offset, length, fin, data } => {
                let mut frame_type = 0x08;
                if *fin { frame_type |= 0x01; }
                if length.is_some() { frame_type |= 0x02; }
                if *offset != 0 { frame_type |= 0x04; }
                
                buf.put_u8(frame_type);
                VarInt(stream_id.into_inner()).encode(buf)?;
                
                if *offset != 0 {
                    VarInt(*offset).encode(buf)?;
                }
                
                if let Some(len) = length {
                    VarInt(*len).encode(buf)?;
                }
                
                buf.put_slice(data);
            }
            
            Frame::MaxData { maximum_data } => {
                buf.put_u8(0x10);
                VarInt(*maximum_data).encode(buf)?;
            }
            
            Frame::MaxStreamData { stream_id, maximum_stream_data } => {
                buf.put_u8(0x11);
                VarInt(stream_id.into_inner()).encode(buf)?;
                VarInt(*maximum_stream_data).encode(buf)?;
            }
            
            Frame::MaxStreams { stream_type, maximum_streams } => {
                let frame_type = match stream_type {
                    StreamType::Bidirectional => 0x12,
                    StreamType::Unidirectional => 0x13,
                };
                buf.put_u8(frame_type);
                VarInt(*maximum_streams).encode(buf)?;
            }
            
            Frame::DataBlocked { maximum_data } => {
                buf.put_u8(0x14);
                VarInt(*maximum_data).encode(buf)?;
            }
            
            Frame::StreamDataBlocked { stream_id, maximum_stream_data } => {
                buf.put_u8(0x15);
                VarInt(stream_id.into_inner()).encode(buf)?;
                VarInt(*maximum_stream_data).encode(buf)?;
            }
            
            Frame::StreamsBlocked { stream_type, maximum_streams } => {
                let frame_type = match stream_type {
                    StreamType::Bidirectional => 0x16,
                    StreamType::Unidirectional => 0x17,
                };
                buf.put_u8(frame_type);
                VarInt(*maximum_streams).encode(buf)?;
            }
            
            Frame::NewConnectionId { sequence_number, retire_prior_to, connection_id, stateless_reset_token } => {
                buf.put_u8(0x18);
                VarInt(*sequence_number).encode(buf)?;
                VarInt(*retire_prior_to).encode(buf)?;
                buf.put_u8(connection_id.len() as u8);
                buf.put_slice(connection_id.as_bytes());
                buf.put_slice(stateless_reset_token);
            }
            
            Frame::RetireConnectionId { sequence_number } => {
                buf.put_u8(0x19);
                VarInt(*sequence_number).encode(buf)?;
            }
            
            Frame::PathChallenge { data } => {
                buf.put_u8(0x1a);
                buf.put_slice(data);
            }
            
            Frame::PathResponse { data } => {
                buf.put_u8(0x1b);
                buf.put_slice(data);
            }
            
            Frame::ConnectionClose { error_code, frame_type, reason_phrase } => {
                let frame_type_byte = if frame_type.is_some() { 0x1c } else { 0x1d };
                buf.put_u8(frame_type_byte);
                VarInt(*error_code).encode(buf)?;
                
                if let Some(ft) = frame_type {
                    VarInt(*ft).encode(buf)?;
                }
                
                VarInt(reason_phrase.len() as u64).encode(buf)?;
                buf.put_slice(reason_phrase);
            }
            
            Frame::HandshakeDone => {
                buf.put_u8(0x1e);
            }
        }
        
        Ok(())
    }
    
    /// Decode frame from bytes
    pub fn decode<B: Buf>(buf: &mut B) -> Result<Self> {
        if !buf.has_remaining() {
            return Err(Error::Incomplete);
        }
        
        let frame_type = buf.get_u8();
        
        match frame_type {
            0x00 => Ok(Frame::Padding),
            0x01 => Ok(Frame::Ping),
            
            0x02 | 0x03 => {
                let largest_acknowledged = VarInt::decode(buf)?.into_inner();
                let ack_delay = VarInt::decode(buf)?.into_inner();
                let ack_range_count = VarInt::decode(buf)?.into_inner();
                let first_ack_range = VarInt::decode(buf)?.into_inner();
                
                let mut ack_ranges = Vec::with_capacity(ack_range_count as usize);
                for _ in 0..ack_range_count {
                    let gap = VarInt::decode(buf)?.into_inner();
                    let ack_range_length = VarInt::decode(buf)?.into_inner();
                    ack_ranges.push(AckRange { gap, ack_range_length });
                }
                
                let ecn_counts = if frame_type == 0x03 {
                    Some(EcnCounts {
                        ect0: VarInt::decode(buf)?.into_inner(),
                        ect1: VarInt::decode(buf)?.into_inner(),
                        ecn_ce: VarInt::decode(buf)?.into_inner(),
                    })
                } else {
                    None
                };
                
                Ok(Frame::Ack {
                    largest_acknowledged,
                    ack_delay,
                    ack_range_count,
                    first_ack_range,
                    ack_ranges,
                    ecn_counts,
                })
            }
            
            0x04 => {
                let stream_id = StreamId::from(VarInt::decode(buf)?.into_inner());
                let application_error_code = VarInt::decode(buf)?.into_inner();
                let final_size = VarInt::decode(buf)?.into_inner();
                Ok(Frame::ResetStream { stream_id, application_error_code, final_size })
            }
            
            0x05 => {
                let stream_id = StreamId::from(VarInt::decode(buf)?.into_inner());
                let application_error_code = VarInt::decode(buf)?.into_inner();
                Ok(Frame::StopSending { stream_id, application_error_code })
            }
            
            0x06 => {
                let offset = VarInt::decode(buf)?.into_inner();
                let length = VarInt::decode(buf)?.into_inner() as usize;
                
                if buf.remaining() < length {
                    return Err(Error::Incomplete);
                }
                
                let mut data = vec![0u8; length];
                buf.copy_to_slice(&mut data);
                
                Ok(Frame::Crypto { offset, data: data.into() })
            }
            
            0x07 => {
                let length = VarInt::decode(buf)?.into_inner() as usize;
                
                if buf.remaining() < length {
                    return Err(Error::Incomplete);
                }
                
                let mut token = vec![0u8; length];
                buf.copy_to_slice(&mut token);
                
                Ok(Frame::NewToken { token: token.into() })
            }
            
            0x08..=0x0f => {
                let fin = (frame_type & 0x01) != 0;
                let has_length = (frame_type & 0x02) != 0;
                let has_offset = (frame_type & 0x04) != 0;
                
                let stream_id = StreamId::from(VarInt::decode(buf)?.into_inner());
                
                let offset = if has_offset {
                    VarInt::decode(buf)?.into_inner()
                } else {
                    0
                };
                
                let length = if has_length {
                    Some(VarInt::decode(buf)?.into_inner())
                } else {
                    None
                };
                
                let data_len = if let Some(len) = length {
                    len as usize
                } else {
                    buf.remaining()
                };
                
                if buf.remaining() < data_len {
                    return Err(Error::Incomplete);
                }
                
                let mut data = vec![0u8; data_len];
                buf.copy_to_slice(&mut data);
                
                Ok(Frame::Stream {
                    stream_id,
                    offset,
                    length,
                    fin,
                    data: data.into(),
                })
            }
            
            0x10 => {
                let maximum_data = VarInt::decode(buf)?.into_inner();
                Ok(Frame::MaxData { maximum_data })
            }
            
            0x11 => {
                let stream_id = StreamId::from(VarInt::decode(buf)?.into_inner());
                let maximum_stream_data = VarInt::decode(buf)?.into_inner();
                Ok(Frame::MaxStreamData { stream_id, maximum_stream_data })
            }
            
            0x12 => {
                let maximum_streams = VarInt::decode(buf)?.into_inner();
                Ok(Frame::MaxStreams {
                    stream_type: StreamType::Bidirectional,
                    maximum_streams,
                })
            }
            
            0x13 => {
                let maximum_streams = VarInt::decode(buf)?.into_inner();
                Ok(Frame::MaxStreams {
                    stream_type: StreamType::Unidirectional,
                    maximum_streams,
                })
            }
            
            0x14 => {
                let maximum_data = VarInt::decode(buf)?.into_inner();
                Ok(Frame::DataBlocked { maximum_data })
            }
            
            0x15 => {
                let stream_id = StreamId::from(VarInt::decode(buf)?.into_inner());
                let maximum_stream_data = VarInt::decode(buf)?.into_inner();
                Ok(Frame::StreamDataBlocked { stream_id, maximum_stream_data })
            }
            
            0x16 => {
                let maximum_streams = VarInt::decode(buf)?.into_inner();
                Ok(Frame::StreamsBlocked {
                    stream_type: StreamType::Bidirectional,
                    maximum_streams,
                })
            }
            
            0x17 => {
                let maximum_streams = VarInt::decode(buf)?.into_inner();
                Ok(Frame::StreamsBlocked {
                    stream_type: StreamType::Unidirectional,
                    maximum_streams,
                })
            }
            
            0x18 => {
                let sequence_number = VarInt::decode(buf)?.into_inner();
                let retire_prior_to = VarInt::decode(buf)?.into_inner();
                let cid_len = buf.get_u8() as usize;
                
                if buf.remaining() < cid_len + 16 {
                    return Err(Error::Incomplete);
                }
                
                let mut cid_bytes = vec![0u8; cid_len];
                buf.copy_to_slice(&mut cid_bytes);
                let connection_id = ConnectionId::from(cid_bytes);
                
                let mut stateless_reset_token = [0u8; 16];
                buf.copy_to_slice(&mut stateless_reset_token);
                
                Ok(Frame::NewConnectionId {
                    sequence_number,
                    retire_prior_to,
                    connection_id,
                    stateless_reset_token,
                })
            }
            
            0x19 => {
                let sequence_number = VarInt::decode(buf)?.into_inner();
                Ok(Frame::RetireConnectionId { sequence_number })
            }
            
            0x1a => {
                if buf.remaining() < 8 {
                    return Err(Error::Incomplete);
                }
                let mut data = [0u8; 8];
                buf.copy_to_slice(&mut data);
                Ok(Frame::PathChallenge { data })
            }
            
            0x1b => {
                if buf.remaining() < 8 {
                    return Err(Error::Incomplete);
                }
                let mut data = [0u8; 8];
                buf.copy_to_slice(&mut data);
                Ok(Frame::PathResponse { data })
            }
            
            0x1c | 0x1d => {
                let error_code = VarInt::decode(buf)?.into_inner();
                
                let frame_type = if frame_type == 0x1c {
                    Some(VarInt::decode(buf)?.into_inner())
                } else {
                    None
                };
                
                let reason_length = VarInt::decode(buf)?.into_inner() as usize;
                
                if buf.remaining() < reason_length {
                    return Err(Error::Incomplete);
                }
                
                let mut reason_phrase = vec![0u8; reason_length];
                buf.copy_to_slice(&mut reason_phrase);
                
                Ok(Frame::ConnectionClose {
                    error_code,
                    frame_type,
                    reason_phrase: reason_phrase.into(),
                })
            }
            
            0x1e => Ok(Frame::HandshakeDone),
            
            _ => Err(Error::InvalidFrame {
                frame_type: format!("0x{:02x}", frame_type),
                reason: "Unknown frame type".to_string()
            }),
        }
    }
    
    /// Check if frame is allowed in packet type
    pub fn is_allowed_in_packet_type(&self, packet_type: crate::quic::packet::PacketType) -> bool {
        use crate::quic::packet::PacketType;
        
        match self {
            Frame::Padding | Frame::Ping => true, // Allowed in all packet types
            
            Frame::Ack { .. } => match packet_type {
                PacketType::Initial | PacketType::Handshake | PacketType::OneRtt => true,
                _ => false,
            },
            
            Frame::Crypto { .. } => match packet_type {
                PacketType::Initial | PacketType::Handshake | PacketType::OneRtt => true,
                _ => false,
            },
            
            Frame::NewToken { .. } | Frame::Stream { .. } | Frame::MaxData { .. } |
            Frame::MaxStreamData { .. } | Frame::MaxStreams { .. } | Frame::DataBlocked { .. } |
            Frame::StreamDataBlocked { .. } | Frame::StreamsBlocked { .. } |
            Frame::NewConnectionId { .. } | Frame::RetireConnectionId { .. } |
            Frame::PathChallenge { .. } | Frame::PathResponse { .. } |
            Frame::HandshakeDone => {
                matches!(packet_type, PacketType::OneRtt)
            }
            
            Frame::ResetStream { .. } | Frame::StopSending { .. } => {
                matches!(packet_type, PacketType::ZeroRtt | PacketType::OneRtt)
            }
            
            Frame::ConnectionClose { .. } => true, // Allowed in all packet types
        }
    }
}