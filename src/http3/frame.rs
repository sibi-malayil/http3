//! HTTP/3 frame types implementation
//!
//! Implements frame format according to RFC 9114 Section 7.

use crate::{
    error::{Error, Result, Http3ErrorCode},
    util::{varint::VarInt, buffer::{BufExt, BufMutExt}},
    http3::{settings::Settings, priority::PriorityUpdateFrame},
};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// HTTP/3 frame types as defined in RFC 9114 Section 7.2 and RFC 9297
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Http3FrameType {
    /// DATA frame (0x00)
    Data = 0x00,
    /// HEADERS frame (0x01)
    Headers = 0x01,
    /// CANCEL_PUSH frame (0x03)
    CancelPush = 0x03,
    /// SETTINGS frame (0x04)
    Settings = 0x04,
    /// PUSH_PROMISE frame (0x05)
    PushPromise = 0x05,
    /// GOAWAY frame (0x07)
    Goaway = 0x07,
    /// MAX_PUSH_ID frame (0x0d)
    MaxPushId = 0x0d,
    /// PRIORITY_UPDATE frame (0x0f) - RFC 9297
    PriorityUpdate = 0x0f,
    /// MAX_STREAMS frame (0x12)
    MaxStreams = 0x12,
    /// STREAMS_BLOCKED frame (0x16)
    StreamsBlocked = 0x16,
    /// DATAGRAM frame (0x30) - RFC 9297
    Datagram = 0x30,
}

impl Http3FrameType {
    /// Returns the frame type identifier
    pub fn id(self) -> u64 {
        self as u64
    }

    /// Creates a frame type from identifier
    pub fn from_id(id: u64) -> Option<Self> {
        match id {
            0x00 => Some(Self::Data),
            0x01 => Some(Self::Headers),
            0x03 => Some(Self::CancelPush),
            0x04 => Some(Self::Settings),
            0x05 => Some(Self::PushPromise),
            0x07 => Some(Self::Goaway),
            0x0d => Some(Self::MaxPushId),
            0x0f => Some(Self::PriorityUpdate),
            0x12 => Some(Self::MaxStreams),
            0x16 => Some(Self::StreamsBlocked),
            0x30 => Some(Self::Datagram),
            _ => None,
        }
    }

    /// Returns true if this frame type is valid on request streams
    pub fn valid_on_request_stream(self) -> bool {
        matches!(self, Self::Data | Self::Headers | Self::Datagram)
    }

    /// Returns true if this frame type is valid on control streams
    pub fn valid_on_control_stream(self) -> bool {
        matches!(
            self,
            Self::CancelPush | Self::Settings | Self::Goaway | Self::MaxPushId | Self::PriorityUpdate | Self::MaxStreams | Self::StreamsBlocked
        )
    }

    /// Returns true if this frame type is valid on push streams
    pub fn valid_on_push_stream(self) -> bool {
        matches!(self, Self::Data | Self::Headers)
    }

    /// Returns true if this frame type requires a connection
    pub fn requires_connection(self) -> bool {
        matches!(
            self,
            Self::CancelPush | Self::Settings | Self::Goaway | Self::MaxPushId | Self::PriorityUpdate | Self::MaxStreams | Self::StreamsBlocked
        )
    }
}

/// HTTP/3 frame representation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http3Frame {
    /// DATA frame - carries request/response body
    Data(DataFrame),
    /// HEADERS frame - carries header field section
    Headers(HeadersFrame),
    /// CANCEL_PUSH frame - cancels server push
    CancelPush(CancelPushFrame),
    /// SETTINGS frame - communicates configuration parameters
    Settings(SettingsFrame),
    /// PUSH_PROMISE frame - announces server push
    PushPromise(PushPromiseFrame),
    /// GOAWAY frame - graceful connection termination
    Goaway(GoawayFrame),
    /// MAX_PUSH_ID frame - controls server push
    MaxPushId(MaxPushIdFrame),
    /// PRIORITY_UPDATE frame - updates stream priority (RFC 9297)
    PriorityUpdate(PriorityUpdateFrame),
    /// MAX_STREAMS frame - stream limit control
    MaxStreams(MaxStreamsFrame),
    /// STREAMS_BLOCKED frame - stream limit notification
    StreamsBlocked(StreamsBlockedFrame),
    /// DATAGRAM frame - unreliable data transmission (RFC 9297)
    Datagram(DatagramFrame),
    /// Unknown frame type - for extensibility
    Unknown {
        /// The unknown frame type identifier
        frame_type: VarInt,
        /// Raw frame payload
        payload: Bytes,
    },
}

impl Http3Frame {
    /// Returns the frame type
    pub fn frame_type(&self) -> Http3FrameType {
        match self {
            Self::Data(_) => Http3FrameType::Data,
            Self::Headers(_) => Http3FrameType::Headers,
            Self::CancelPush(_) => Http3FrameType::CancelPush,
            Self::Settings(_) => Http3FrameType::Settings,
            Self::PushPromise(_) => Http3FrameType::PushPromise,
            Self::Goaway(_) => Http3FrameType::Goaway,
            Self::MaxPushId(_) => Http3FrameType::MaxPushId,
            Self::PriorityUpdate(_) => Http3FrameType::PriorityUpdate,
            Self::MaxStreams(_) => Http3FrameType::MaxStreams,
            Self::StreamsBlocked(_) => Http3FrameType::StreamsBlocked,
            Self::Datagram(_) => Http3FrameType::Datagram,
            Self::Unknown { .. } => Http3FrameType::Data, // Default for unknown
        }
    }

    /// Encodes the frame into bytes
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        match self {
            Self::Data(frame) => frame.encode(buf),
            Self::Headers(frame) => frame.encode(buf),
            Self::CancelPush(frame) => frame.encode(buf),
            Self::Settings(frame) => frame.encode(buf),
            Self::PushPromise(frame) => frame.encode(buf),
            Self::Goaway(frame) => frame.encode(buf),
            Self::MaxPushId(frame) => frame.encode(buf),
            Self::PriorityUpdate(frame) => frame.encode(buf),
            Self::MaxStreams(frame) => frame.encode(buf),
            Self::StreamsBlocked(frame) => frame.encode(buf),
            Self::Datagram(frame) => frame.encode(buf),
            Self::Unknown { frame_type, payload } => {
                buf.put_var(*frame_type);
                buf.put_var(VarInt::try_from(payload.len())?);
                buf.put(payload.as_ref());
                Ok(())
            }
        }
    }

    /// Decodes a frame from bytes
    pub fn decode(mut buf: Bytes) -> Result<Self> {
        if buf.remaining() < 2 {
            return Err(Error::Http3Error {
                code: Http3ErrorCode::FrameError,
                reason: "Insufficient data for frame header".to_string(),
            });
        }

        let frame_type_raw = buf.get_var()?;
        let length = buf.get_var()?;

        if buf.remaining() < length.into_inner() as usize {
            return Err(Error::Http3Error {
                code: Http3ErrorCode::FrameError,
                reason: "Insufficient data for frame payload".to_string(),
            });
        }

        let payload = buf.get_bytes(length.into_inner() as usize).unwrap();

        match Http3FrameType::from_id(frame_type_raw.into_inner()) {
            Some(Http3FrameType::Data) => Ok(Self::Data(DataFrame::decode(payload)?)),
            Some(Http3FrameType::Headers) => Ok(Self::Headers(HeadersFrame::decode(payload)?)),
            Some(Http3FrameType::CancelPush) => {
                Ok(Self::CancelPush(CancelPushFrame::decode(payload)?))
            }
            Some(Http3FrameType::Settings) => {
                Ok(Self::Settings(SettingsFrame::decode(payload)?))
            }
            Some(Http3FrameType::PushPromise) => {
                Ok(Self::PushPromise(PushPromiseFrame::decode(payload)?))
            }
            Some(Http3FrameType::Goaway) => Ok(Self::Goaway(GoawayFrame::decode(payload)?)),
            Some(Http3FrameType::MaxPushId) => {
                Ok(Self::MaxPushId(MaxPushIdFrame::decode(payload)?))
            }
            Some(Http3FrameType::PriorityUpdate) => {
                Ok(Self::PriorityUpdate(PriorityUpdateFrame::decode(payload)?))
            }
            Some(Http3FrameType::MaxStreams) => {
                Ok(Self::MaxStreams(MaxStreamsFrame::decode(payload)?))
            }
            Some(Http3FrameType::StreamsBlocked) => {
                Ok(Self::StreamsBlocked(StreamsBlockedFrame::decode(payload)?))
            }
            Some(Http3FrameType::Datagram) => {
                Ok(Self::Datagram(DatagramFrame::decode(payload)?))
            }
            None => Ok(Self::Unknown {
                frame_type: frame_type_raw,
                payload,
            }),
        }
    }

    /// Returns the frame size in bytes
    pub fn size(&self) -> usize {
        let payload_size = match self {
            Self::Data(frame) => frame.data.len(),
            Self::Headers(frame) => frame.field_section.len(),
            Self::CancelPush(_) => VarInt::size(VarInt::from_u64(0).unwrap()),
            Self::Settings(frame) => frame.encoded_size(),
            Self::PushPromise(frame) => {
                VarInt::size(frame.push_id) + frame.field_section.len()
            }
            Self::Goaway(_) => VarInt::size(VarInt::from_u64(0).unwrap()),
            Self::MaxPushId(_) => VarInt::size(VarInt::from_u64(0).unwrap()),
            Self::PriorityUpdate(frame) => {
                VarInt::size(frame.prioritized_element_id) + frame.priority_field_value.len()
            }
            Self::MaxStreams(_) => 1 + VarInt::size(VarInt::from_u64(0).unwrap()),
            Self::StreamsBlocked(_) => 1 + VarInt::size(VarInt::from_u64(0).unwrap()),
            Self::Datagram(frame) => frame.data.len(),
            Self::Unknown { payload, .. } => payload.len(),
        };

        let frame_type_size = VarInt::size(VarInt::try_from(self.frame_type().id()).unwrap());
        let length_size = VarInt::size(VarInt::try_from(payload_size).unwrap());

        frame_type_size + length_size + payload_size
    }

    /// Validates frame context
    pub fn validate_context(&self, stream_type: &str) -> Result<()> {
        let frame_type = self.frame_type();

        match stream_type {
            "request" => {
                if !frame_type.valid_on_request_stream() {
                    return Err(Error::Http3Error {
                        code: Http3ErrorCode::FrameUnexpected,
                        reason: format!("{:?} frame not allowed on request stream", frame_type),
                    });
                }
            }
            "control" => {
                if !frame_type.valid_on_control_stream() {
                    return Err(Error::Http3Error {
                        code: Http3ErrorCode::FrameUnexpected,
                        reason: format!("{:?} frame not allowed on control stream", frame_type),
                    });
                }
            }
            "push" => {
                if !frame_type.valid_on_push_stream() {
                    return Err(Error::Http3Error {
                        code: Http3ErrorCode::FrameUnexpected,
                        reason: format!("{:?} frame not allowed on push stream", frame_type),
                    });
                }
            }
            _ => {
                return Err(Error::Http3Error {
                    code: Http3ErrorCode::InternalError,
                    reason: "Unknown stream type".to_string(),
                });
            }
        }

        Ok(())
    }
}

/// DATA frame - carries HTTP request/response body data
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataFrame {
    /// The payload data
    pub data: Bytes,
}

impl DataFrame {
    /// Creates a new DATA frame
    pub fn new(data: Bytes) -> Self {
        Self { data }
    }

    /// Encodes the frame
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        buf.put_var(VarInt::try_from(Http3FrameType::Data.id())?);
        buf.put_var(VarInt::try_from(self.data.len())?);
        buf.put(self.data.as_ref());
        Ok(())
    }

    /// Decodes the frame
    pub fn decode(payload: Bytes) -> Result<Self> {
        Ok(Self { data: payload })
    }

    /// Returns true if the frame is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the data length
    pub fn len(&self) -> usize {
        self.data.len()
    }
}

/// HEADERS frame - carries HTTP header field section
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadersFrame {
    /// The encoded header field section (QPACK encoded)
    pub field_section: Bytes,
}

impl HeadersFrame {
    /// Creates a new HEADERS frame
    pub fn new(field_section: Bytes) -> Self {
        Self { field_section }
    }

    /// Encodes the frame
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        buf.put_var(VarInt::try_from(Http3FrameType::Headers.id())?);
        buf.put_var(VarInt::try_from(self.field_section.len())?);
        buf.put(self.field_section.as_ref());
        Ok(())
    }

    /// Decodes the frame
    pub fn decode(payload: Bytes) -> Result<Self> {
        Ok(Self {
            field_section: payload,
        })
    }

    /// Returns the field section length
    pub fn len(&self) -> usize {
        self.field_section.len()
    }

    /// Returns true if the field section is empty
    pub fn is_empty(&self) -> bool {
        self.field_section.is_empty()
    }
}

/// CANCEL_PUSH frame - cancels a server push
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelPushFrame {
    /// Push ID to cancel
    pub push_id: VarInt,
}

impl CancelPushFrame {
    /// Creates a new CANCEL_PUSH frame
    pub fn new(push_id: VarInt) -> Self {
        Self { push_id }
    }

    /// Encodes the frame
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        buf.put_var(VarInt::try_from(Http3FrameType::CancelPush.id())?);
        buf.put_var(VarInt::try_from(VarInt::size(self.push_id))?);
        buf.put_var(self.push_id);
        Ok(())
    }

    /// Decodes the frame
    pub fn decode(mut payload: Bytes) -> Result<Self> {
        if payload.is_empty() {
            return Err(Error::Http3Error {
                code: Http3ErrorCode::FrameError,
                reason: "Empty CANCEL_PUSH frame".to_string(),
            });
        }

        let push_id = payload.get_var()?;
        Ok(Self { push_id })
    }
}

/// SETTINGS frame - communicates configuration parameters
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsFrame {
    /// Settings parameters
    pub settings: Settings,
}

impl SettingsFrame {
    /// Creates a new SETTINGS frame
    pub fn new(settings: Settings) -> Self {
        Self { settings }
    }

    /// Encodes the frame
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        buf.put_var(VarInt::try_from(Http3FrameType::Settings.id())?);
        
        let mut settings_buf = BytesMut::new();
        self.settings.encode(&mut settings_buf)?;
        
        buf.put_var(VarInt::try_from(settings_buf.len())?);
        buf.put(settings_buf);
        Ok(())
    }

    /// Decodes the frame
    pub fn decode(payload: Bytes) -> Result<Self> {
        let settings = Settings::decode(&payload)?;
        Ok(Self { settings })
    }

    /// Returns the encoded size
    pub fn encoded_size(&self) -> usize {
        let mut buf = BytesMut::new();
        self.settings.encode(&mut buf).unwrap();
        buf.len()
    }
}

/// PUSH_PROMISE frame - announces a server push
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushPromiseFrame {
    /// Push ID for the promised resource
    pub push_id: VarInt,
    /// The encoded header field section (QPACK encoded)
    pub field_section: Bytes,
}

impl PushPromiseFrame {
    /// Creates a new PUSH_PROMISE frame
    pub fn new(push_id: VarInt, field_section: Bytes) -> Self {
        Self {
            push_id,
            field_section,
        }
    }

    /// Encodes the frame
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        buf.put_var(VarInt::try_from(Http3FrameType::PushPromise.id())?);
        
        let payload_len = VarInt::size(self.push_id) + self.field_section.len();
        buf.put_var(VarInt::try_from(payload_len)?);
        buf.put_var(self.push_id);
        buf.put(self.field_section.as_ref());
        Ok(())
    }

    /// Decodes the frame
    pub fn decode(mut payload: Bytes) -> Result<Self> {
        if payload.remaining() < VarInt::size(VarInt::from_u32(0)) {
            return Err(Error::Http3Error {
                code: Http3ErrorCode::FrameError,
                reason: "Insufficient data for PUSH_PROMISE push ID".to_string(),
            });
        }

        let push_id = payload.get_var()?;
        let field_section = payload;

        Ok(Self {
            push_id,
            field_section,
        })
    }
}

/// GOAWAY frame - graceful connection termination
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoawayFrame {
    /// Stream ID of the last processed stream
    pub stream_id: VarInt,
}

impl GoawayFrame {
    /// Creates a new GOAWAY frame
    pub fn new(stream_id: VarInt) -> Self {
        Self { stream_id }
    }

    /// Encodes the frame
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        buf.put_var(VarInt::try_from(Http3FrameType::Goaway.id())?);
        buf.put_var(VarInt::try_from(VarInt::size(self.stream_id))?);
        buf.put_var(self.stream_id);
        Ok(())
    }

    /// Decodes the frame
    pub fn decode(mut payload: Bytes) -> Result<Self> {
        if payload.is_empty() {
            return Err(Error::Http3Error {
                code: Http3ErrorCode::FrameError,
                reason: "Empty GOAWAY frame".to_string(),
            });
        }

        let stream_id = payload.get_var()?;
        Ok(Self { stream_id })
    }
}

/// MAX_PUSH_ID frame - controls server push
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaxPushIdFrame {
    /// Maximum push ID
    pub push_id: VarInt,
}

impl MaxPushIdFrame {
    /// Creates a new MAX_PUSH_ID frame
    pub fn new(push_id: VarInt) -> Self {
        Self { push_id }
    }

    /// Encodes the frame
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        buf.put_var(VarInt::try_from(Http3FrameType::MaxPushId.id())?);
        buf.put_var(VarInt::try_from(VarInt::size(self.push_id))?);
        buf.put_var(self.push_id);
        Ok(())
    }

    /// Decodes the frame
    pub fn decode(mut payload: Bytes) -> Result<Self> {
        if payload.is_empty() {
            return Err(Error::Http3Error {
                code: Http3ErrorCode::FrameError,
                reason: "Empty MAX_PUSH_ID frame".to_string(),
            });
        }

        let push_id = payload.get_var()?;
        Ok(Self { push_id })
    }
}

/// Frame parsing utilities
pub struct FrameParser {
    /// Buffer for accumulating frame data
    buffer: BytesMut,
    /// Expected frame length
    expected_length: Option<usize>,
    /// Frame type being parsed
    frame_type: Option<VarInt>,
}

impl FrameParser {
    /// Creates a new frame parser
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::new(),
            expected_length: None,
            frame_type: None,
        }
    }

    /// Adds data to the parser
    pub fn push_data(&mut self, data: Bytes) {
        self.buffer.extend_from_slice(&data);
    }

    /// Attempts to parse a complete frame
    pub fn parse_frame(&mut self) -> Result<Option<Http3Frame>> {
        loop {
            // If we don't have a frame type yet, try to read it
            if self.frame_type.is_none()
                && !self.try_read_frame_header()? {
                    return Ok(None);
                }

            // Check if we have enough data for the complete frame
            if let Some(expected_len) = self.expected_length {
                if self.buffer.len() >= expected_len {
                    // Extract the frame data
                    let frame_data = self.buffer.split_to(expected_len);
                    
                    // Reset parser state
                    self.frame_type = None;
                    self.expected_length = None;
                    
                    // Parse the frame
                    return Ok(Some(Http3Frame::decode(frame_data.freeze())?));
                }
                return Ok(None); // Need more data
            }
        }
    }

    /// Tries to read the frame header (type and length)
    fn try_read_frame_header(&mut self) -> Result<bool> {
        let mut temp_buf = self.buffer.clone();
        
        // Try to read frame type
        if temp_buf.remaining() < 1 {
            return Ok(false);
        }
        
        let frame_type = match temp_buf.get_var() {
            Ok(ft) => ft,
            Err(_) => return Ok(false), // Need more data
        };
        
        // Try to read frame length
        if temp_buf.remaining() < 1 {
            return Ok(false);
        }
        
        let frame_length = match temp_buf.get_var() {
            Ok(fl) => fl,
            Err(_) => return Ok(false), // Need more data
        };
        
        // Calculate total frame size (header + payload)
        let header_size = self.buffer.len() - temp_buf.remaining();
        let total_size = header_size + frame_length.into_inner() as usize;
        
        self.frame_type = Some(frame_type);
        self.expected_length = Some(total_size);
        
        Ok(true)
    }

    /// Returns the current buffer length
    pub fn buffer_len(&self) -> usize {
        self.buffer.len()
    }

    /// Clears the parser state
    pub fn clear(&mut self) {
        self.buffer.clear();
        self.frame_type = None;
        self.expected_length = None;
    }
}

impl Default for FrameParser {
    fn default() -> Self {
        Self::new()
    }
}

/// MAX_STREAMS frame - controls stream limits
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaxStreamsFrame {
    /// Stream type: 0 = bidirectional, 1 = unidirectional
    pub stream_type: u8,
    /// Maximum number of streams
    pub maximum_streams: VarInt,
}

impl MaxStreamsFrame {
    /// Create a new MAX_STREAMS frame
    pub fn new(stream_type: u8, maximum_streams: VarInt) -> Self {
        Self {
            stream_type,
            maximum_streams,
        }
    }

    /// Encode the frame
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        buf.put_var(VarInt::try_from(Http3FrameType::MaxStreams.id())?);
        buf.put_var(VarInt::try_from(1 + VarInt::size(self.maximum_streams))?);
        buf.extend_from_slice(&[self.stream_type]);
        buf.put_var(self.maximum_streams);
        Ok(())
    }

    /// Decode the frame
    pub fn decode(mut payload: Bytes) -> Result<Self> {
        if payload.is_empty() {
            return Err(Error::Http3Error {
                code: Http3ErrorCode::FrameError,
                reason: "Empty MAX_STREAMS frame payload".to_string(),
            });
        }

        let stream_type = payload[0];
        payload.advance(1);

        let maximum_streams = VarInt::decode(&mut payload)?;

        Ok(Self {
            stream_type,
            maximum_streams,
        })
    }
}

/// STREAMS_BLOCKED frame - stream limit notification
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamsBlockedFrame {
    /// Stream type: 0 = bidirectional, 1 = unidirectional
    pub stream_type: u8,
    /// Maximum stream ID that can be opened
    pub maximum_streams: VarInt,
}

impl StreamsBlockedFrame {
    /// Create a new STREAMS_BLOCKED frame
    pub fn new(stream_type: u8, maximum_streams: VarInt) -> Self {
        Self {
            stream_type,
            maximum_streams,
        }
    }

    /// Encode the frame
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        buf.put_var(VarInt::try_from(Http3FrameType::StreamsBlocked.id())?);
        buf.put_var(VarInt::try_from(1 + VarInt::size(self.maximum_streams))?);
        buf.extend_from_slice(&[self.stream_type]);
        buf.put_var(self.maximum_streams);
        Ok(())
    }

    /// Decode the frame
    pub fn decode(mut payload: Bytes) -> Result<Self> {
        if payload.is_empty() {
            return Err(Error::Http3Error {
                code: Http3ErrorCode::FrameError,
                reason: "Empty STREAMS_BLOCKED frame payload".to_string(),
            });
        }

        let stream_type = payload[0];
        payload.advance(1);

        let maximum_streams = VarInt::decode(&mut payload)?;

        Ok(Self {
            stream_type,
            maximum_streams,
        })
    }
}

/// DATAGRAM frame - RFC 9297
/// 
/// The DATAGRAM frame carries application data in an unreliable manner.
/// Data sent in DATAGRAM frames is not retransmitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramFrame {
    /// Datagram data
    pub data: Bytes,
}

impl DatagramFrame {
    /// Create a new DATAGRAM frame
    pub fn new(data: Bytes) -> Self {
        Self { data }
    }

    /// Encode the frame to bytes
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        // Encode frame type
        buf.put_var(VarInt::from_u32(Http3FrameType::Datagram.id() as u32));
        
        // Encode length
        let length = self.data.len() as u64;
        buf.put_var(VarInt::try_from(length)?);
        
        // Encode payload
        buf.put(self.data.as_ref());
        
        Ok(())
    }

    /// Decode frame from payload bytes
    pub fn decode(payload: Bytes) -> Result<Self> {
        // For DATAGRAM frames, the entire payload is the datagram data
        Ok(Self { data: payload })
    }

    /// Get the length of the datagram data
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the datagram is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_frame_encoding_roundtrip() {
        let original_data = Bytes::from_static(b"Hello, HTTP/3!");
        let frame = DataFrame::new(original_data.clone());
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        
        let decoded_frame = Http3Frame::decode(buf.freeze()).unwrap();
        
        match decoded_frame {
            Http3Frame::Data(decoded) => {
                assert_eq!(decoded.data, original_data);
            }
            _ => panic!("Expected DATA frame"),
        }
    }

    #[test]
    fn headers_frame_encoding_roundtrip() {
        let field_section = Bytes::from_static(b"\x00\x00\x88\x61\x65\x5f\x0b\x0c\x0d");
        let frame = HeadersFrame::new(field_section.clone());
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        
        let decoded_frame = Http3Frame::decode(buf.freeze()).unwrap();
        
        match decoded_frame {
            Http3Frame::Headers(decoded) => {
                assert_eq!(decoded.field_section, field_section);
            }
            _ => panic!("Expected HEADERS frame"),
        }
    }

    #[test]
    fn settings_frame_encoding_roundtrip() {
        let settings = Settings::new();
        
        let frame = SettingsFrame::new(settings.clone());
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        
        let decoded_frame = Http3Frame::decode(buf.freeze()).unwrap();
        
        match decoded_frame {
            Http3Frame::Settings(decoded) => {
                assert_eq!(decoded.settings, settings);
            }
            _ => panic!("Expected SETTINGS frame"),
        }
    }

    #[test]
    fn cancel_push_frame_encoding_roundtrip() {
        let push_id = VarInt::from_u32(42);
        let frame = CancelPushFrame::new(push_id);
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        
        let decoded_frame = Http3Frame::decode(buf.freeze()).unwrap();
        
        match decoded_frame {
            Http3Frame::CancelPush(decoded) => {
                assert_eq!(decoded.push_id, push_id);
            }
            _ => panic!("Expected CANCEL_PUSH frame"),
        }
    }

    #[test]
    fn push_promise_frame_encoding_roundtrip() {
        let push_id = VarInt::from_u32(42);
        let field_section = Bytes::from_static(b"\x00\x00\x88\x61\x65\x5f\x0b\x0c\x0d");
        let frame = PushPromiseFrame::new(push_id, field_section.clone());
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        
        let decoded_frame = Http3Frame::decode(buf.freeze()).unwrap();
        
        match decoded_frame {
            Http3Frame::PushPromise(decoded) => {
                assert_eq!(decoded.push_id, push_id);
                assert_eq!(decoded.field_section, field_section);
            }
            _ => panic!("Expected PUSH_PROMISE frame"),
        }
    }

    #[test]
    fn goaway_frame_encoding_roundtrip() {
        let stream_id = VarInt::from_u32(100);
        let frame = GoawayFrame::new(stream_id);
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        
        let decoded_frame = Http3Frame::decode(buf.freeze()).unwrap();
        
        match decoded_frame {
            Http3Frame::Goaway(decoded) => {
                assert_eq!(decoded.stream_id, stream_id);
            }
            _ => panic!("Expected GOAWAY frame"),
        }
    }

    #[test]
    fn max_push_id_frame_encoding_roundtrip() {
        let push_id = VarInt::from_u32(1000);
        let frame = MaxPushIdFrame::new(push_id);
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        
        let decoded_frame = Http3Frame::decode(buf.freeze()).unwrap();
        
        match decoded_frame {
            Http3Frame::MaxPushId(decoded) => {
                assert_eq!(decoded.push_id, push_id);
            }
            _ => panic!("Expected MAX_PUSH_ID frame"),
        }
    }

    #[test]
    fn frame_type_validation() {
        assert!(Http3FrameType::Data.valid_on_request_stream());
        assert!(Http3FrameType::Headers.valid_on_request_stream());
        assert!(!Http3FrameType::Settings.valid_on_request_stream());
        
        assert!(Http3FrameType::Settings.valid_on_control_stream());
        assert!(Http3FrameType::Goaway.valid_on_control_stream());
        assert!(!Http3FrameType::Data.valid_on_control_stream());
        
        assert!(Http3FrameType::Data.valid_on_push_stream());
        assert!(Http3FrameType::Headers.valid_on_push_stream());
        assert!(!Http3FrameType::Settings.valid_on_push_stream());
        
        // Test DATAGRAM frame validation
        assert!(Http3FrameType::Datagram.valid_on_request_stream());
        assert!(!Http3FrameType::Datagram.valid_on_control_stream());
    }

    #[test]
    fn frame_parser_basic() {
        let mut parser = FrameParser::new();
        
        // Create a DATA frame
        let data = Bytes::from_static(b"test data");
        let frame = DataFrame::new(data.clone());
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        
        // Parse it
        parser.push_data(buf.freeze());
        let parsed_frame = parser.parse_frame().unwrap().unwrap();
        
        match parsed_frame {
            Http3Frame::Data(decoded) => {
                assert_eq!(decoded.data, data);
            }
            _ => panic!("Expected DATA frame"),
        }
    }

    #[test]
    fn frame_parser_partial_data() {
        let mut parser = FrameParser::new();
        
        // Create a DATA frame
        let data = Bytes::from_static(b"test data");
        let frame = DataFrame::new(data);
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        
        let frame_data = buf.freeze();
        
        // Send partial data
        parser.push_data(frame_data.slice(0..3));
        assert!(parser.parse_frame().unwrap().is_none());
        
        // Send remaining data
        parser.push_data(frame_data.slice(3..));
        let parsed_frame = parser.parse_frame().unwrap().unwrap();
        
        assert!(matches!(parsed_frame, Http3Frame::Data(_)));
    }

    #[test]
    fn unknown_frame_handling() {
        let mut buf = BytesMut::new();
        buf.put_var(VarInt::from_u32(0xFF)); // Unknown frame type
        buf.put_var(VarInt::from_u32(4)); // Length
        buf.put_u32(0x12345678); // Payload
        
        let frame = Http3Frame::decode(buf.freeze()).unwrap();
        
        match frame {
            Http3Frame::Unknown { frame_type, payload } => {
                assert_eq!(frame_type.into_inner(), 0xFF);
                assert_eq!(payload.len(), 4);
            }
            _ => panic!("Expected unknown frame"),
        }
    }

    #[test]
    fn datagram_frame_encoding_roundtrip() {
        let datagram_data = Bytes::from_static(b"Hello, Datagram!");
        let frame = DatagramFrame::new(datagram_data.clone());
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        
        let decoded_frame = Http3Frame::decode(buf.freeze()).unwrap();
        
        match decoded_frame {
            Http3Frame::Datagram(decoded) => {
                assert_eq!(decoded.data, datagram_data);
                assert_eq!(decoded.len(), datagram_data.len());
                assert!(!decoded.is_empty());
            }
            _ => panic!("Expected DATAGRAM frame"),
        }
    }

    #[test]
    fn empty_datagram_frame() {
        let frame = DatagramFrame::new(Bytes::new());
        
        assert!(frame.is_empty());
        assert_eq!(frame.len(), 0);
        
        let mut buf = BytesMut::new();
        frame.encode(&mut buf).unwrap();
        
        let decoded_frame = Http3Frame::decode(buf.freeze()).unwrap();
        
        match decoded_frame {
            Http3Frame::Datagram(decoded) => {
                assert!(decoded.is_empty());
                assert_eq!(decoded.len(), 0);
            }
            _ => panic!("Expected DATAGRAM frame"),
        }
    }
}