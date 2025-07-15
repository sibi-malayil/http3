//! Simplified HTTP/3 frame types for internal use

use crate::{
    error::{Error, Result},
    http3::settings::Settings,
    quic::stream::StreamId,
    util::varint::VarInt,
};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io::{Cursor, Read};

/// Frame type identifiers
#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u64)]
pub enum FrameType {
    /// DATA frame carries request/response body
    Data = 0x00,
    /// HEADERS frame carries header fields
    Headers = 0x01,
    /// CANCEL_PUSH frame cancels a push promise
    CancelPush = 0x03,
    /// SETTINGS frame carries configuration parameters
    Settings = 0x04,
    /// PUSH_PROMISE frame initiates a push stream
    PushPromise = 0x05,
    /// GOAWAY frame initiates graceful shutdown
    Goaway = 0x07,
    /// MAX_PUSH_ID frame controls push stream limits
    MaxPushId = 0x0d,
}

/// HTTP/3 frame
#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    /// DATA frame
    Data(Bytes),
    /// HEADERS frame
    Headers(Bytes),
    /// CANCEL_PUSH frame
    CancelPush(u64),
    /// SETTINGS frame
    Settings(Settings),
    /// PUSH_PROMISE frame
    PushPromise(u64, Bytes),
    /// GOAWAY frame
    Goaway(StreamId),
    /// MAX_PUSH_ID frame
    MaxPushId(u64),
    /// Reserved frame type
    Reserved(u64, Bytes),
}

impl Frame {
    /// Encode frame to bytes
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        match self {
            Frame::Data(data) => {
                encode_varint(FrameType::Data as u64, buf);
                encode_varint(data.len() as u64, buf);
                buf.put_slice(data);
            }
            Frame::Headers(headers) => {
                encode_varint(FrameType::Headers as u64, buf);
                encode_varint(headers.len() as u64, buf);
                buf.put_slice(headers);
            }
            Frame::CancelPush(push_id) => {
                encode_varint(FrameType::CancelPush as u64, buf);
                let mut payload = BytesMut::new();
                encode_varint(*push_id, &mut payload);
                encode_varint(payload.len() as u64, buf);
                buf.put(payload);
            }
            Frame::Settings(settings) => {
                encode_varint(FrameType::Settings as u64, buf);
                let mut payload = BytesMut::new();
                settings.encode(&mut payload)?;
                encode_varint(payload.len() as u64, buf);
                buf.put(payload);
            }
            Frame::PushPromise(push_id, headers) => {
                encode_varint(FrameType::PushPromise as u64, buf);
                let mut payload = BytesMut::new();
                encode_varint(*push_id, &mut payload);
                payload.put_slice(headers);
                encode_varint(payload.len() as u64, buf);
                buf.put(payload);
            }
            Frame::Goaway(stream_id) => {
                encode_varint(FrameType::Goaway as u64, buf);
                let mut payload = BytesMut::new();
                encode_varint(stream_id.into_inner(), &mut payload);
                encode_varint(payload.len() as u64, buf);
                buf.put(payload);
            }
            Frame::MaxPushId(push_id) => {
                encode_varint(FrameType::MaxPushId as u64, buf);
                let mut payload = BytesMut::new();
                encode_varint(*push_id, &mut payload);
                encode_varint(payload.len() as u64, buf);
                buf.put(payload);
            }
            Frame::Reserved(frame_type, data) => {
                encode_varint(*frame_type, buf);
                encode_varint(data.len() as u64, buf);
                buf.put_slice(data);
            }
        }
        Ok(())
    }

    /// Decode frame from bytes
    pub fn decode(cursor: &mut Cursor<&[u8]>) -> Result<Self> {
        // Check if we have enough data for frame type
        if cursor.remaining() < 1 {
            return Err(Error::Incomplete);
        }

        let frame_type = decode_varint(cursor)?;
        let length = decode_varint(cursor)?;

        if cursor.remaining() < length as usize {
            return Err(Error::Incomplete);
        }

        let mut payload = vec![0u8; length as usize];
        cursor.read_exact(&mut payload).map_err(|_| Error::Incomplete)?;
        let payload = Bytes::from(payload);

        match frame_type {
            0x00 => Ok(Frame::Data(payload)),
            0x01 => Ok(Frame::Headers(payload)),
            0x03 => {
                let mut cursor = Cursor::new(&payload);
                let push_id = cursor.get_u64();
                Ok(Frame::CancelPush(push_id))
            }
            0x04 => {
                let settings = Settings::decode(&payload)?;
                Ok(Frame::Settings(settings))
            }
            0x05 => {
                let mut cursor = Cursor::new(&payload);
                let push_id = cursor.get_u64();
                let remaining = cursor.remaining();
                let mut headers_data = vec![0u8; remaining];
                cursor.read_exact(&mut headers_data).map_err(|_| Error::Incomplete)?;
                let headers = Bytes::from(headers_data);
                Ok(Frame::PushPromise(push_id, headers))
            }
            0x07 => {
                let mut cursor = Cursor::new(&payload);
                let stream_id = cursor.get_u64();
                Ok(Frame::Goaway(StreamId::from(stream_id)))
            }
            0x0d => {
                let mut cursor = Cursor::new(&payload);
                let push_id = cursor.get_u64();
                Ok(Frame::MaxPushId(push_id))
            }
            _ => Ok(Frame::Reserved(frame_type, payload)),
        }
    }
}

/// Helper function to encode a variable-length integer
fn encode_varint(value: u64, buf: &mut BytesMut) {
    VarInt(value).encode(buf).unwrap();
}

/// Helper function to decode a variable-length integer
fn decode_varint(cursor: &mut Cursor<&[u8]>) -> Result<u64> {
    // Get remaining bytes
    let pos = cursor.position() as usize;
    let remaining = &cursor.get_ref()[pos..];
    
    // Create a new cursor for the remaining bytes
    let mut remaining_cursor = Cursor::new(remaining);
    let varint = VarInt::decode(&mut remaining_cursor)?;
    
    // Update the original cursor position
    cursor.set_position(cursor.position() + varint.size() as u64);
    Ok(varint.into_inner())
}