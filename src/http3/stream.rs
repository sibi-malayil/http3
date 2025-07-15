//! HTTP/3 stream management
//!
//! Implements HTTP/3 stream handling for request/response and push streams.

use crate::{
    error::{Error, Result},
    http3::{frame_simple::Frame, priority::{Priority, StreamPriority, PriorityScheduler}},
    qpack::{decoder::Decoder, encoder::Encoder, field::HeaderField},
    quic::stream::StreamId,
    whathappened::{Level, EventKind},
    {debug, info, warn, error, protocol_event, span, time_block},
};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::{
    collections::VecDeque,
    io::Cursor,
    sync::Arc,
};
use tokio::sync::{mpsc, Mutex};

/// HTTP/3 stream type
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StreamType {
    /// Control stream
    Control,
    /// Push stream
    Push,
    /// QPACK encoder stream
    QpackEncoder,
    /// QPACK decoder stream
    QpackDecoder,
    /// Request/response stream
    Request,
    /// Reserved stream type
    Reserved(u64),
}

impl StreamType {
    /// Encode stream type
    pub fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        let type_id = match self {
            StreamType::Control => 0x00,
            StreamType::Push => 0x01,
            StreamType::QpackEncoder => 0x02,
            StreamType::QpackDecoder => 0x03,
            StreamType::Reserved(id) => *id,
            StreamType::Request => {
                return Err(Error::StreamError {
                    code: crate::error::StreamErrorCode::IdError,
                    reason: "Request streams don't have a type ID".to_string()
                });
            }
        };
        
        buf.put_u8(type_id as u8);
        Ok(())
    }

    /// Decode stream type
    pub fn decode(data: &Bytes) -> Result<Self> {
        let mut cursor = Cursor::new(data);
        if cursor.remaining() < 1 {
            return Err(Error::Incomplete);
        }
        let type_id = cursor.get_u8() as u64;
        
        Ok(match type_id {
            0x00 => StreamType::Control,
            0x01 => StreamType::Push,
            0x02 => StreamType::QpackEncoder,
            0x03 => StreamType::QpackDecoder,
            id => StreamType::Reserved(id),
        })
    }
}

/// HTTP/3 stream state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StreamState {
    /// Stream created but not yet active
    Idle,
    /// Sending or receiving headers
    Headers,
    /// Sending or receiving data
    Data,
    /// Sending or receiving trailers
    Trailers,
    /// Stream finished
    Finished,
    /// Stream reset
    Reset,
}

/// HTTP/3 stream event
#[derive(Debug)]
pub enum StreamEvent {
    /// Headers received
    Headers(Vec<HeaderField>),
    /// Data received
    Data(Bytes),
    /// Trailers received
    Trailers(Vec<HeaderField>),
    /// Stream finished
    Finished,
    /// Stream reset
    Reset(u64),
}

/// HTTP/3 stream
pub struct Stream {
    /// Stream ID
    id: StreamId,
    /// Stream type
    stream_type: StreamType,
    /// Stream state
    state: StreamState,
    /// Stream priority information
    priority: StreamPriority,
    /// QPACK encoder
    qpack_encoder: Arc<Mutex<Encoder>>,
    /// QPACK decoder
    qpack_decoder: Arc<Mutex<Decoder>>,
    /// Received data buffer
    recv_buffer: BytesMut,
    /// Send buffer
    send_buffer: BytesMut,
    /// Pending frames to send
    pending_frames: VecDeque<Frame>,
    /// Event sender
    event_tx: Option<mpsc::UnboundedSender<StreamEvent>>,
    /// Whether headers have been sent
    headers_sent: bool,
    /// Whether headers have been received
    headers_received: bool,
    /// Whether the stream is finished
    finished: bool,
}

impl Stream {
    /// Create a new HTTP/3 stream
    pub fn new(
        id: StreamId,
        stream_type: StreamType,
        qpack_encoder: Arc<Mutex<Encoder>>,
        qpack_decoder: Arc<Mutex<Decoder>>,
    ) -> Result<Self> {
        protocol_event!(
            Level::Info,
            "HTTP/3 stream created";
            "stream_id" => id.into_inner(),
            "stream_type" => stream_type
        );
        
        Ok(Self {
            id,
            stream_type,
            state: StreamState::Idle,
            priority: StreamPriority::new(),
            qpack_encoder,
            qpack_decoder,
            recv_buffer: BytesMut::with_capacity(16384),
            send_buffer: BytesMut::with_capacity(16384),
            pending_frames: VecDeque::new(),
            event_tx: None,
            headers_sent: false,
            headers_received: false,
            finished: false,
        })
    }

    /// Set event sender
    pub fn set_event_sender(&mut self, tx: mpsc::UnboundedSender<StreamEvent>) {
        self.event_tx = Some(tx);
    }

    /// Send headers
    pub async fn send_headers(&mut self, headers: Vec<HeaderField>) -> Result<()> {
        let _span = span!(Level::Debug, "send_headers", stream_id = self.id.into_inner(), header_count = headers.len());
        
        if self.headers_sent {
            protocol_event!(
                Level::Warn,
                "Cannot send headers - already sent";
                "stream_id" => self.id.into_inner(),
                "state" => self.state
            );
            return Err(Error::StreamError {
                code: crate::error::StreamErrorCode::FrameUnexpected,
                reason: "Headers already sent".to_string()
            });
        }

        // Encode headers with QPACK
        let mut encoder = self.qpack_encoder.lock().await;
        let encoded = encoder.encode_field_section(self.id.into(), &headers, false)?;
        drop(encoder);

        // Create HEADERS frame
        let encoded_size = encoded.len();
        let frame = Frame::Headers(encoded);
        self.pending_frames.push_back(frame);
        
        self.headers_sent = true;
        let old_state = self.state;
        self.state = StreamState::Data;
        
        protocol_event!(
            Level::Info,
            "HTTP/3 headers sent";
            "stream_id" => self.id.into_inner(),
            "header_count" => headers.len(),
            "old_state" => old_state,
            "new_state" => self.state,
            "encoded_size" => encoded_size
        );
        
        Ok(())
    }

    /// Send data
    pub async fn send_data(&mut self, data: Bytes) -> Result<()> {
        let _span = span!(Level::Debug, "send_data", stream_id = self.id.into_inner(), data_len = data.len());
        
        if !self.headers_sent {
            protocol_event!(
                Level::Warn,
                "Cannot send data - headers not sent";
                "stream_id" => self.id.into_inner(),
                "data_len" => data.len(),
                "state" => self.state
            );
            return Err(Error::StreamError {
                code: crate::error::StreamErrorCode::FrameUnexpected,
                reason: "Headers must be sent before data".to_string()
            });
        }

        protocol_event!(
            Level::Debug,
            "HTTP/3 data sent";
            "stream_id" => self.id.into_inner(),
            "data_len" => data.len(),
            "state" => self.state
        );

        // Record bytes for priority scheduling
        self.record_bytes_sent(data.len() as u64);

        // Create DATA frame
        let frame = Frame::Data(data);
        self.pending_frames.push_back(frame);
        
        Ok(())
    }

    /// Send trailers
    pub async fn send_trailers(&mut self, trailers: Vec<HeaderField>) -> Result<()> {
        if !self.headers_sent {
            return Err(Error::StreamError {
                code: crate::error::StreamErrorCode::FrameUnexpected,
                reason: "Headers must be sent before trailers".to_string()
            });
        }

        // Encode trailers with QPACK
        let mut encoder = self.qpack_encoder.lock().await;
        let encoded = encoder.encode_field_section(self.id.into(), &trailers, false)?;
        drop(encoder);

        // Create HEADERS frame for trailers
        let frame = Frame::Headers(encoded);
        self.pending_frames.push_back(frame);
        
        self.state = StreamState::Trailers;
        
        Ok(())
    }

    /// Get pending data to send
    pub fn get_send_data(&mut self) -> Option<Bytes> {
        if self.pending_frames.is_empty() && self.send_buffer.is_empty() {
            return None;
        }

        // Encode pending frames
        while let Some(frame) = self.pending_frames.pop_front() {
            frame.encode(&mut self.send_buffer).ok()?;
        }

        if self.send_buffer.is_empty() {
            None
        } else {
            Some(self.send_buffer.split().freeze())
        }
    }

    /// Process received data
    pub async fn process_data(&mut self, data: Bytes) -> Result<()> {
        self.recv_buffer.extend_from_slice(&data);
        
        // Process frames
        while !self.recv_buffer.is_empty() {
            let mut cursor = Cursor::new(&self.recv_buffer[..]);
            
            // Try to decode a frame
            match Frame::decode(&mut cursor) {
                Ok(frame) => {
                    let consumed = cursor.position() as usize;
                    self.recv_buffer.advance(consumed);
                    
                    self.process_frame(frame).await?;
                }
                Err(Error::Incomplete) => {
                    // Need more data
                    break;
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
        
        Ok(())
    }

    /// Process a received frame
    async fn process_frame(&mut self, frame: Frame) -> Result<()> {
        match frame {
            Frame::Headers(encoded) => {
                self.process_headers(encoded).await?
            }
            Frame::Data(data) => {
                self.process_data_frame(data).await?
            }
            Frame::CancelPush(_) | Frame::Settings(_) | Frame::PushPromise(_, _) |
            Frame::Goaway(_) | Frame::MaxPushId(_) => {
                // These frames should not appear on request/response streams
                return Err(Error::FrameError(
                    "Unexpected frame type on request stream".to_string()
                ));
            }
            Frame::Reserved(_, _) => {
                // Ignore unknown frame types
            }
        }
        
        Ok(())
    }

    /// Process headers frame
    async fn process_headers(&mut self, encoded: Bytes) -> Result<()> {
        // Decode headers with QPACK
        let mut decoder = self.qpack_decoder.lock().await;
        let headers = decoder.decode_field_section(self.id.into(), encoded)?.unwrap_or_default();
        drop(decoder);

        if !self.headers_received {
            // First headers
            self.headers_received = true;
            self.state = StreamState::Data;
            
            if let Some(tx) = &self.event_tx {
                tx.send(StreamEvent::Headers(headers))
                    .map_err(|_| Error::StreamError {
                        code: crate::error::StreamErrorCode::InternalError,
                        reason: "Event channel closed".to_string()
                    })?;
            }
        } else {
            // Trailers
            self.state = StreamState::Trailers;
            
            if let Some(tx) = &self.event_tx {
                tx.send(StreamEvent::Trailers(headers))
                    .map_err(|_| Error::StreamError {
                        code: crate::error::StreamErrorCode::InternalError,
                        reason: "Event channel closed".to_string()
                    })?;
            }
        }
        
        Ok(())
    }

    /// Process data frame
    async fn process_data_frame(&mut self, data: Bytes) -> Result<()> {
        if !self.headers_received {
            return Err(Error::StreamError {
                code: crate::error::StreamErrorCode::FrameUnexpected,
                reason: "Data received before headers".to_string()
            });
        }

        if let Some(tx) = &self.event_tx {
            tx.send(StreamEvent::Data(data))
                .map_err(|_| Error::StreamError {
                    code: crate::error::StreamErrorCode::InternalError,
                    reason: "Event channel closed".to_string()
                })?;
        }
        
        Ok(())
    }

    /// Handle stream finished
    pub async fn handle_finished(&mut self) -> Result<()> {
        self.finished = true;
        self.state = StreamState::Finished;
        
        if let Some(tx) = &self.event_tx {
            tx.send(StreamEvent::Finished)
                .map_err(|_| Error::StreamError {
                    code: crate::error::StreamErrorCode::InternalError,
                    reason: "Event channel closed".to_string()
                })?;
        }
        
        Ok(())
    }

    /// Handle stream reset
    pub async fn handle_reset(&mut self, error_code: u64) -> Result<()> {
        self.state = StreamState::Reset;
        
        if let Some(tx) = &self.event_tx {
            tx.send(StreamEvent::Reset(error_code))
                .map_err(|_| Error::StreamError {
                    code: crate::error::StreamErrorCode::InternalError,
                    reason: "Event channel closed".to_string()
                })?;
        }
        
        Ok(())
    }

    /// Close the stream
    pub fn close(&mut self) {
        self.finished = true;
        self.event_tx = None;
    }

    /// Get stream ID
    pub fn id(&self) -> StreamId {
        self.id
    }

    /// Get stream type
    pub fn stream_type(&self) -> StreamType {
        self.stream_type
    }

    /// Get stream state
    pub fn state(&self) -> StreamState {
        self.state
    }

    /// Check if stream is finished
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Create event receiver
    pub fn create_event_receiver(&mut self) -> mpsc::UnboundedReceiver<StreamEvent> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.event_tx = Some(tx);
        rx
    }

    /// Get stream priority
    pub fn priority(&self) -> &Priority {
        &self.priority.priority
    }

    /// Set stream priority
    pub fn set_priority(&mut self, priority: Priority) {
        self.priority.update_priority(priority);
        
        protocol_event!(
            Level::Debug,
            "Stream priority updated";
            "stream_id" => self.id.into_inner(),
            "urgency" => self.priority.priority.urgency,
            "incremental" => self.priority.priority.incremental
        );
    }

    /// Get stream priority info
    pub fn priority_info(&self) -> &StreamPriority {
        &self.priority
    }

    /// Record bytes sent for priority scheduling
    pub fn record_bytes_sent(&mut self, bytes: u64) {
        self.priority.record_bytes_sent(bytes);
    }

    /// Mark stream as inactive for priority scheduling
    pub fn mark_inactive(&mut self) {
        self.priority.set_inactive();
    }

    /// Create stream with specific priority
    pub fn with_priority(
        id: StreamId,
        stream_type: StreamType,
        priority: Priority,
        qpack_encoder: Arc<Mutex<Encoder>>,
        qpack_decoder: Arc<Mutex<Decoder>>,
    ) -> Result<Self> {
        let mut stream = Self::new(id, stream_type, qpack_encoder, qpack_decoder)?;
        stream.priority = StreamPriority::with_priority(priority);
        Ok(stream)
    }
}