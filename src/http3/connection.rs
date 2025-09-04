//! HTTP/3 connection management
//!
//! Implements HTTP/3 connection handling as per RFC 9114.

use crate::{
    error::{Error, Result},
    http3::{
        frame_simple::Frame,
        settings::Settings,
        stream::{Stream, StreamType},
    },
    qpack::{decoder::Decoder, encoder::Encoder},
    quic::{
        connection::Connection as QuicConnection,
        stream::StreamId,
    },
    whathappened::Level,
    {protocol_event, span},
};
use bytes::{Buf, Bytes, BytesMut};
use std::{
    collections::HashMap,
    sync::Arc,
};
use tokio::sync::{mpsc, Mutex, RwLock};

/// HTTP/3 connection state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionState {
    /// Connection is being established
    Connecting,
    /// Connection is active
    Connected,
    /// Connection is closing
    Closing,
    /// Connection is closed
    Closed,
}

/// HTTP/3 connection
pub struct Connection {
    /// Underlying QUIC connection
    _quic_conn: Arc<Mutex<QuicConnection>>,
    /// Connection state
    state: ConnectionState,
    /// Local settings
    local_settings: Settings,
    /// Remote settings
    remote_settings: Option<Settings>,
    /// QPACK encoder
    qpack_encoder: Arc<Mutex<Encoder>>,
    /// QPACK decoder
    qpack_decoder: Arc<Mutex<Decoder>>,
    /// Active HTTP/3 streams
    streams: Arc<RwLock<HashMap<StreamId, Arc<Mutex<Stream>>>>>,
    /// Control stream ID (bidirectional)
    control_stream_id: Option<StreamId>,
    /// QPACK encoder stream ID (unidirectional)
    qpack_encoder_stream_id: Option<StreamId>,
    /// QPACK decoder stream ID (unidirectional)
    qpack_decoder_stream_id: Option<StreamId>,
    /// Maximum push ID
    max_push_id: Option<u64>,
    /// Received goaway
    goaway_received: bool,
    /// Sent goaway
    goaway_sent: bool,
    /// Frame receiver
    frame_rx: mpsc::UnboundedReceiver<(StreamId, Frame)>,
    /// Frame sender
    frame_tx: mpsc::UnboundedSender<(StreamId, Frame)>,
}

impl Connection {
    /// Create a new HTTP/3 connection
    pub fn new(_quic_conn: Arc<Mutex<QuicConnection>>) -> Result<Self> {
        let (frame_tx, frame_rx) = mpsc::unbounded_channel();
        
        protocol_event!(
            Level::Info,
            "HTTP/3 connection created";
            "state" => ConnectionState::Connecting,
            "max_table_capacity" => Settings::default().qpack_max_table_capacity(),
            "max_blocked_streams" => Settings::default().qpack_blocked_streams()
        );
        
        Ok(Self {
            _quic_conn,
            state: ConnectionState::Connecting,
            local_settings: Settings::default(),
            remote_settings: None,
            qpack_encoder: Arc::new(Mutex::new(Encoder::new(
                crate::qpack::Config {
                    max_table_capacity: Settings::default().qpack_max_table_capacity(),
                    max_blocked_streams: Settings::default().qpack_blocked_streams(),
                    use_huffman: true,
                }
            ))),
            qpack_decoder: Arc::new(Mutex::new(Decoder::new(
                crate::qpack::Config {
                    max_table_capacity: Settings::default().qpack_max_table_capacity(),
                    max_blocked_streams: Settings::default().qpack_blocked_streams(),
                    use_huffman: true,
                }
            ))),
            streams: Arc::new(RwLock::new(HashMap::new())),
            control_stream_id: None,
            qpack_encoder_stream_id: None,
            qpack_decoder_stream_id: None,
            max_push_id: None,
            goaway_received: false,
            goaway_sent: false,
            frame_rx,
            frame_tx,
        })
    }

    /// Initialize the HTTP/3 connection
    pub async fn initialize(&mut self) -> Result<()> {
        let _span = span!(Level::Info, "initialize_http3_connection");
        
        protocol_event!(
            Level::Info,
            "Initializing HTTP/3 connection";
            "state" => self.state
        );
        
        // Create control stream
        self.create_control_stream().await?;
        
        // Create QPACK streams
        self.create_qpack_streams().await?;
        
        // Send SETTINGS frame
        self.send_settings().await?;
        
        // Update state
        let old_state = self.state;
        self.state = ConnectionState::Connected;
        
        protocol_event!(
            Level::Info,
            "HTTP/3 connection initialized";
            "old_state" => old_state,
            "new_state" => self.state,
            "control_stream_id" => self.control_stream_id,
            "qpack_encoder_stream_id" => self.qpack_encoder_stream_id,
            "qpack_decoder_stream_id" => self.qpack_decoder_stream_id
        );
        
        Ok(())
    }

    /// Create the control stream
    async fn create_control_stream(&mut self) -> Result<()> {
        let _span = span!(Level::Debug, "create_control_stream");
        
        let mut _quic_conn = self._quic_conn.lock().await;
        
        // Create unidirectional stream for control
        let stream_id = _quic_conn.create_stream(crate::quic::stream::StreamType::Unidirectional)?;
        self.control_stream_id = Some(stream_id);
        
        // Send stream type
        let stream_type = StreamType::Control;
        let mut data = BytesMut::new();
        stream_type.encode(&mut data)?;
        
        _quic_conn.stream_send(stream_id, data.freeze(), false).await?;
        
        protocol_event!(
            Level::Info,
            "HTTP/3 control stream created";
            "stream_id" => stream_id.into_inner(),
            "stream_type" => stream_type
        );
        
        Ok(())
    }

    /// Create QPACK encoder and decoder streams
    async fn create_qpack_streams(&mut self) -> Result<()> {
        let _span = span!(Level::Debug, "create_qpack_streams");
        
        let mut _quic_conn = self._quic_conn.lock().await;
        
        // Create QPACK encoder stream
        let encoder_stream_id = _quic_conn.create_stream(crate::quic::stream::StreamType::Unidirectional)?;
        self.qpack_encoder_stream_id = Some(encoder_stream_id);
        
        let stream_type = StreamType::QpackEncoder;
        let mut data = BytesMut::new();
        stream_type.encode(&mut data)?;
        _quic_conn.stream_send(encoder_stream_id, data.freeze(), false).await?;
        
        protocol_event!(
            Level::Info,
            "QPACK encoder stream created";
            "stream_id" => encoder_stream_id.into_inner(),
            "stream_type" => stream_type
        );
        
        // Create QPACK decoder stream
        let decoder_stream_id = _quic_conn.create_stream(crate::quic::stream::StreamType::Unidirectional)?;
        self.qpack_decoder_stream_id = Some(decoder_stream_id);
        
        let stream_type = StreamType::QpackDecoder;
        let mut data = BytesMut::new();
        stream_type.encode(&mut data)?;
        _quic_conn.stream_send(decoder_stream_id, data.freeze(), false).await?;
        
        protocol_event!(
            Level::Info,
            "QPACK decoder stream created";
            "stream_id" => decoder_stream_id.into_inner(),
            "stream_type" => stream_type
        );
        
        Ok(())
    }

    /// Send SETTINGS frame
    async fn send_settings(&mut self) -> Result<()> {
        let _span = span!(Level::Debug, "send_settings");
        
        let control_stream_id = self.control_stream_id
            .ok_or_else(|| Error::ConnectionError("Control stream not created".to_string()))?;
        
        let frame = Frame::Settings(self.local_settings.clone());
        self.send_frame(control_stream_id, frame).await?;
        
        protocol_event!(
            Level::Info,
            "HTTP/3 SETTINGS frame sent";
            "control_stream_id" => control_stream_id.into_inner(),
            "max_table_capacity" => self.local_settings.qpack_max_table_capacity(),
            "max_blocked_streams" => self.local_settings.qpack_blocked_streams()
        );
        
        Ok(())
    }

    /// Send a frame on a stream
    pub async fn send_frame(&self, stream_id: StreamId, frame: Frame) -> Result<()> {
        let _span = span!(Level::Debug, "send_frame", stream_id = stream_id.into_inner());
        
        let mut data = BytesMut::new();
        frame.encode(&mut data)?;
        
        let frame_size = data.len();
        let mut _quic_conn = self._quic_conn.lock().await;
        _quic_conn.stream_send(stream_id, data.freeze(), false).await?;
        
        protocol_event!(
            Level::Debug,
            "HTTP/3 frame sent";
            "stream_id" => stream_id.into_inner(),
            "frame_type" => frame,
            "frame_size" => frame_size
        );
        
        Ok(())
    }

    /// Process incoming data on a stream
    pub async fn process_stream_data(&mut self, stream_id: StreamId, data: Bytes) -> Result<()> {
        let _span = span!(Level::Debug, "process_stream_data", stream_id = stream_id.into_inner(), data_len = data.len());
        
        // Check if this is a known stream
        let streams = self.streams.read().await;
        if let Some(stream) = streams.get(&stream_id) {
            protocol_event!(
                Level::Debug,
                "Processing data on existing HTTP/3 stream";
                "stream_id" => stream_id.into_inner(),
                "data_len" => data.len()
            );
            let mut stream = stream.lock().await;
            return stream.process_data(data).await;
        }
        drop(streams);
        
        // Handle new stream
        protocol_event!(
            Level::Info,
            "Processing data on new HTTP/3 stream";
            "stream_id" => stream_id.into_inner(),
            "data_len" => data.len(),
            "is_bidirectional" => stream_id.is_bidirectional()
        );
        self.handle_new_stream(stream_id, data).await
    }

    /// Handle a new stream
    async fn handle_new_stream(&mut self, stream_id: StreamId, data: Bytes) -> Result<()> {
        let _span = span!(Level::Debug, "handle_new_stream", stream_id = stream_id.into_inner());
        
        // Parse stream type for unidirectional streams
        if !stream_id.is_bidirectional() {
            let stream_type = StreamType::decode(&data)?;
            
            protocol_event!(
                Level::Info,
                "New unidirectional HTTP/3 stream detected";
                "stream_id" => stream_id.into_inner(),
                "stream_type" => stream_type,
                "data_len" => data.len()
            );
            
            match stream_type {
                StreamType::Control => {
                    // Process control stream
                    self.process_control_stream(stream_id, data).await?
                }
                StreamType::QpackEncoder => {
                    // Process QPACK encoder stream
                    self.process_qpack_encoder_stream(stream_id, data).await?
                }
                StreamType::QpackDecoder => {
                    // Process QPACK decoder stream
                    self.process_qpack_decoder_stream(stream_id, data).await?
                }
                StreamType::Push => {
                    // Process push stream
                    self.process_push_stream(stream_id, data).await?
                }
                _ => {
                    // Unknown stream type
                    return Err(Error::StreamError {
                        code: crate::error::StreamErrorCode::IdError,
                        reason: "Unknown stream type".to_string()
                    });
                }
            }
        } else {
            // Create new request/response stream
            let stream = Stream::new(
                stream_id,
                StreamType::Request,
                self.qpack_encoder.clone(),
                self.qpack_decoder.clone(),
            )?;
            
            let stream = Arc::new(Mutex::new(stream));
            let mut streams = self.streams.write().await;
            streams.insert(stream_id, stream.clone());
            
            // Process initial data
            let mut stream = stream.lock().await;
            stream.process_data(data).await?
        }
        
        Ok(())
    }

    /// Process control stream data
    async fn process_control_stream(&mut self, _stream_id: StreamId, data: Bytes) -> Result<()> {
        // Parse frames from control stream
        let mut cursor = std::io::Cursor::new(data.as_ref());
        
        while cursor.position() < cursor.get_ref().len() as u64 {
            let frame = Frame::decode(&mut cursor)?;
            
            match frame {
                Frame::Settings(settings) => {
                    self.apply_remote_settings(settings).await?;
                }
                Frame::Goaway(id) => {
                    self.handle_goaway(id).await?;
                }
                Frame::MaxPushId(id) => {
                    self.max_push_id = Some(id);
                }
                _ => {
                    // Unexpected frame on control stream
                    return Err(Error::FrameError(
                        "Unexpected frame on control stream".to_string()
                    ));
                }
            }
        }
        
        Ok(())
    }

    /// Process QPACK encoder stream data
    async fn process_qpack_encoder_stream(&mut self, _stream_id: StreamId, data: Bytes) -> Result<()> {
        let mut decoder = self.qpack_decoder.lock().await;
        decoder.process_encoder_stream(data)?;
        Ok(())
    }

    /// Process QPACK decoder stream data
    async fn process_qpack_decoder_stream(&mut self, _stream_id: StreamId, data: Bytes) -> Result<()> {
        let mut encoder = self.qpack_encoder.lock().await;
        encoder.process_decoder_stream(data)?;
        Ok(())
    }

    /// Process push stream data
    async fn process_push_stream(&mut self, stream_id: StreamId, data: Bytes) -> Result<()> {
        // Parse push ID
        let mut cursor = std::io::Cursor::new(&data);
        let _push_id = cursor.get_u64();
        
        // Create push stream
        let stream = Stream::new(
            stream_id,
            StreamType::Push,
            self.qpack_encoder.clone(),
            self.qpack_decoder.clone(),
        )?;
        
        let stream = Arc::new(Mutex::new(stream));
        let mut streams = self.streams.write().await;
        streams.insert(stream_id, stream.clone());
        
        // Process remaining data
        let remaining = &data[cursor.position() as usize..];
        if !remaining.is_empty() {
            let mut stream = stream.lock().await;
            stream.process_data(Bytes::copy_from_slice(remaining)).await?
        }
        
        Ok(())
    }

    /// Apply remote settings
    async fn apply_remote_settings(&mut self, settings: Settings) -> Result<()> {
        // Update QPACK encoder with remote settings
        let mut encoder = self.qpack_encoder.lock().await;
        encoder.set_capacity(settings.qpack_max_table_capacity())?;
        
        // Store remote settings
        self.remote_settings = Some(settings);
        
        Ok(())
    }

    /// Handle GOAWAY frame
    async fn handle_goaway(&mut self, stream_id: StreamId) -> Result<()> {
        self.goaway_received = true;
        
        // Close streams with ID greater than goaway ID
        let streams = self.streams.read().await;
        let affected_streams: Vec<StreamId> = streams.keys()
            .filter(|&&id| id > stream_id)
            .copied()
            .collect();
        drop(streams);
        
        for id in affected_streams {
            self.close_stream(id).await?;
        }
        
        Ok(())
    }

    /// Create a new request stream
    pub async fn create_request_stream(&self) -> Result<Arc<Mutex<Stream>>> {
        if self.state != ConnectionState::Connected {
            return Err(Error::ConnectionError("Connection not established".to_string()));
        }
        
        let mut _quic_conn = self._quic_conn.lock().await;
        let stream_id = _quic_conn.create_stream(crate::quic::stream::StreamType::Bidirectional)?;
        
        let stream = Stream::new(
            stream_id,
            StreamType::Request,
            self.qpack_encoder.clone(),
            self.qpack_decoder.clone(),
        )?;
        
        let stream = Arc::new(Mutex::new(stream));
        let mut streams = self.streams.write().await;
        streams.insert(stream_id, stream.clone());
        
        Ok(stream)
    }

    /// Close a stream
    pub async fn close_stream(&self, stream_id: StreamId) -> Result<()> {
        let mut streams = self.streams.write().await;
        streams.remove(&stream_id);
        
        let mut quic_conn = self._quic_conn.lock().await;
        // Close the stream in QUIC connection with error code 0 (no error)
        quic_conn.close_stream(stream_id, 0).await?;
        
        Ok(())
    }

    /// Send GOAWAY frame
    pub async fn send_goaway(&mut self, stream_id: StreamId) -> Result<()> {
        if self.goaway_sent {
            return Ok(());
        }
        
        let control_stream_id = self.control_stream_id
            .ok_or_else(|| Error::ConnectionError("Control stream not created".to_string()))?;
        
        let frame = Frame::Goaway(stream_id);
        self.send_frame(control_stream_id, frame).await?;
        self.goaway_sent = true;
        
        Ok(())
    }

    /// Close the connection
    pub async fn close(&mut self, _error_code: u64, reason: String) -> Result<()> {
        self.state = ConnectionState::Closing;
        
        // Send GOAWAY if not already sent
        if let Some(last_stream_id) = self.get_last_stream_id().await {
            self.send_goaway(last_stream_id).await?;
        }
        
        // Close QUIC connection
        let mut _quic_conn = self._quic_conn.lock().await;
        _quic_conn.close(
            crate::error::ConnectionErrorCode::ApplicationError,
            reason
        ).await?;
        
        self.state = ConnectionState::Closed;
        
        Ok(())
    }

    /// Get the last stream ID
    async fn get_last_stream_id(&self) -> Option<StreamId> {
        let streams = self.streams.read().await;
        streams.keys().max().copied()
    }

    /// Get connection state
    pub fn state(&self) -> ConnectionState {
        self.state
    }

    /// Check if connection is closed
    pub fn is_closed(&self) -> bool {
        matches!(self.state, ConnectionState::Closing | ConnectionState::Closed)
    }

    /// Get local settings
    pub fn local_settings(&self) -> &Settings {
        &self.local_settings
    }

    /// Get remote settings
    pub fn remote_settings(&self) -> Option<&Settings> {
        self.remote_settings.as_ref()
    }

    /// Process connection events
    pub async fn process_events(&mut self) -> Result<()> {
        // Process QUIC connection events
        let mut _quic_conn = self._quic_conn.lock().await;
        _quic_conn.maintain().await?;
        drop(_quic_conn);
        
        Ok(())
    }
}