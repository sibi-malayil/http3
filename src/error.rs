use thiserror::Error;

/// Result type alias for this crate
pub type Result<T> = std::result::Result<T, Error>;

/// Error types for HTTP/3 and QUIC operations
#[derive(Error, Debug)]
pub enum Error {
    /// Connection was closed with an error code and reason
    #[error("Connection closed: {code:?} - {reason}")]
    ConnectionClosed { 
        /// The connection error code
        code: ConnectionErrorCode, 
        /// Human-readable reason for closure
        reason: String,
    },
    
    /// Stream encountered an error
    #[error("Stream error: {code:?} - {reason}")]
    StreamError { 
        /// The stream error code
        code: StreamErrorCode, 
        /// Human-readable reason for the error
        reason: String,
    },
    
    /// HTTP/3 protocol error occurred
    #[error("HTTP/3 protocol error: {code:?} - {reason}")]
    Http3Error { 
        /// The HTTP/3 error code
        code: Http3ErrorCode, 
        /// Human-readable reason for the error
        reason: String,
    },
    
    /// QPACK compression/decompression error
    #[error("QPACK compression error: {code:?} - {reason}")]
    QpackError { 
        /// The QPACK error code
        code: QpackErrorCode, 
        /// Human-readable reason for the error
        reason: String,
    },
    
    /// Transport layer error
    #[error("Transport layer error: {0}")]
    Transport(String),
    
    /// Cryptographic operation error
    #[error("Cryptographic error: {0}")]
    Crypto(String),
    
    /// Alternative cryptographic error
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
    
    /// TLS/SSL error
    #[error("TLS error: {0}")]
    TlsError(String),
    
    /// Incomplete data received
    #[error("Incomplete data")]
    Incomplete,
    
    /// Internal implementation error
    #[error("Internal implementation error: {0}")]
    Internal(String),
    
    /// Invalid frame format encountered
    #[error("Invalid frame format: {frame_type} - {reason}")]
    InvalidFrame { 
        /// The frame type that was invalid
        frame_type: String, 
        /// Reason why the frame was invalid
        reason: String,
    },
    
    /// Invalid packet format
    #[error("Invalid packet format: {0}")]
    InvalidPacket(String),
    
    /// Packet too short
    #[error("Packet too short")]
    PacketTooShort,
    
    /// Invalid packet format (no details)
    #[error("Invalid packet format")]
    InvalidPacketFormat,
    
    /// Invalid transport parameter
    #[error("Invalid transport parameter")]
    InvalidTransportParameter,
    
    /// Protocol specification violation
    #[error("Protocol violation: {0}")]
    ProtocolViolation(String),
    
    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),
    
    /// Connection timeout occurred
    #[error("Connection timeout")]
    Timeout,
    
    /// Connection was reset by peer
    #[error("Connection reset by peer")]
    Reset,
    
    /// Not connected to remote peer
    #[error("Not connected")]
    NotConnected,
    
    /// Connection was refused by peer
    #[error("Connection refused")]
    ConnectionRefused,
    
    /// Version negotiation failed
    #[error("Version negotiation failed")]
    VersionNegotiation,
    
    /// Flow control violation
    #[error("Flow control violation")]
    FlowControl,
    
    /// Buffer is full and cannot accept more data
    #[error("Buffer full")]
    BufferFull,
    
    /// Stream limit exceeded
    #[error("Stream limit exceeded")]
    StreamLimitError,
    
    /// Streams are blocked by flow control
    #[error("Streams blocked by flow control")]
    StreamsBlocked,
    
    /// General connection error
    #[error("Connection error: {0}")]
    ConnectionError(String),
    
    /// Frame processing error
    #[error("Frame error: {0}")]
    FrameError(String),
    
    /// Variable integer value exceeded maximum bounds
    #[error("Variable integer bounds exceeded")]
    VarIntBounds(#[from] crate::util::varint::VarIntBoundsExceeded),
    
    /// Variable integer decoding failed
    #[error("Variable integer decode error")]
    VarIntDecode(#[from] crate::util::varint::VarIntDecodeError),
    
    /// Buffer operation failed
    #[error("Buffer operation failed")]
    Buffer(#[from] crate::util::buffer::BufferError),
    
    /// Not implemented
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    
    /// I/O operation failed
    #[error("IO operation failed: {0}")]
    Io(#[from] std::io::Error),
    
    // QPACK specific errors
    /// QPACK string value exceeded maximum allowed length
    #[error("QPACK string too long")]
    QpackStringTooLong,
    
    /// QPACK decoder encountered incomplete data
    #[error("QPACK incomplete data")]
    QpackIncompleteData,
    
    /// QPACK header name contains invalid characters
    #[error("QPACK invalid header name")]
    QpackInvalidHeaderName,
    
    /// QPACK header value contains invalid characters
    #[error("QPACK invalid header value")]
    QpackInvalidHeaderValue,
    
    /// QPACK dynamic table size exceeded maximum capacity
    #[error("QPACK table size exceeded")]
    QpackTableSizeExceeded,
    
    /// QPACK decoder received invalid table index
    #[error("QPACK invalid index")]
    QpackInvalidIndex,
    
    /// QPACK stream would block due to dynamic table dependency
    #[error("QPACK would block stream")]
    QpackWouldBlock,
    
    /// QPACK encoder has too many blocked streams
    #[error("QPACK too many blocked streams")]
    QpackTooManyBlockedStreams,
    
    /// QPACK field line format is invalid
    #[error("QPACK invalid field line")]
    QpackInvalidFieldLine,
    
    /// QPACK Huffman decoder encountered invalid symbol
    #[error("QPACK Huffman decoding error")]
    QpackHuffmanError,
    
    /// QPACK decoding error
    #[error("QPACK decoding error: {0}")]
    QpackDecodingError(String),
    
    /// QPACK encoding error
    #[error("QPACK encoding error: {0}")]
    QpackEncodingError(String),
}

/// QUIC connection error codes as defined in RFC 9000
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum ConnectionErrorCode {
    /// No error (0x00)
    NoError = 0x00,
    /// Internal error in the QUIC implementation (0x01)
    InternalError = 0x01,
    /// Server refused the connection (0x02)
    ConnectionRefused = 0x02,
    /// Flow control protocol violation (0x03)
    FlowControlError = 0x03,
    /// Stream limit exceeded (0x04)
    StreamLimitError = 0x04,
    /// Invalid stream state transition (0x05)
    StreamStateError = 0x05,
    /// Final size field mismatch (0x06)
    FinalSizeError = 0x06,
    /// Frame encoding error (0x07)
    FrameEncodingError = 0x07,
    /// Transport parameter error (0x08)
    TransportParameterError = 0x08,
    /// Connection ID limit exceeded (0x09)
    ConnectionIdLimitError = 0x09,
    /// Generic protocol violation (0x0A)
    ProtocolViolation = 0x0A,
    /// Invalid connection migration token (0x0B)
    InvalidToken = 0x0B,
    /// Application-specific error (0x0C)
    ApplicationError = 0x0C,
    /// Crypto buffer limit exceeded (0x0D)
    CryptoBufferExceeded = 0x0D,
    /// TLS key update error (0x0E)
    KeyUpdateError = 0x0E,
    /// AEAD integrity limit reached (0x0F)
    AeadLimitReached = 0x0F,
    /// No viable network path available (0x10)
    NoViablePath = 0x10,
}

/// QUIC stream error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum StreamErrorCode {
    /// No error (0x00)
    NoError = 0x00,
    /// Internal error in stream processing (0x01)
    InternalError = 0x01,
    /// Error creating new stream (0x02)
    StreamCreationError = 0x02,
    /// Critical stream was closed unexpectedly (0x03)
    ClosedCriticalStream = 0x03,
    /// Frame received in invalid context (0x04)
    FrameUnexpected = 0x04,
    /// Frame decoding or validation error (0x05)
    FrameError = 0x05,
    /// Endpoint detected excessive load (0x06)
    ExcessiveLoad = 0x06,
    /// Stream or connection ID error (0x07)
    IdError = 0x07,
    /// SETTINGS frame error (0x08)
    SettingsError = 0x08,
    /// Required SETTINGS frame missing (0x09)
    MissingSettings = 0x09,
    /// Request was rejected by peer (0x0A)
    RequestRejected = 0x0A,
    /// Request was cancelled (0x0B)
    RequestCancelled = 0x0B,
    /// Request transmission incomplete (0x0C)
    RequestIncomplete = 0x0C,
    /// Message format error (0x0D)
    MessageError = 0x0D,
    /// CONNECT method error (0x0E)
    ConnectError = 0x0E,
    /// Version fallback triggered (0x0F)
    VersionFallback = 0x0F,
    /// Stream not found (0x10)
    StreamNotFound = 0x10,
    /// Flow control error (0x11)
    FlowControlError = 0x11,
    /// Final size error (0x12)
    FinalSizeError = 0x12,
    /// Stream limit error (0x13)
    StreamLimitError = 0x13,
}

/// HTTP/3 specific error codes as defined in RFC 9114
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum Http3ErrorCode {
    /// No error occurred (0x100)
    NoError = 0x100,
    /// General HTTP/3 protocol error (0x101)
    GeneralProtocolError = 0x101,
    /// Internal error in HTTP/3 implementation (0x102)
    InternalError = 0x102,
    /// Error creating HTTP/3 stream (0x103)
    StreamCreationError = 0x103,
    /// Critical HTTP/3 stream was closed (0x104)
    ClosedCriticalStream = 0x104,
    /// HTTP/3 frame received in wrong context (0x105)
    FrameUnexpected = 0x105,
    /// HTTP/3 frame format error (0x106)
    FrameError = 0x106,
    /// Excessive load detected in HTTP/3 layer (0x107)
    ExcessiveLoad = 0x107,
    /// HTTP/3 stream or connection ID error (0x108)
    IdError = 0x108,
    /// HTTP/3 SETTINGS frame error (0x109)
    SettingsError = 0x109,
    /// Required HTTP/3 SETTINGS missing (0x10A)
    MissingSettings = 0x10A,
    /// HTTP request was rejected (0x10B)
    RequestRejected = 0x10B,
    /// HTTP request was cancelled (0x10C)
    RequestCancelled = 0x10C,
    /// HTTP request transmission incomplete (0x10D)
    RequestIncomplete = 0x10D,
    /// HTTP message format error (0x10E)
    MessageError = 0x10E,
    /// HTTP CONNECT method error (0x10F)
    ConnectError = 0x10F,
    /// HTTP version fallback required (0x110)
    VersionFallback = 0x110,
}

/// QPACK specific error codes as defined in RFC 9204
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum QpackErrorCode {
    /// QPACK decompression failed (0x200)
    DecompressionFailed = 0x200,
    /// QPACK encoder stream error (0x201)
    EncoderStreamError = 0x201,
    /// QPACK decoder stream error (0x202)
    DecoderStreamError = 0x202,
}

impl ConnectionErrorCode {
    /// Check if this is an application-level error
    #[must_use]
    pub const fn is_application_error(self) -> bool {
        matches!(self, Self::ApplicationError)
    }

    /// Check if this is a transport-level error
    #[must_use]
    pub const fn is_transport_error(self) -> bool {
        !self.is_application_error()
    }
}

impl From<ConnectionErrorCode> for u64 {
    /// Convert connection error code to its numeric value
    fn from(code: ConnectionErrorCode) -> u64 {
        code as u64
    }
}

impl From<StreamErrorCode> for u64 {
    /// Convert stream error code to its numeric value
    fn from(code: StreamErrorCode) -> u64 {
        code as u64
    }
}

impl From<Http3ErrorCode> for u64 {
    /// Convert HTTP/3 error code to its numeric value
    fn from(code: Http3ErrorCode) -> u64 {
        code as u64
    }
}

impl From<QpackErrorCode> for u64 {
    /// Convert QPACK error code to its numeric value
    fn from(code: QpackErrorCode) -> u64 {
        code as u64
    }
}

impl TryFrom<u64> for ConnectionErrorCode {
    type Error = Error;

    /// Try to convert a numeric value to a connection error code
    /// 
    /// # Errors
    /// 
    /// Returns an error if the value doesn't correspond to a known error code.
    fn try_from(value: u64) -> Result<Self> {
        match value {
            0x00 => Ok(Self::NoError),
            0x01 => Ok(Self::InternalError),
            0x02 => Ok(Self::ConnectionRefused),
            0x03 => Ok(Self::FlowControlError),
            0x04 => Ok(Self::StreamLimitError),
            0x05 => Ok(Self::StreamStateError),
            0x06 => Ok(Self::FinalSizeError),
            0x07 => Ok(Self::FrameEncodingError),
            0x08 => Ok(Self::TransportParameterError),
            0x09 => Ok(Self::ConnectionIdLimitError),
            0x0A => Ok(Self::ProtocolViolation),
            0x0B => Ok(Self::InvalidToken),
            0x0C => Ok(Self::ApplicationError),
            0x0D => Ok(Self::CryptoBufferExceeded),
            0x0E => Ok(Self::KeyUpdateError),
            0x0F => Ok(Self::AeadLimitReached),
            0x10 => Ok(Self::NoViablePath),
            _ => Err(Error::ProtocolViolation(format!("Unknown connection error code: {value:#x}"))),
        }
    }
}

impl TryFrom<u64> for Http3ErrorCode {
    type Error = Error;

    /// Try to convert a numeric value to an HTTP/3 error code
    /// 
    /// # Errors
    /// 
    /// Returns an error if the value doesn't correspond to a known HTTP/3 error code.
    fn try_from(value: u64) -> Result<Self> {
        match value {
            0x100 => Ok(Self::NoError),
            0x101 => Ok(Self::GeneralProtocolError),
            0x102 => Ok(Self::InternalError),
            0x103 => Ok(Self::StreamCreationError),
            0x104 => Ok(Self::ClosedCriticalStream),
            0x105 => Ok(Self::FrameUnexpected),
            0x106 => Ok(Self::FrameError),
            0x107 => Ok(Self::ExcessiveLoad),
            0x108 => Ok(Self::IdError),
            0x109 => Ok(Self::SettingsError),
            0x10A => Ok(Self::MissingSettings),
            0x10B => Ok(Self::RequestRejected),
            0x10C => Ok(Self::RequestCancelled),
            0x10D => Ok(Self::RequestIncomplete),
            0x10E => Ok(Self::MessageError),
            0x10F => Ok(Self::ConnectError),
            0x110 => Ok(Self::VersionFallback),
            _ => Err(Error::ProtocolViolation(format!("Unknown HTTP/3 error code: {value:#x}"))),
        }
    }
}