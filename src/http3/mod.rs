//! HTTP/3 protocol implementation
//!
//! This module implements the HTTP/3 protocol as specified in RFC 9114.
//! HTTP/3 is the mapping of HTTP semantics over QUIC transport that provides:
//! - Binary framing with stream multiplexing
//! - QPACK header compression
//! - Server push capabilities
//! - Prioritization and flow control

pub mod frame;
pub mod frame_simple;
pub mod connection;
pub mod stream;
pub mod settings;
pub mod priority;
pub mod priority_manager;
pub mod server_push;
pub mod connection_manager;
pub mod stream_multiplexer;
pub mod datagram;
pub mod webtransport;
pub mod message;

pub use frame::{Http3Frame, Http3FrameType, MaxStreamsFrame, StreamsBlockedFrame, DatagramFrame};
pub use frame_simple::{Frame, FrameType};
pub use settings::{Settings, SettingId};
pub use priority::{Priority, PriorityUpdateFrame, PriorityScheduler, StreamPriority};
pub use priority_manager::{PriorityManager, PriorityStats};
pub use server_push::{ServerPushManager, ServerPushConfig, PushPromise, PushStreamState};
pub use connection_manager::{ConnectionManager, StreamInfo, StreamState, ConnectionStats};
pub use stream_multiplexer::{StreamMultiplexer, StreamMultiplexerConfig, MultiplexerStats};
pub use datagram::{DatagramManager, DatagramConfig, DatagramStats, DatagramResult, DatagramReceived};
pub use webtransport::{WebTransportManager, WebTransportConfig, WebTransportStats, WebTransportSession, SessionId, SessionState, WebTransportStreamType, WebTransportStreamEvent, WebTransportDatagram};
pub use message::{Request, Response};

/// HTTP/3 version identifier
pub const VERSION: &[u8] = b"h3";

/// ALPN identifier for HTTP/3
pub const ALPN_H3: &[u8] = b"h3";

/// Maximum field section size (default)
pub const DEFAULT_MAX_FIELD_SECTION_SIZE: u64 = 16384;

/// Default QPACK blocked streams limit
pub const DEFAULT_QPACK_BLOCKED_STREAMS: u64 = 16;

/// Default QPACK table capacity
pub const DEFAULT_QPACK_TABLE_CAPACITY: u64 = 4096;

/// Well-known stream types per RFC 9114 Section 6.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamType {
    /// Control stream (0x00)
    Control = 0x00,
    /// Push stream (0x01)  
    Push = 0x01,
    /// QPACK encoder stream (0x02)
    QpackEncoder = 0x02,
    /// QPACK decoder stream (0x03)
    QpackDecoder = 0x03,
}

impl StreamType {
    /// Returns the stream type identifier
    pub fn id(self) -> u64 {
        self as u64
    }

    /// Creates a stream type from identifier
    pub fn from_id(id: u64) -> Option<Self> {
        match id {
            0x00 => Some(Self::Control),
            0x01 => Some(Self::Push),
            0x02 => Some(Self::QpackEncoder),
            0x03 => Some(Self::QpackDecoder),
            _ => None,
        }
    }

    /// Returns true if this is a unidirectional stream type
    pub fn is_unidirectional(self) -> bool {
        match self {
            Self::Control | Self::QpackEncoder | Self::QpackDecoder => true,
            Self::Push => true, // Push streams are unidirectional from server
        }
    }

    /// Returns true if this stream type can be initiated by client
    pub fn client_initiated(self) -> bool {
        match self {
            Self::Control | Self::QpackEncoder | Self::QpackDecoder => true,
            Self::Push => false, // Only server can initiate push streams
        }
    }
}

/// HTTP/3 connection roles
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionRole {
    /// Client role
    Client,
    /// Server role
    Server,
}

impl ConnectionRole {
    /// Returns true if this role can initiate push streams
    pub fn can_push(self) -> bool {
        matches!(self, Self::Server)
    }

    /// Returns true if this role can send PUSH_PROMISE frames
    pub fn can_promise(self) -> bool {
        matches!(self, Self::Server)
    }
}