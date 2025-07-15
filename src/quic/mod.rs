//! QUIC transport protocol implementation
//!
//! This module implements the QUIC transport protocol as specified in RFC 9000.
//! QUIC is a general-purpose transport protocol that provides:
//! - Connection-oriented communication with unique connection IDs
//! - Stream multiplexing without head-of-line blocking
//! - Built-in security via TLS 1.3
//! - Connection migration and loss recovery

pub mod packet;
pub mod frame;
pub mod frame_types;
pub mod connection;
pub mod stream;
pub mod stream_manager;
pub mod crypto;
pub mod crypto_impl;
pub mod crypto_test;
pub mod crypto_enhanced;
pub mod rustls_keys;
pub mod recovery;
pub mod congestion;
pub mod bbr;
pub mod cubic;
pub mod pacing;
pub mod ecn;
pub mod transport;
pub mod encryption;
pub mod ack_manager;
pub mod migration;
pub mod zero_rtt;
pub mod unreliable;
pub mod version;

#[cfg(test)]
mod flow_control_tests;

#[cfg(test)]
mod flow_control_integration_tests;

pub use packet::{Packet, PacketHeader, PacketType, LongHeader, ShortHeader, ConnectionId};
pub use frame::{Frame, FrameType};
pub use connection::{Connection, ConnectionState};
pub use stream::{Stream, StreamId, StreamType, StreamState};
pub use stream_manager::{StreamManager, StreamParameters, StreamPriority, StreamEvent, FramePriority, TransmissionStats};
pub use encryption::{PacketSpace, PacketNumberSpace, PacketNumberLength, PacketProtection};
pub use unreliable::{UnreliableDeliveryManager, UnreliableConfig, UnreliableStats, UnreliableResult, ReceivedDatagram};
pub use version::{VersionNegotiator, VersionConfig, VersionNegotiationPacket, CompatibleVersions, VERSION_NEGOTIATION};

/// QUIC version 1 as defined in RFC 9000
pub const VERSION_1: u32 = 0x0000_0001;

/// Maximum size of a QUIC packet
pub const MAX_PACKET_SIZE: usize = 65535;

/// Minimum size of a QUIC packet
pub const MIN_PACKET_SIZE: usize = 1200;

/// Maximum connection ID length
pub const MAX_CID_LEN: usize = 20;

/// Minimum connection ID length for initial packets
pub const MIN_INITIAL_CID_LEN: usize = 8;