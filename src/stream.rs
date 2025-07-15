//! Stream management placeholder

/// Stream ID type
pub type StreamId = u64;

/// Stream type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    /// Bidirectional stream
    Bidirectional,
    /// Unidirectional stream
    Unidirectional,
}

/// Stream state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    /// Stream is open for sending and receiving
    Open,
    /// Stream is closed
    Closed,
}

/// Stream placeholder
pub struct Stream {
    /// Stream ID
    pub id: StreamId,
    /// Stream type
    pub stream_type: StreamType,
    /// Stream state
    pub state: StreamState,
}