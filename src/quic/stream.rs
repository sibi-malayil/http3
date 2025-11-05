//! QUIC stream management implementation
//!
//! Implements QUIC streams according to RFC 9000 Section 2.

use crate::{
    error::{Error, Result, StreamErrorCode},
    quic::connection::ConnectionRole,
    util::varint::VarInt,
    whathappened::Level,
    {protocol_event, span},
};
use bytes::{Bytes, BytesMut};
use std::{
    collections::{BTreeMap, VecDeque},
    cmp::Ordering,
};

/// QUIC stream identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(u64);

impl StreamId {
    /// Create a new stream ID
    pub fn new(id: u64, stream_type: StreamType, initiator: ConnectionRole) -> Result<Self> {
        // Validate stream ID format according to RFC 9000 Section 2.1
        let expected_initiator_bit = match initiator {
            ConnectionRole::Client => 0,
            ConnectionRole::Server => 1,
        };
        
        let expected_directionality_bit = match stream_type {
            StreamType::Bidirectional => 0,
            StreamType::Unidirectional => 2,
        };

        let expected_pattern = expected_initiator_bit | expected_directionality_bit;
        if (id & 3) != expected_pattern {
            return Err(Error::ProtocolViolation(
                format!("Invalid stream ID pattern: {}", id)
            ));
        }

        Ok(Self(id))
    }

    /// Get the raw stream ID value
    pub fn into_inner(self) -> u64 {
        self.0
    }

    /// Check if this stream was initiated by the client
    pub fn initiated_by_client(self) -> bool {
        (self.0 & 1) == 0
    }

    /// Check if this stream was initiated by the server
    pub fn initiated_by_server(self) -> bool {
        (self.0 & 1) == 1
    }

    /// Check if this is a bidirectional stream
    pub fn is_bidirectional(self) -> bool {
        (self.0 & 2) == 0
    }

    /// Check if this is a unidirectional stream
    pub fn is_unidirectional(self) -> bool {
        (self.0 & 2) == 2
    }

    /// Get the stream type
    pub fn stream_type(self) -> StreamType {
        if self.is_bidirectional() {
            StreamType::Bidirectional
        } else {
            StreamType::Unidirectional
        }
    }

    /// Get the next stream ID for the same role and type
    pub fn next(self, _role: ConnectionRole) -> Result<Self> {
        let next_id = self.0 + 4; // Stream IDs increment by 4
        if next_id >= (1u64 << 62) {
            return Err(Error::ProtocolViolation("Stream ID space exhausted".to_string()));
        }
        Ok(Self(next_id))
    }
}

impl From<u64> for StreamId {
    fn from(id: u64) -> Self {
        Self(id)
    }
}

impl From<StreamId> for u64 {
    fn from(id: StreamId) -> u64 {
        id.0
    }
}

impl From<StreamId> for VarInt {
    fn from(id: StreamId) -> VarInt {
        VarInt(id.0)
    }
}

impl std::fmt::Display for StreamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Stream type (bidirectional or unidirectional)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamType {
    /// Bidirectional stream (data flows both ways)
        Bidirectional,
    /// Unidirectional stream (data flows one way)
        Unidirectional,
}

/// Stream state according to RFC 9000 Section 3
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamState {
    /// Stream is open and can send/receive data
    Open,
    /// Local side has sent FIN
    HalfClosedLocal,
    /// Remote side has sent FIN
    HalfClosedRemote,
    /// Both sides have sent FIN
    Closed,
    /// Stream was reset by peer
    ResetRecv,
    /// Stream was reset locally
    ResetSent,
}

impl StreamState {
    /// Check if the stream can send data
    pub fn can_send(self) -> bool {
        matches!(self, Self::Open)
    }

    /// Check if the stream can receive data
    pub fn can_receive(self) -> bool {
        matches!(self, Self::Open | Self::HalfClosedLocal)
    }

    /// Check if the stream is closed
    pub fn is_closed(self) -> bool {
        matches!(self, Self::Closed | Self::ResetRecv | Self::ResetSent)
    }
}

/// Received data chunk with offset
#[derive(Debug, Clone)]
struct DataChunk {
    offset: u64,
    data: Bytes,
    fin: bool,
}

impl DataChunk {
    fn end_offset(&self) -> u64 {
        self.offset + self.data.len() as u64
    }
}

impl PartialEq for DataChunk {
    fn eq(&self, other: &Self) -> bool {
        self.offset == other.offset
    }
}

impl Eq for DataChunk {}

impl PartialOrd for DataChunk {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DataChunk {
    fn cmp(&self, other: &Self) -> Ordering {
        self.offset.cmp(&other.offset)
    }
}

/// QUIC stream implementation
pub struct Stream {
    /// Stream identifier
    id: StreamId,
    /// Stream state
    state: StreamState,
    /// Stream type
    stream_type: StreamType,
    /// Connection role that created this stream
    local_role: ConnectionRole,
    
    // Send side state
    /// Data to be sent
    send_buffer: BytesMut,
    /// Offset of next byte to send
    send_offset: u64,
    /// Whether FIN has been sent
    fin_sent: bool,
    /// Maximum data allowed to send (flow control)
    max_data_send: u64,
    /// Data already sent
    data_sent: u64,
    
    // Receive side state  
    /// Received data chunks (may be out of order)
    recv_chunks: BTreeMap<u64, DataChunk>,
    /// Next expected offset for ordered delivery
    recv_offset: u64,
    /// Whether FIN has been received
    fin_received: bool,
    /// Final size of the stream (if FIN received)
    final_size: Option<u64>,
    /// Maximum data allowed to receive (flow control)
    max_data_recv: u64,
    /// Data already received
    data_recv: u64,
    
    // Flow control
    /// Buffer to store assembled, ordered data for application
    ready_data: VecDeque<Bytes>,
    /// Whether to send MAX_STREAM_DATA frame
    should_send_max_data: bool,
}

impl Stream {
    #[cfg(test)]
    /// Test helper to set send limit
    pub fn test_set_send_limit(&mut self, limit: u64) {
        self.max_data_send = limit;
    }
    /// Create a new stream
    pub fn new(id: StreamId, local_role: ConnectionRole) -> Self {
        let stream_type = id.stream_type();
        
        protocol_event!(
            Level::Info,
            "Stream created";
            "stream_id" => id.0,
            "stream_type" => stream_type,
            "local_role" => local_role,
            "is_local" => match local_role {
                ConnectionRole::Client => id.initiated_by_client(),
                ConnectionRole::Server => id.initiated_by_server(),
            }
        );
        
        Self {
            id,
            state: StreamState::Open,
            stream_type,
            local_role,
            send_buffer: BytesMut::new(),
            send_offset: 0,
            fin_sent: false,
            max_data_send: 1048576, // 1MB default send window
            data_sent: 0,
            recv_chunks: BTreeMap::new(),
            recv_offset: 0,
            fin_received: false,
            final_size: None,
            max_data_recv: 65536, // Default 64KB window
            data_recv: 0,
            ready_data: VecDeque::new(),
            should_send_max_data: false,
        }
    }

    /// Get the stream ID
    pub fn id(&self) -> StreamId {
        self.id
    }

    /// Get the stream state
    pub fn state(&self) -> StreamState {
        self.state
    }

    /// Get the stream type
    pub fn stream_type(&self) -> StreamType {
        self.stream_type
    }

    /// Check if this stream was locally initiated
    pub fn is_local(&self) -> bool {
        match self.local_role {
            ConnectionRole::Client => self.id.initiated_by_client(),
            ConnectionRole::Server => self.id.initiated_by_server(),
        }
    }

    /// Queue data to be sent on this stream
    pub fn send_data(&mut self, data: Bytes, fin: bool) -> Result<u64> {
        let _span = span!(Level::Debug, "send_data", stream_id = self.id.0, data_len = data.len(), fin = fin);
        
        if !self.state.can_send() {
            protocol_event!(
                Level::Warn,
                "Cannot send data - stream in wrong state";
                "stream_id" => self.id.0,
                "state" => self.state,
                "data_len" => data.len()
            );
            return Err(Error::StreamError {
                code: StreamErrorCode::FrameUnexpected,
                reason: "Stream cannot send data in current state".to_string(),
            });
        }

        if self.fin_sent {
            protocol_event!(
                Level::Warn,
                "Cannot send data - FIN already sent";
                "stream_id" => self.id.0,
                "data_len" => data.len()
            );
            return Err(Error::StreamError {
                code: StreamErrorCode::FrameUnexpected,
                reason: "FIN already sent on stream".to_string(),
            });
        }

        // Check flow control
        if self.data_sent + data.len() as u64 > self.max_data_send {
            protocol_event!(
                Level::Warn,
                "Send blocked by flow control";
                "stream_id" => self.id.0,
                "data_len" => data.len(),
                "data_sent" => self.data_sent,
                "max_data_send" => self.max_data_send
            );
            return Err(Error::FlowControl);
        }

        let offset = self.send_offset;
        self.send_buffer.extend_from_slice(&data);
        self.send_offset += data.len() as u64;
        self.data_sent += data.len() as u64;

        protocol_event!(
            Level::Debug,
            "Stream data queued for sending";
            "stream_id" => self.id.0,
            "offset" => offset,
            "data_len" => data.len(),
            "fin" => fin,
            "total_sent" => self.data_sent
        );

        if fin {
            self.fin_sent = true;
            let old_state = self.state;
            match self.state {
                StreamState::Open => {
                    self.state = StreamState::HalfClosedLocal;
                }
                StreamState::HalfClosedRemote => {
                    self.state = StreamState::Closed;
                }
                _ => {}
            }
            
            if old_state != self.state {
                protocol_event!(
                    Level::Info,
                    "Stream state changed due to FIN sent";
                    "stream_id" => self.id.0,
                    "old_state" => old_state,
                    "new_state" => self.state
                );
            }
        }

        Ok(offset)
    }

    /// Receive data for this stream
    pub fn receive_data(&mut self, offset: u64, data: Bytes, fin: bool) -> Result<()> {
        let _span = span!(Level::Debug, "receive_data", stream_id = self.id.0, offset = offset, data_len = data.len(), fin = fin);
        
        if !self.state.can_receive() {
            protocol_event!(
                Level::Warn,
                "Cannot receive data - stream in wrong state";
                "stream_id" => self.id.0,
                "state" => self.state,
                "offset" => offset,
                "data_len" => data.len()
            );
            return Err(Error::StreamError {
                code: StreamErrorCode::FrameUnexpected,
                reason: "Stream cannot receive data in current state".to_string(),
            });
        }

        // Check for duplicate or old data
        if offset + data.len() as u64 <= self.recv_offset {
            protocol_event!(
                Level::Debug,
                "Duplicate or old data received, ignoring";
                "stream_id" => self.id.0,
                "offset" => offset,
                "data_len" => data.len(),
                "recv_offset" => self.recv_offset
            );
            return Ok(()); // Duplicate data, ignore
        }

        // Check flow control
        let end_offset = offset + data.len() as u64;
        if end_offset > self.max_data_recv {
            protocol_event!(
                Level::Warn,
                "Receive blocked by flow control";
                "stream_id" => self.id.0,
                "offset" => offset,
                "data_len" => data.len(),
                "end_offset" => end_offset,
                "max_data_recv" => self.max_data_recv
            );
            return Err(Error::FlowControl);
        }

        // Handle FIN
        if fin {
            if self.fin_received {
                // Check that final size is consistent
                if let Some(existing_final_size) = self.final_size {
                    if existing_final_size != end_offset {
                        protocol_event!(
                            Level::Error,
                            "Inconsistent final size on FIN";
                            "stream_id" => self.id.0,
                            "existing_final_size" => existing_final_size,
                            "new_final_size" => end_offset
                        );
                        return Err(Error::StreamError {
                            code: StreamErrorCode::FrameError,
                            reason: "Inconsistent final size".to_string(),
                        });
                    }
                }
            } else {
                self.fin_received = true;
                self.final_size = Some(end_offset);
                
                let old_state = self.state;
                match self.state {
                    StreamState::Open => {
                        self.state = StreamState::HalfClosedRemote;
                    }
                    StreamState::HalfClosedLocal => {
                        self.state = StreamState::Closed;
                    }
                    _ => {}
                }
                
                if old_state != self.state {
                    protocol_event!(
                        Level::Info,
                        "Stream state changed due to FIN received";
                        "stream_id" => self.id.0,
                        "old_state" => old_state,
                        "new_state" => self.state,
                        "final_size" => end_offset
                    );
                }
            }
        }

        // Insert data chunk
        let chunk = DataChunk { offset, data: data.clone(), fin };
        self.recv_chunks.insert(offset, chunk);
        self.data_recv += data.len() as u64;

        protocol_event!(
            Level::Debug,
            "Stream data received";
            "stream_id" => self.id.0,
            "offset" => offset,
            "data_len" => data.len(),
            "fin" => fin,
            "total_recv" => self.data_recv,
            "recv_chunks" => self.recv_chunks.len()
        );

        // Process any newly contiguous data
        self.process_recv_data();

        // Update flow control
        self.consider_flow_control_update();

        Ok(())
    }

    /// Process received data to make it available for reading
    fn process_recv_data(&mut self) {
        while let Some(chunk) = self.recv_chunks.remove(&self.recv_offset) {
            // Handle overlapping data
            let data_start = if chunk.offset < self.recv_offset {
                (self.recv_offset - chunk.offset) as usize
            } else {
                0
            };

            if data_start < chunk.data.len() {
                let useful_data = chunk.data.slice(data_start..);
                self.ready_data.push_back(useful_data.clone());
                self.recv_offset += useful_data.len() as u64;
            } else {
                // No useful data in this chunk
                self.recv_offset = chunk.end_offset();
            }

            // Check if stream is complete
            if chunk.fin && self.recv_offset >= self.final_size.unwrap_or(u64::MAX) {
                break;
            }
        }
    }

    /// Read data from the stream
    pub fn read_data(&mut self, max_length: usize) -> Option<Bytes> {
        if self.ready_data.is_empty() {
            return None;
        }

        let mut result = BytesMut::new();
        let mut remaining = max_length;

        while remaining > 0 && !self.ready_data.is_empty() {
            let chunk = self.ready_data.front_mut().unwrap();
            let to_take = std::cmp::min(remaining, chunk.len());
            
            result.extend_from_slice(&chunk[..to_take]);
            
            if to_take == chunk.len() {
                self.ready_data.pop_front();
            } else {
                *chunk = chunk.split_off(to_take);
            }
            
            remaining -= to_take;
        }

        if result.is_empty() {
            None
        } else {
            Some(result.freeze())
        }
    }

    /// Check if there is data available to read
    pub fn has_data(&self) -> bool {
        !self.ready_data.is_empty()
    }

    /// Check if the stream has finished receiving data
    pub fn is_finished(&self) -> bool {
        self.fin_received && 
        self.ready_data.is_empty() && 
        self.recv_offset >= self.final_size.unwrap_or(0)
    }

    /// Reset the stream
    pub fn reset(&mut self, error_code: u64, final_size: u64) -> Result<()> {
        let old_state = self.state;
        self.state = StreamState::ResetRecv;
        self.final_size = Some(final_size);
        
        // Clear receive buffers
        let cleared_chunks = self.recv_chunks.len();
        let cleared_ready_data = self.ready_data.len();
        self.recv_chunks.clear();
        self.ready_data.clear();
        
        protocol_event!(
            Level::Warn,
            "Stream reset";
            "stream_id" => self.id.0,
            "error_code" => error_code,
            "final_size" => final_size,
            "old_state" => old_state,
            "cleared_chunks" => cleared_chunks,
            "cleared_ready_data" => cleared_ready_data
        );
        
        Ok(())
    }

    /// Stop sending on the stream (respond to STOP_SENDING)
    pub fn stop_sending(&mut self, error_code: u64) -> Result<()> {
        let old_state = self.state;
        if self.state.can_send() {
            self.state = StreamState::ResetSent;
            let cleared_send_buffer = self.send_buffer.len();
            self.send_buffer.clear();
            
            protocol_event!(
                Level::Warn,
                "Stream stop sending";
                "stream_id" => self.id.0,
                "error_code" => error_code,
                "old_state" => old_state,
                "new_state" => self.state,
                "cleared_send_buffer" => cleared_send_buffer
            );
        }
        Ok(())
    }

    /// Handle STOP_SENDING frame from peer
    pub fn handle_stop_sending(&mut self, error_code: u64) -> Result<()> {
        self.stop_sending(error_code)
    }

    /// Receive a RESET_STREAM frame from peer
    pub fn receive_reset(&mut self, _error_code: u64, final_size: u64) -> Result<()> {
        self.state = StreamState::ResetRecv;
        self.final_size = Some(final_size);
        
        // Clear receive buffers
        self.recv_chunks.clear();
        self.ready_data.clear();
        
        Ok(())
    }

    /// Update the maximum data that can be sent (from MAX_STREAM_DATA frame)
    pub fn update_max_data(&mut self, max_data: u64) -> Result<()> {
        if max_data < self.max_data_send {
            protocol_event!(
                Level::Error,
                "MAX_STREAM_DATA decreased";
                "stream_id" => self.id.0,
                "old_max_data" => self.max_data_send,
                "new_max_data" => max_data
            );
            return Err(Error::StreamError {
                code: StreamErrorCode::FrameUnexpected,
                reason: "MAX_STREAM_DATA decreased".to_string(),
            });
        }
        
        let old_max = self.max_data_send;
        self.max_data_send = max_data;
        
        if max_data > old_max {
            protocol_event!(
                Level::Debug,
                "Stream send window increased";
                "stream_id" => self.id.0,
                "old_max_data" => old_max,
                "new_max_data" => max_data,
                "increase" => (max_data - old_max)
            );
        }
        
        Ok(())
    }

    /// Get the maximum data that can be received
    pub fn max_data_recv(&self) -> u64 {
        self.max_data_recv
    }

    /// Check if we should send MAX_STREAM_DATA frame
    pub fn should_send_max_stream_data(&self) -> bool {
        self.should_send_max_data
    }

    /// Consider sending MAX_STREAM_DATA frame
    pub fn consider_sending_max_stream_data(&mut self) {
        // Send update when window is more than 50% consumed
        let window_consumed = self.data_recv as f64 / self.max_data_recv as f64;
        self.should_send_max_data = window_consumed > 0.5;
    }

    /// Update flow control window
    fn consider_flow_control_update(&mut self) {
        let window_consumed = self.data_recv as f64 / self.max_data_recv as f64;
        if window_consumed > 0.5 {
            // Increase receive window
            let old_max = self.max_data_recv;
            self.max_data_recv = self.max_data_recv.saturating_mul(2);
            self.should_send_max_data = true;
            
            protocol_event!(
                Level::Debug,
                "Stream receive window expanded";
                "stream_id" => self.id.0,
                "old_max_data_recv" => old_max,
                "new_max_data_recv" => self.max_data_recv,
                "window_consumed" => window_consumed,
                "data_recv" => self.data_recv
            );
        }
    }
    
    /// Get the total bytes received on this stream
    pub fn bytes_received(&self) -> u64 {
        self.data_recv
    }
    
    /// Get the total bytes sent on this stream
    pub fn bytes_sent(&self) -> u64 {
        self.data_sent
    }
    
    /// Get the current receive maximum data limit
    pub fn receive_max_data(&self) -> u64 {
        self.max_data_recv
    }
    
    /// Set the receive maximum data limit
    pub fn set_receive_max_data(&mut self, max_data: u64) {
        self.max_data_recv = max_data;
    }
    
    /// Get the current send max data limit
    pub fn send_max_data(&self) -> u64 {
        self.max_data_send
    }
    
    /// Check if stream has data ready to send
    pub fn has_data_to_send(&self) -> bool {
        !self.send_buffer.is_empty() || (self.fin_sent && self.state != StreamState::Closed)
    }

    /// Get the final size of the stream (if FIN received)
    pub fn final_size(&self) -> Option<u64> {
        self.final_size
    }

    /// Get stream statistics
    pub fn stats(&self) -> StreamStats {
        StreamStats {
            id: self.id,
            state: self.state,
            stream_type: self.stream_type,
            data_sent: self.data_sent,
            data_recv: self.data_recv,
            max_data_send: self.max_data_send,
            max_data_recv: self.max_data_recv,
            pending_send: self.send_buffer.len(),
            pending_recv: self.ready_data.iter().map(|b| b.len()).sum(),
            is_finished: self.is_finished(),
        }
    }
}

/// Stream statistics
#[derive(Debug, Clone)]
pub struct StreamStats {
    /// Stream identifier
    pub id: StreamId,
    /// Current stream state
    pub state: StreamState,
    /// Type of stream (bidirectional/unidirectional)
    pub stream_type: StreamType,
    /// Total bytes sent on this stream
    pub data_sent: u64,
    /// Total bytes received on this stream
    pub data_recv: u64,
    /// Maximum bytes allowed to send
    pub max_data_send: u64,
    /// Maximum bytes allowed to receive
    pub max_data_recv: u64,
    /// Bytes pending to be sent
    pub pending_send: usize,
    /// Bytes pending to be received
    pub pending_recv: usize,
    /// Whether the stream has finished
    pub is_finished: bool,
}

impl Stream {
    /// Get stream's send offset
    pub fn send_offset(&self) -> u64 {
        self.send_offset
    }
    
    /// Get the size of pending send data
    pub fn pending_send_size(&self) -> usize {
        self.send_buffer.len()
    }
    
    /// Check if send is complete
    pub fn is_send_complete(&self) -> bool {
        self.fin_sent
    }
    
    /// Get pending send data up to max_size
    pub fn get_pending_send_data(&mut self, max_size: usize) -> Option<Bytes> {
        if self.send_buffer.is_empty() {
            return None;
        }
        
        let size = self.send_buffer.len().min(max_size);
        if size == 0 {
            return None;
        }
        
        let data = self.send_buffer.split_to(size);
        Some(Bytes::copy_from_slice(&data))
    }
    
    /// Advance the send offset
    pub fn advance_send_offset(&mut self, amount: u64) {
        self.send_offset += amount;
        self.data_sent += amount;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_id_validation() {
        // Client-initiated bidirectional stream
        let id = StreamId::new(0, StreamType::Bidirectional, ConnectionRole::Client).unwrap();
        assert!(id.initiated_by_client());
        assert!(id.is_bidirectional());

        // Server-initiated unidirectional stream  
        let id = StreamId::new(3, StreamType::Unidirectional, ConnectionRole::Server).unwrap();
        assert!(id.initiated_by_server());
        assert!(id.is_unidirectional());

        // Invalid pattern should fail
        assert!(StreamId::new(0, StreamType::Unidirectional, ConnectionRole::Client).is_err());
    }

    #[test]
    fn stream_state_transitions() {
        let mut stream = Stream::new(
            StreamId::new(0, StreamType::Bidirectional, ConnectionRole::Client).unwrap(),
            ConnectionRole::Client,
        );

        assert_eq!(stream.state(), StreamState::Open);
        assert!(stream.state().can_send());
        assert!(stream.state().can_receive());

        // Send data with FIN
        stream.send_data(Bytes::from("test"), true).unwrap();
        assert_eq!(stream.state(), StreamState::HalfClosedLocal);
        assert!(!stream.state().can_send());
        assert!(stream.state().can_receive());

        // Receive data with FIN
        stream.receive_data(0, Bytes::from("response"), true).unwrap();
        assert_eq!(stream.state(), StreamState::Closed);
        assert!(!stream.state().can_send());
        assert!(!stream.state().can_receive());
    }

    #[test]
    fn stream_data_ordering() {
        let mut stream = Stream::new(
            StreamId::new(0, StreamType::Bidirectional, ConnectionRole::Client).unwrap(),
            ConnectionRole::Client,
        );

        // Receive out-of-order data
        stream.receive_data(10, Bytes::from("world"), false).unwrap();
        assert!(!stream.has_data()); // Should not be readable yet

        stream.receive_data(0, Bytes::from("hello "), false).unwrap();
        assert!(stream.has_data()); // Should be readable now

        // Read the data
        let data = stream.read_data(100).unwrap();
        assert_eq!(data, Bytes::from("hello world"));
    }

    #[test]
    fn stream_flow_control() {
        let mut stream = Stream::new(
            StreamId::new(0, StreamType::Bidirectional, ConnectionRole::Client).unwrap(),
            ConnectionRole::Client,
        );

        // Set a small send window
        stream.max_data_send = 5;

        // Should be able to send within window
        assert!(stream.send_data(Bytes::from("hello"), false).is_ok());

        // Should fail to send beyond window
        assert!(stream.send_data(Bytes::from("world"), false).is_err());

        // Update window and try again
        stream.update_max_data(20).unwrap();
        assert!(stream.send_data(Bytes::from("world"), false).is_ok());
    }

    #[test]
    fn stream_reset() {
        let mut stream = Stream::new(
            StreamId::new(0, StreamType::Bidirectional, ConnectionRole::Client).unwrap(),
            ConnectionRole::Client,
        );

        stream.receive_data(0, Bytes::from("data"), false).unwrap();
        assert!(stream.has_data());

        stream.reset(42, 4).unwrap();
        assert_eq!(stream.state(), StreamState::ResetRecv);
        assert!(!stream.has_data()); // Data should be cleared
    }
}