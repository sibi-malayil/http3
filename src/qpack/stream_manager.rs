//! QPACK Stream Manager
//!
//! This module manages QPACK encoder and decoder streams, handling instruction
//! exchange, reference tracking, and table state synchronization per RFC 9204.

use crate::{
    error::{Error, Result},
    qpack::{
        encoder::Encoder,
        decoder::Decoder,
        EncoderInstruction,
        DecoderInstruction,
        field::HeaderField,
        Config,
    },
    whathappened::Level,
    {protocol_event},
};
use bytes::{Bytes, BytesMut, BufMut};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, RwLock, mpsc};

/// QPACK stream types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QpackStreamType {
    /// Encoder stream (from encoder to decoder)
    Encoder,
    /// Decoder stream (from decoder to encoder)
    Decoder,
}

/// Tracks references to dynamic table entries by streams
#[derive(Debug)]
struct ReferenceTracker {
    /// Map from stream ID to set of absolute indices referenced
    stream_references: HashMap<u64, HashSet<u64>>,
    /// Map from absolute index to set of streams referencing it
    index_references: HashMap<u64, HashSet<u64>>,
    /// Highest acknowledged insert count
    acknowledged_insert_count: u64,
    /// Streams that have been cancelled but not yet acknowledged
    cancelled_streams: HashSet<u64>,
}

impl ReferenceTracker {
    fn new() -> Self {
        Self {
            stream_references: HashMap::new(),
            index_references: HashMap::new(),
            acknowledged_insert_count: 0,
            cancelled_streams: HashSet::new(),
        }
    }

    /// Add a reference from a stream to an absolute index
    fn add_reference(&mut self, stream_id: u64, absolute_index: u64) {
        self.stream_references
            .entry(stream_id)
            .or_insert_with(HashSet::new)
            .insert(absolute_index);
        
        self.index_references
            .entry(absolute_index)
            .or_insert_with(HashSet::new)
            .insert(stream_id);
    }

    /// Remove all references from a stream (when acknowledged or cancelled)
    fn remove_stream_references(&mut self, stream_id: u64) {
        if let Some(indices) = self.stream_references.remove(&stream_id) {
            for index in indices {
                if let Some(streams) = self.index_references.get_mut(&index) {
                    streams.remove(&stream_id);
                    if streams.is_empty() {
                        self.index_references.remove(&index);
                    }
                }
            }
        }
        self.cancelled_streams.remove(&stream_id);
    }

    /// Mark a stream as cancelled
    fn cancel_stream(&mut self, stream_id: u64) {
        self.cancelled_streams.insert(stream_id);
    }

    /// Get the highest index that can be safely evicted
    fn get_evictable_index(&self) -> u64 {
        // Find the lowest referenced index
        if let Some(&min_referenced) = self.index_references.keys().min() {
            // Can evict anything below the lowest referenced index
            if min_referenced > 0 {
                min_referenced - 1
            } else {
                0
            }
        } else {
            // No references, can evict everything up to acknowledged count
            self.acknowledged_insert_count
        }
    }

    /// Check if a stream is blocked on dynamic table entries
    fn is_stream_blocked(&self, stream_id: u64) -> bool {
        self.stream_references.contains_key(&stream_id)
    }

    /// Get count of blocked streams
    fn blocked_stream_count(&self) -> usize {
        self.stream_references.len()
    }
}

/// Manages QPACK encoder/decoder streams and coordination
pub struct QpackStreamManager {
    /// The QPACK encoder
    encoder: Arc<Mutex<Encoder>>,
    /// The QPACK decoder  
    decoder: Arc<Mutex<Decoder>>,
    /// Reference tracking
    reference_tracker: Arc<RwLock<ReferenceTracker>>,
    /// Pending encoder instructions to send
    encoder_instruction_tx: mpsc::UnboundedSender<Bytes>,
    encoder_instruction_rx: Arc<Mutex<mpsc::UnboundedReceiver<Bytes>>>,
    /// Pending decoder instructions to send
    decoder_instruction_tx: mpsc::UnboundedSender<Bytes>,
    decoder_instruction_rx: Arc<Mutex<mpsc::UnboundedReceiver<Bytes>>>,
    /// Configuration
    config: Config,
    /// Statistics
    stats: Arc<Mutex<QpackStats>>,
}

impl QpackStreamManager {
    /// Creates a new QPACK stream manager
    pub fn new(config: Config) -> Self {
        let (encoder_tx, encoder_rx) = mpsc::unbounded_channel();
        let (decoder_tx, decoder_rx) = mpsc::unbounded_channel();
        
        Self {
            encoder: Arc::new(Mutex::new(Encoder::new(config.clone()))),
            decoder: Arc::new(Mutex::new(Decoder::new(config.clone()))),
            reference_tracker: Arc::new(RwLock::new(ReferenceTracker::new())),
            encoder_instruction_tx: encoder_tx,
            encoder_instruction_rx: Arc::new(Mutex::new(encoder_rx)),
            decoder_instruction_tx: decoder_tx,
            decoder_instruction_rx: Arc::new(Mutex::new(decoder_rx)),
            config,
            stats: Arc::new(Mutex::new(QpackStats::new())),
        }
    }

    /// Encode headers for a stream
    pub async fn encode_headers(
        &self,
        stream_id: u64,
        headers: Vec<HeaderField>,
        allow_blocking: bool,
    ) -> Result<Bytes> {
        let start = Instant::now();
        
        let mut encoder = self.encoder.lock().await;
        let encoded = encoder.encode_field_section(stream_id, &headers, allow_blocking)?;
        
        // Track any dynamic table references
        if let Some(references) = self.extract_references(&headers, &encoder) {
            let mut tracker = self.reference_tracker.write().await;
            for abs_index in references {
                tracker.add_reference(stream_id, abs_index);
            }
        }

        // Get any pending encoder instructions
        if let Some(instructions) = encoder.take_encoder_instructions() {
            let encoded_instructions = self.encode_instructions(instructions)?;
            self.encoder_instruction_tx.send(encoded_instructions)
                .map_err(|_| Error::Internal("Encoder instruction channel closed".to_string()))?;
        }

        // Update stats
        {
            let mut stats = self.stats.lock().await;
            stats.headers_encoded += 1;
            stats.total_encoded_bytes += encoded.len() as u64;
            stats.encoding_time += start.elapsed();
        }

        protocol_event!(
            Level::Debug,
            "Headers encoded";
            "stream_id" => stream_id,
            "header_count" => headers.len(),
            "encoded_size" => encoded.len(),
            "allow_blocking" => allow_blocking
        );

        Ok(encoded)
    }

    /// Decode headers for a stream
    pub async fn decode_headers(
        &self,
        stream_id: u64,
        data: Bytes,
    ) -> Result<Option<Vec<HeaderField>>> {
        let start = Instant::now();
        
        let mut decoder = self.decoder.lock().await;
        let result = decoder.decode_field_section(stream_id, data)?;
        
        if let Some(ref headers) = result {
            // Send acknowledgment if needed
            if let Some(ack) = decoder.get_pending_acknowledgment(stream_id) {
                let instruction = DecoderInstruction::SectionAcknowledgment { stream_id };
                let encoded = self.encode_decoder_instruction(instruction)?;
                self.decoder_instruction_tx.send(encoded)
                    .map_err(|_| Error::Internal("Decoder instruction channel closed".to_string()))?;
            }

            // Update stats
            let mut stats = self.stats.lock().await;
            stats.headers_decoded += 1;
            stats.decoding_time += start.elapsed();
            
            protocol_event!(
                Level::Debug,
                "Headers decoded";
                "stream_id" => stream_id,
                "header_count" => headers.len()
            );
        } else {
            // Headers are blocked, waiting for dynamic table updates
            protocol_event!(
                Level::Debug,
                "Headers blocked on dynamic table";
                "stream_id" => stream_id
            );
        }

        Ok(result)
    }

    /// Process encoder stream data (received at decoder)
    pub async fn process_encoder_stream(&self, data: Bytes) -> Result<()> {
        let mut decoder = self.decoder.lock().await;
        decoder.process_encoder_stream(data)?;
        
        // Check if any blocked streams can now be decoded
        let unblocked = decoder.get_unblocked_streams();
        for stream_id in unblocked {
            protocol_event!(
                Level::Debug,
                "Stream unblocked";
                "stream_id" => stream_id
            );
        }

        // Send insert count increment if needed
        if let Some(increment) = decoder.get_pending_insert_count_increment() {
            let instruction = DecoderInstruction::InsertCountIncrement { increment };
            let encoded = self.encode_decoder_instruction(instruction)?;
            self.decoder_instruction_tx.send(encoded)
                .map_err(|_| Error::Internal("Decoder instruction channel closed".to_string()))?;
        }

        Ok(())
    }

    /// Process decoder stream data (received at encoder)
    pub async fn process_decoder_stream(&self, data: Bytes) -> Result<()> {
        let mut encoder = self.encoder.lock().await;
        encoder.process_decoder_stream(data)?;
        
        // Update reference tracker based on acknowledgments
        if let Some(ack_info) = encoder.get_acknowledgment_info() {
            let mut tracker = self.reference_tracker.write().await;
            for stream_id in ack_info.acknowledged_streams {
                tracker.remove_stream_references(stream_id);
            }
            tracker.acknowledged_insert_count = ack_info.insert_count;
        }

        Ok(())
    }

    /// Handle stream cancellation
    pub async fn cancel_stream(&self, stream_id: u64) -> Result<()> {
        // Mark stream as cancelled in reference tracker
        {
            let mut tracker = self.reference_tracker.write().await;
            tracker.cancel_stream(stream_id);
        }

        // Send stream cancellation instruction
        let instruction = DecoderInstruction::StreamCancellation { stream_id };
        let encoded = self.encode_decoder_instruction(instruction)?;
        self.decoder_instruction_tx.send(encoded)
            .map_err(|_| Error::Internal("Decoder instruction channel closed".to_string()))?;

        protocol_event!(
            Level::Debug,
            "Stream cancelled";
            "stream_id" => stream_id
        );

        Ok(())
    }

    /// Update dynamic table capacity
    pub async fn set_dynamic_table_capacity(&self, capacity: u64) -> Result<()> {
        let mut encoder = self.encoder.lock().await;
        encoder.set_capacity(capacity)?;
        
        // This will generate a SetDynamicTableCapacity instruction
        if let Some(instructions) = encoder.take_encoder_instructions() {
            let encoded = self.encode_instructions(instructions)?;
            self.encoder_instruction_tx.send(encoded)
                .map_err(|_| Error::Internal("Encoder instruction channel closed".to_string()))?;
        }

        protocol_event!(
            Level::Info,
            "Dynamic table capacity updated";
            "new_capacity" => capacity
        );

        Ok(())
    }

    /// Get pending encoder stream data to send
    pub async fn get_encoder_stream_data(&self) -> Option<Bytes> {
        let mut rx = self.encoder_instruction_rx.lock().await;
        rx.recv().await
    }

    /// Get pending decoder stream data to send
    pub async fn get_decoder_stream_data(&self) -> Option<Bytes> {
        let mut rx = self.decoder_instruction_rx.lock().await;
        rx.recv().await
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> QpackStats {
        let stats = self.stats.lock().await;
        stats.clone()
    }

    /// Get reference tracking information
    pub async fn get_reference_info(&self) -> ReferenceInfo {
        let tracker = self.reference_tracker.read().await;
        ReferenceInfo {
            blocked_streams: tracker.blocked_stream_count(),
            evictable_index: tracker.get_evictable_index(),
            acknowledged_insert_count: tracker.acknowledged_insert_count,
        }
    }

    /// Extract dynamic table references from headers
    fn extract_references(
        &self,
        headers: &[HeaderField],
        encoder: &Encoder,
    ) -> Option<Vec<u64>> {
        // This would analyze which dynamic table entries are referenced
        // For now, returning None as this requires deeper encoder integration
        None
    }

    /// Encode encoder instructions
    fn encode_instructions(&self, instructions: Vec<EncoderInstruction>) -> Result<Bytes> {
        let mut buf = BytesMut::new();
        for instruction in instructions {
            self.encode_encoder_instruction(&mut buf, instruction)?;
        }
        Ok(buf.freeze())
    }

    /// Encode a single encoder instruction
    fn encode_encoder_instruction(
        &self,
        buf: &mut BytesMut,
        instruction: EncoderInstruction,
    ) -> Result<()> {
        match instruction {
            EncoderInstruction::SetDynamicTableCapacity { capacity } => {
                // 001xxxxx pattern
                if capacity < 31 {
                    buf.put_u8(0x20 | (capacity as u8));
                } else {
                    buf.put_u8(0x3F);
                    self.encode_varint(buf, capacity - 31)?;
                }
            }
            EncoderInstruction::InsertWithNameReference { table, name_index, value } => {
                if table {
                    // Static table reference: 11xxxxxx
                    if name_index < 63 {
                        buf.put_u8(0xC0 | (name_index as u8));
                    } else {
                        buf.put_u8(0xFF);
                        self.encode_varint(buf, name_index - 63)?;
                    }
                } else {
                    // Dynamic table reference: 10xxxxxx
                    if name_index < 63 {
                        buf.put_u8(0x80 | (name_index as u8));
                    } else {
                        buf.put_u8(0xBF);
                        self.encode_varint(buf, name_index - 63)?;
                    }
                }
                // Encode value
                self.encode_string(buf, value.as_bytes())?;
            }
            EncoderInstruction::InsertWithLiteralName { name, value } => {
                // 01Hxxxxx pattern
                let use_huffman = self.config.use_huffman;
                if use_huffman {
                    buf.put_u8(0x60); // 01100000
                } else {
                    buf.put_u8(0x40); // 01000000
                }
                self.encode_string(buf, name.as_bytes())?;
                self.encode_string(buf, value.as_bytes())?;
            }
            EncoderInstruction::Duplicate { index } => {
                // 000xxxxx pattern
                if index < 31 {
                    buf.put_u8(index as u8);
                } else {
                    buf.put_u8(0x1F);
                    self.encode_varint(buf, index - 31)?;
                }
            }
        }
        Ok(())
    }

    /// Encode a decoder instruction
    fn encode_decoder_instruction(&self, instruction: DecoderInstruction) -> Result<Bytes> {
        let mut buf = BytesMut::new();
        match instruction {
            DecoderInstruction::SectionAcknowledgment { stream_id } => {
                // 1xxxxxxx pattern
                if stream_id < 127 {
                    buf.put_u8(0x80 | (stream_id as u8));
                } else {
                    buf.put_u8(0xFF);
                    self.encode_varint(&mut buf, stream_id - 127)?;
                }
            }
            DecoderInstruction::StreamCancellation { stream_id } => {
                // 01xxxxxx pattern
                if stream_id < 63 {
                    buf.put_u8(0x40 | (stream_id as u8));
                } else {
                    buf.put_u8(0x7F);
                    self.encode_varint(&mut buf, stream_id - 63)?;
                }
            }
            DecoderInstruction::InsertCountIncrement { increment } => {
                // 00xxxxxx pattern
                if increment < 63 {
                    buf.put_u8(increment as u8);
                } else {
                    buf.put_u8(0x3F);
                    self.encode_varint(&mut buf, increment - 63)?;
                }
            }
        }
        Ok(buf.freeze())
    }

    /// Encode a variable-length integer
    fn encode_varint(&self, buf: &mut BytesMut, value: u64) -> Result<()> {
        // Simplified varint encoding - would use proper QPACK varint in production
        if value < 128 {
            buf.put_u8(value as u8);
        } else if value < 16384 {
            buf.put_u8(((value >> 7) | 0x80) as u8);
            buf.put_u8((value & 0x7F) as u8);
        } else {
            return Err(Error::QpackEncodingError("Varint too large".into()));
        }
        Ok(())
    }

    /// Encode a string (with optional Huffman encoding)
    fn encode_string(&self, buf: &mut BytesMut, value: &[u8]) -> Result<()> {
        // For now, always use literal encoding
        // Huffman encoding would be implemented here when needed
        if value.len() < 127 {
            buf.put_u8(value.len() as u8);
        } else {
            buf.put_u8(0x7F);
            self.encode_varint(buf, value.len() as u64 - 127)?;
        }
        buf.put_slice(value);
        Ok(())
    }
}

/// QPACK statistics
#[derive(Debug, Clone)]
pub struct QpackStats {
    /// Number of header blocks encoded
    pub headers_encoded: u64,
    /// Number of header blocks decoded
    pub headers_decoded: u64,
    /// Total encoded bytes
    pub total_encoded_bytes: u64,
    /// Total decoded bytes
    pub total_decoded_bytes: u64,
    /// Time spent encoding
    pub encoding_time: Duration,
    /// Time spent decoding
    pub decoding_time: Duration,
    /// Number of dynamic table insertions
    pub dynamic_insertions: u64,
    /// Number of evictions
    pub evictions: u64,
    /// Current dynamic table size
    pub dynamic_table_size: u64,
    /// Number of blocked streams
    pub blocked_streams: u64,
}

impl QpackStats {
    fn new() -> Self {
        Self {
            headers_encoded: 0,
            headers_decoded: 0,
            total_encoded_bytes: 0,
            total_decoded_bytes: 0,
            encoding_time: Duration::ZERO,
            decoding_time: Duration::ZERO,
            dynamic_insertions: 0,
            evictions: 0,
            dynamic_table_size: 0,
            blocked_streams: 0,
        }
    }

    /// Calculate compression ratio
    pub fn compression_ratio(&self) -> f64 {
        if self.total_decoded_bytes == 0 {
            0.0
        } else {
            self.total_encoded_bytes as f64 / self.total_decoded_bytes as f64
        }
    }
}

/// Reference tracking information
#[derive(Debug, Clone)]
pub struct ReferenceInfo {
    /// Number of streams currently blocked
    pub blocked_streams: usize,
    /// Highest index that can be safely evicted
    pub evictable_index: u64,
    /// Highest acknowledged insert count
    pub acknowledged_insert_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qpack::field::{HeaderName, HeaderValue};

    #[tokio::test]
    async fn test_stream_manager_creation() {
        let config = Config::default();
        let manager = QpackStreamManager::new(config);
        
        let stats = manager.get_stats().await;
        assert_eq!(stats.headers_encoded, 0);
        assert_eq!(stats.headers_decoded, 0);
    }

    #[tokio::test]
    async fn test_header_encoding() {
        let config = Config::default();
        let manager = QpackStreamManager::new(config);
        
        let headers = vec![
            HeaderField::new(
                HeaderName::new(":method").unwrap(),
                HeaderValue::new("GET").unwrap(),
            ),
            HeaderField::new(
                HeaderName::new(":path").unwrap(),
                HeaderValue::new("/").unwrap(),
            ),
        ];
        
        let encoded = manager.encode_headers(1, headers, true).await.unwrap();
        assert!(!encoded.is_empty());
        
        let stats = manager.get_stats().await;
        assert_eq!(stats.headers_encoded, 1);
    }

    #[tokio::test]
    async fn test_stream_cancellation() {
        let config = Config::default();
        let manager = QpackStreamManager::new(config);
        
        manager.cancel_stream(42).await.unwrap();
        
        // Should generate a decoder instruction
        let decoder_data = manager.get_decoder_stream_data().await;
        assert!(decoder_data.is_some());
    }

    #[tokio::test]
    async fn test_dynamic_table_capacity_update() {
        let config = Config::default();
        let manager = QpackStreamManager::new(config);
        
        manager.set_dynamic_table_capacity(8192).await.unwrap();
        
        // Should generate an encoder instruction
        let encoder_data = manager.get_encoder_stream_data().await;
        assert!(encoder_data.is_some());
    }

    #[tokio::test]
    async fn test_reference_tracking() {
        let config = Config::default();
        let manager = QpackStreamManager::new(config);
        
        let ref_info = manager.get_reference_info().await;
        assert_eq!(ref_info.blocked_streams, 0);
        assert_eq!(ref_info.acknowledged_insert_count, 0);
    }
}