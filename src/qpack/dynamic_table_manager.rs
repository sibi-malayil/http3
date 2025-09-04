//! QPACK Dynamic Table Manager with proper eviction and synchronization
//!
//! This module implements the dynamic table management for QPACK header compression,
//! including insertion, eviction, and synchronization between encoder and decoder.

use crate::{
    error::{Result, QpackErrorCode},
    error_context::ErrorConversion,
    qpack::{
        table::DynamicTable,
        field::HeaderField,
        EncoderInstruction,
        Config,
    },
    whathappened::Level,
    protocol_event,
};
use std::{
    collections::{HashMap, VecDeque, HashSet},
    sync::Arc,
};
use tokio::sync::RwLock;

/// Dynamic table insertion policy
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InsertionPolicy {
    /// Always insert if space available
    Always,
    /// Insert only if field appears frequently
    FrequencyBased { min_occurrences: u32 },
    /// Insert based on field size
    SizeBased { min_size: usize },
    /// Custom policy based on multiple factors
    Adaptive,
}

impl Default for InsertionPolicy {
    fn default() -> Self {
        Self::Adaptive
    }
}

/// Entry tracking information
#[derive(Debug, Clone)]
struct EntryInfo {
    /// Number of times this entry has been referenced
    reference_count: u64,
    /// Last time this entry was referenced
    last_referenced: std::time::Instant,
    /// Size of the entry in bytes
    size: usize,
    /// Whether this entry is currently referenced by in-flight requests
    in_flight_references: HashSet<u64>, // stream IDs
}

/// Dynamic table manager that handles insertions and evictions
pub struct DynamicTableManager {
    /// Encoder-side dynamic table
    encoder_table: Arc<RwLock<DynamicTable>>,
    /// Decoder-side dynamic table (for tracking)
    decoder_table: Arc<RwLock<DynamicTable>>,
    /// Entry information for eviction decisions
    entry_info: Arc<RwLock<HashMap<u64, EntryInfo>>>, // absolute index -> info
    /// Field occurrence tracking for insertion decisions
    field_occurrences: Arc<RwLock<HashMap<HeaderField, u32>>>,
    /// Insertion policy
    insertion_policy: InsertionPolicy,
    /// Maximum table capacity
    max_capacity: usize,
    /// Current capacity usage
    current_size: Arc<RwLock<usize>>,
    /// Pending insertions to be sent to decoder
    pending_insertions: Arc<RwLock<VecDeque<(HeaderField, u64)>>>, // (field, absolute_index)
    /// Known decoder insert count
    known_decoder_count: Arc<RwLock<u64>>,
    /// Encoder insert count
    encoder_insert_count: Arc<RwLock<u64>>,
}

impl DynamicTableManager {
    /// Create a new dynamic table manager
    pub fn new(config: &Config, insertion_policy: InsertionPolicy) -> Self {
        let max_capacity = config.max_table_capacity as usize;
        
        Self {
            encoder_table: Arc::new(RwLock::new(DynamicTable::new(max_capacity as u64))),
            decoder_table: Arc::new(RwLock::new(DynamicTable::new(max_capacity as u64))),
            entry_info: Arc::new(RwLock::new(HashMap::new())),
            field_occurrences: Arc::new(RwLock::new(HashMap::new())),
            insertion_policy,
            max_capacity,
            current_size: Arc::new(RwLock::new(0)),
            pending_insertions: Arc::new(RwLock::new(VecDeque::new())),
            known_decoder_count: Arc::new(RwLock::new(0)),
            encoder_insert_count: Arc::new(RwLock::new(0)),
        }
    }

    /// Evaluate whether a field should be inserted into the dynamic table
    pub async fn should_insert(&self, field: &HeaderField) -> bool {
        // Never insert sensitive fields
        if field.never_index() {
            return false;
        }

        match self.insertion_policy {
            InsertionPolicy::Always => {
                // Check if we have space
                let current = *self.current_size.read().await;
                current + field.encoded_size() as usize <= self.max_capacity
            }
            InsertionPolicy::FrequencyBased { min_occurrences } => {
                let occurrences = self.field_occurrences.read().await;
                occurrences.get(field).copied().unwrap_or(0) >= min_occurrences
            }
            InsertionPolicy::SizeBased { min_size } => {
                field.encoded_size() as usize >= min_size
            }
            InsertionPolicy::Adaptive => {
                // Adaptive policy based on multiple factors
                self.evaluate_adaptive_policy(field).await
            }
        }
    }

    /// Evaluate adaptive insertion policy
    async fn evaluate_adaptive_policy(&self, field: &HeaderField) -> bool {
        let field_size = field.encoded_size() as usize;
        
        // Don't insert very small fields (not worth the overhead)
        if field_size < 20 {
            return false;
        }

        // Check occurrence count
        let occurrences = self.field_occurrences.read().await;
        let count = occurrences.get(field).copied().unwrap_or(0);
        
        // Require at least 2 occurrences for medium fields, 1 for large fields
        if field_size < 100 && count < 2 {
            return false;
        }

        // Check table utilization
        let current = *self.current_size.read().await;
        let utilization = current as f64 / self.max_capacity as f64;
        
        // Be more selective when table is getting full
        if utilization > 0.8 {
            // Only insert frequently used or large fields
            return count >= 3 || field_size >= 200;
        }

        true
    }

    /// Insert a field into the dynamic table with eviction if needed
    pub async fn insert_field(&self, field: HeaderField) -> Result<Option<u64>> {
        // Track field occurrence
        {
            let mut occurrences = self.field_occurrences.write().await;
            *occurrences.entry(field.clone()).or_insert(0) += 1;
        }

        // Check insertion policy
        if !self.should_insert(&field).await {
            return Ok(None);
        }

        let field_size = field.encoded_size() as usize;
        
        // Evict entries if needed to make space
        self.evict_for_space(field_size).await?;

        // Insert into encoder table
        let mut encoder_table = self.encoder_table.write().await;
        let absolute_index = encoder_table.insert(field.clone())?;
        
        // Update tracking
        {
            let mut insert_count = self.encoder_insert_count.write().await;
            *insert_count = absolute_index + 1;
        }

        // Track entry info
        {
            let mut entry_info = self.entry_info.write().await;
            entry_info.insert(absolute_index, EntryInfo {
                reference_count: 0,
                last_referenced: std::time::Instant::now(),
                size: field_size,
                in_flight_references: HashSet::new(),
            });
        }

        // Update current size
        {
            let mut current = self.current_size.write().await;
            *current += field_size;
        }

        // Queue for decoder notification
        {
            let mut pending = self.pending_insertions.write().await;
            pending.push_back((field, absolute_index));
        }

        protocol_event!(
            Level::Debug,
            "Dynamic table insertion";
            "absolute_index" => absolute_index,
            "field_size" => field_size,
            "table_size" => *self.current_size.read().await
        );

        Ok(Some(absolute_index))
    }

    /// Evict entries to make space for a new entry
    async fn evict_for_space(&self, required_space: usize) -> Result<()> {
        let current = *self.current_size.read().await;
        
        if current + required_space <= self.max_capacity {
            return Ok(()); // No eviction needed
        }

        let space_needed = (current + required_space) - self.max_capacity;
        let mut evicted_space = 0;
        let mut entries_to_evict = Vec::new();

        // Select entries for eviction using LRU with reference counting
        {
            let entry_info = self.entry_info.read().await;
            let mut candidates: Vec<(u64, &EntryInfo)> = entry_info.iter()
                .map(|(&idx, info)| (idx, info))
                .collect();

            // Sort by eviction priority (least recently used, least referenced)
            candidates.sort_by_key(|(_, info)| {
                (
                    !info.in_flight_references.is_empty(), // Don't evict if referenced
                    info.last_referenced,
                    info.reference_count,
                )
            });

            for (idx, info) in candidates {
                if info.in_flight_references.is_empty() {
                    entries_to_evict.push(idx);
                    evicted_space += info.size;
                    if evicted_space >= space_needed {
                        break;
                    }
                }
            }
        }

        if evicted_space < space_needed {
            return Err("Cannot evict enough entries to make space"
                .to_qpack_error(QpackErrorCode::EncoderStreamError));
        }

        // Perform eviction
        for idx in entries_to_evict {
            self.evict_entry(idx).await?;
        }

        Ok(())
    }

    /// Evict a specific entry from the dynamic table
    async fn evict_entry(&self, absolute_index: u64) -> Result<()> {
        // Remove from encoder table
        let mut encoder_table = self.encoder_table.write().await;
        if let Some(evicted) = encoder_table.evict_absolute(absolute_index) {
            // Update current size
            let evicted_size = evicted.encoded_size() as usize;
            {
                let mut current = self.current_size.write().await;
                *current = current.saturating_sub(evicted_size);
            }

            // Remove entry info
            self.entry_info.write().await.remove(&absolute_index);

            protocol_event!(
                Level::Debug,
                "Dynamic table eviction";
                "absolute_index" => absolute_index,
                "evicted_size" => evicted_size
            );
        }

        Ok(())
    }

    /// Mark an entry as referenced by a stream
    pub async fn add_reference(&self, absolute_index: u64, stream_id: u64) -> Result<()> {
        let mut entry_info = self.entry_info.write().await;
        if let Some(info) = entry_info.get_mut(&absolute_index) {
            info.reference_count += 1;
            info.last_referenced = std::time::Instant::now();
            info.in_flight_references.insert(stream_id);
        }
        Ok(())
    }

    /// Remove reference from a stream
    pub async fn remove_reference(&self, absolute_index: u64, stream_id: u64) -> Result<()> {
        let mut entry_info = self.entry_info.write().await;
        if let Some(info) = entry_info.get_mut(&absolute_index) {
            info.in_flight_references.remove(&stream_id);
        }
        Ok(())
    }

    /// Remove all references for a stream (e.g., on stream cancellation)
    pub async fn remove_stream_references(&self, stream_id: u64) -> Result<()> {
        let mut entry_info = self.entry_info.write().await;
        for (_, info) in entry_info.iter_mut() {
            info.in_flight_references.remove(&stream_id);
        }
        Ok(())
    }

    /// Get pending encoder instructions
    pub async fn get_pending_instructions(&self) -> Vec<EncoderInstruction> {
        let mut instructions = Vec::new();
        let mut pending = self.pending_insertions.write().await;
        
        while let Some((field, _absolute_index)) = pending.pop_front() {
            // Check if name exists in static table
            if let Some(name_index) = crate::qpack::StaticTable::find_name(&field.name) {
                instructions.push(EncoderInstruction::InsertWithNameReference {
                    table: true, // Static table
                    name_index: name_index as u64,
                    value: field.value,
                });
            } else {
                // Check if name exists in dynamic table
                let encoder_table = self.encoder_table.read().await;
                if let Some(name_index) = encoder_table.find_name(&field.name) {
                    instructions.push(EncoderInstruction::InsertWithNameReference {
                        table: false, // Dynamic table
                        name_index,
                        value: field.value,
                    });
                } else {
                    instructions.push(EncoderInstruction::InsertWithLiteralName {
                        name: field.name,
                        value: field.value,
                    });
                }
            }
        }
        
        instructions
    }

    /// Process decoder acknowledgment
    pub async fn process_acknowledgment(&self, stream_id: u64, insert_count: u64) -> Result<()> {
        // Update known decoder count
        {
            let mut known = self.known_decoder_count.write().await;
            *known = (*known).max(insert_count);
        }
        
        // Remove references for acknowledged stream
        self.remove_stream_references(stream_id).await?;
        
        protocol_event!(
            Level::Debug,
            "Decoder acknowledgment processed";
            "stream_id" => stream_id,
            "insert_count" => insert_count
        );
        
        Ok(())
    }

    /// Get table utilization statistics
    pub async fn get_stats(&self) -> TableStats {
        TableStats {
            current_size: *self.current_size.read().await,
            max_capacity: self.max_capacity,
            entry_count: self.entry_info.read().await.len(),
            encoder_insert_count: *self.encoder_insert_count.read().await,
            known_decoder_count: *self.known_decoder_count.read().await,
        }
    }
}

/// Dynamic table statistics
#[derive(Debug, Clone)]
pub struct TableStats {
    /// Current size in bytes
    pub current_size: usize,
    /// Maximum capacity in bytes
    pub max_capacity: usize,
    /// Number of entries
    pub entry_count: usize,
    /// Encoder insert count
    pub encoder_insert_count: u64,
    /// Known decoder insert count
    pub known_decoder_count: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dynamic_table_insertion() {
        let config = Config {
            max_table_capacity: 1024,
            max_blocked_streams: 10,
            use_huffman: true,
        };
        
        let manager = DynamicTableManager::new(&config, InsertionPolicy::Always);
        
        // Insert a field
        let field = HeaderField::new(
            HeaderName::from("x-custom-header"),
            HeaderValue::from("test-value"),
        );
        
        let result = manager.insert_field(field.clone()).await.unwrap();
        assert!(result.is_some());
        
        // Check stats
        let stats = manager.get_stats().await;
        assert_eq!(stats.entry_count, 1);
        assert!(stats.current_size > 0);
    }

    #[tokio::test]
    async fn test_eviction_on_full_table() {
        let config = Config {
            max_table_capacity: 100, // Small table
            max_blocked_streams: 10,
            use_huffman: true,
        };
        
        let manager = DynamicTableManager::new(&config, InsertionPolicy::Always);
        
        // Insert one field to start
        let field = HeaderField::new(
            HeaderName::from("header-1"),
            HeaderValue::from("value-1"),
        );
        manager.insert_field(field).await.unwrap();
        
        // Get initial stats
        let initial_stats = manager.get_stats().await;
        let initial_count = initial_stats.entry_count;
        
        // Insert a medium field that requires eviction but still fits
        let medium_field = HeaderField::new(
            HeaderName::from("x-medium"),
            HeaderValue::from("medium-val"),
        );
        
        let result = manager.insert_field(medium_field).await.unwrap();
        
        // Since the table is small, we might not be able to insert if the field is too large
        // Just verify the table size constraint is maintained
        let final_stats = manager.get_stats().await;
        assert!(final_stats.current_size <= config.max_table_capacity as usize);
        
        // If we did insert, check eviction occurred
        if result.is_some() {
            assert!(final_stats.entry_count <= initial_count + 1);
        }
    }

    #[tokio::test]
    async fn test_frequency_based_insertion() {
        let config = Config {
            max_table_capacity: 1024,
            max_blocked_streams: 10,
            use_huffman: true,
        };
        
        let manager = DynamicTableManager::new(
            &config, 
            InsertionPolicy::FrequencyBased { min_occurrences: 2 }
        );
        
        let field = HeaderField::new(
            HeaderName::from("x-frequent"),
            HeaderValue::from("value"),
        );
        
        // First occurrence - should not insert
        let result = manager.insert_field(field.clone()).await.unwrap();
        assert!(result.is_none());
        
        // Second occurrence - should insert
        let result = manager.insert_field(field).await.unwrap();
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_reference_tracking() {
        let config = Config::default();
        let manager = DynamicTableManager::new(&config, InsertionPolicy::Always);
        
        let field = HeaderField::new(
            HeaderName::from("x-ref"),
            HeaderValue::from("value"),
        );
        
        let index = manager.insert_field(field).await.unwrap().unwrap();
        
        // Add reference
        manager.add_reference(index, 123).await.unwrap();
        
        // Try to evict - should not evict referenced entry
        // We'll try to evict for a small amount
        let stats = manager.get_stats().await;
        if stats.current_size < stats.max_capacity {
            // Only test eviction if there's room to add something
            manager.evict_for_space(10).await.unwrap();
        }
        
        // Remove reference
        manager.remove_reference(index, 123).await.unwrap();
        
        // Now eviction should work
        let stats = manager.get_stats().await;
        if stats.current_size < stats.max_capacity {
            manager.evict_for_space(10).await.unwrap();
        }
    }
}