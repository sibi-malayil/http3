//! QPACK static and dynamic table implementation per RFC 9204

use crate::error::{Error, Result};
use crate::qpack::field::{HeaderField, HeaderName, HeaderValue};
use std::collections::VecDeque;

/// QPACK static table per RFC 9204 Appendix A
pub struct StaticTable;

impl StaticTable {
    /// Get header field by index (1-based indexing)
    pub fn get(index: u64) -> Option<HeaderField> {
        if index == 0 || index > STATIC_TABLE.len() as u64 {
            return None;
        }
        
        let (name, value) = STATIC_TABLE[(index - 1) as usize];
        Some(HeaderField::new(
            HeaderName::new(name).unwrap(),
            HeaderValue::new(value).unwrap(),
        ))
    }
    
    /// Get header name by index (1-based indexing)
    pub fn get_name(index: u64) -> Option<HeaderName> {
        if index == 0 || index > STATIC_TABLE.len() as u64 {
            return None;
        }
        
        let (name, _) = STATIC_TABLE[(index - 1) as usize];
        Some(HeaderName::new(name).unwrap())
    }
    
    /// Find index of header field in static table
    pub fn find(field: &HeaderField) -> Option<u64> {
        for (i, (name, value)) in STATIC_TABLE.iter().enumerate() {
            if field.name.as_str() == *name && field.value.as_str().unwrap_or("") == *value {
                return Some((i + 1) as u64);
            }
        }
        None
    }
    
    /// Find index of header field in static table (legacy alias)
    pub fn find_field(field: &HeaderField) -> Option<u64> {
        Self::find(field)
    }
    
    /// Find index of header name in static table
    pub fn find_name(name: &HeaderName) -> Option<u64> {
        for (i, (table_name, _)) in STATIC_TABLE.iter().enumerate() {
            if name.as_str() == *table_name {
                return Some((i + 1) as u64);
            }
        }
        None
    }
    
    /// Get the size of the static,
    pub fn size() -> u64 {
        STATIC_TABLE.len() as u64
    }
}

/// QPACK dynamic table with evict on and size management
#[derive(Debug)]
pub struct DynamicTable {
    entries: VecDeque<HeaderField>,
    capacity: u64,
    size: u64,
    insert_count: u64,
    draining_index: u64,
}

impl DynamicTable {
    /// Create a new dynamic table with the specified capacity
    pub fn new(capacity: u64) -> Self {
        Self {
            entries: VecDeque::new(),
            capacity,
            size: 0,
            insert_count: 0,
            draining_index: 0,
        }
    }
    
    /// Set the table capacity and evict entries if necessary
    /// 
    /// # Errors
    /// 
    /// Returns an error if eviction fails.
    pub fn set_capacity(&mut self, capacity: u64) -> Result<()> {
        self.capacity = capacity;
        self.evict_to_fit(0)?;
        Ok(())
    }
    
    /// Get the current capacity
    pub fn capacity(&self) -> u64 {
        self.capacity
    }
    
    /// Get the current size in bytes
    pub fn size(&self) -> u64 {
        self.size
    }
    
    /// Get the current insert count
    pub fn insert_count(&self) -> u64 {
        self.insert_count
    }
    
    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    
    /// Check if the table is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    
    /// Insert a new header field into the table
    /// 
    /// # Errors
    /// 
    /// Returns an error if the field exceeds table capacity or eviction fails.
    pub fn insert(&mut self, field: HeaderField) -> Result<u64> {
        let field_size = field.size() as u64;
        
        // Check if the field fits in the table
        if field_size > self.capacity {
            return Err(Error::QpackTableSizeExceeded);
        }
        
        // Evict entries to make space
        self.evict_to_fit(field_size)?;
        
        // Insert the new field at the front
        self.entries.push_front(field);
        self.size += field_size;
        self.insert_count += 1;
        
        Ok(self.insert_count)
    }
    
    /// Duplicate an existing entry (relative index from most recent)
    /// 
    /// # Errors
    /// 
    /// Returns an error if the index is invalid or insertion fails.
    pub fn duplicate(&mut self, relative_index: u64) -> Result<u64> {
        if relative_index >= self.entries.len() as u64 {
            return Err(Error::QpackInvalidIndex);
        }
        
        let field = self.entries[relative_index as usize].clone();
        self.insert(field)
    }
    
    /// Get header field by relative index (0-based from most recent)
    pub fn get(&self, relative_index: u64) -> Option<&HeaderField> {
        if relative_index >= self.entries.len() as u64 {
            return None;
        }
        self.entries.get(relative_index as usize)
    }
    
    /// Get header field by absolute index (insert count based)
    pub fn get_by_absolute_index(&self, absolute_index: u64) -> Option<&HeaderField> {
        if absolute_index > self.insert_count || absolute_index <= self.draining_index {
            return None;
        }
        
        let relative_index = self.insert_count - absolute_index;
        self.get(relative_index)
    }
    
    /// Convert absolute index to relative index
    pub fn absolute_to_relative(&self, absolute_index: u64) -> Option<u64> {
        if absolute_index > self.insert_count || absolute_index <= self.draining_index {
            return None;
        }
        Some(self.insert_count - absolute_index)
    }
    
    /// Convert relative index to absolute index
    pub fn relative_to_absolute(&self, relative_index: u64) -> Option<u64> {
        if relative_index >= self.entries.len() as u64 {
            return None;
        }
        Some(self.insert_count - relative_index)
    }

    /// Evict entry by absolute index
    pub fn evict_absolute(&mut self, absolute_index: u64) -> Option<HeaderField> {
        // Convert absolute to relative
        if let Some(relative_index) = self.absolute_to_relative(absolute_index) {
            if relative_index < self.entries.len() as u64 {
                let entry = self.entries.remove(relative_index as usize).unwrap();
                self.size = self.size.saturating_sub(entry.size() as u64);
                return Some(entry);
            }
        }
        None
    }

    /// Check if a field can be inserted given its size
    pub fn can_insert(&self, field_size: usize) -> bool {
        field_size as u64 <= self.capacity
    }
    
    /// Find the index of a header field in the table
    pub fn find_field(&self, field: &HeaderField) -> Option<u64> {
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.name == field.name && entry.value == field.value {
                return Some(i as u64);
            }
        }
        None
    }
    
    /// Find the index of a header name in the table
    pub fn find_name(&self, name: &HeaderName) -> Option<u64> {
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.name == *name {
                return Some(i as u64);
            }
        }
        None
    }
    
    /// Evict entries to make room for a new entry of the specified size
    /// 
    /// # Errors
    /// 
    /// Returns an error if the needed size exceeds table capacity.
    fn evict_to_fit(&mut self, needed_size: u64) -> Result<()> {
        while self.size + needed_size > self.capacity && !self.entries.is_empty() {
            if let Some(evicted) = self.entries.pop_back() {
                self.size -= evicted.size() as u64;
                self.draining_index += 1;
            }
        }
        
        if self.size + needed_size > self.capacity {
            return Err(Error::QpackTableSizeExceeded);
        }
        
        Ok(())
    }
    
    /// Get the draining index (entries below this have been evicted)
    pub fn draining_index(&self) -> u64 {
        self.draining_index
    }
    
    /// Check if an absolute index is still valid (not evicted)
    pub fn is_valid_absolute_index(&self, absolute_index: u64) -> bool {
        absolute_index > self.draining_index && absolute_index <= self.insert_count
    }
    
    /// Get the length of the dynamic table as u64
    pub fn len_u64(&self) -> u64 {
        self.entries.len() as u64
    }
    
    
    /// Get the current size of the dynamic table
    pub fn current_size(&self) -> u64 {
        self.size
    }
    
    /// Get the maximum capacity of the dynamic table
    pub fn max_capacity(&self) -> u64 {
        self.capacity
    }
}

impl Default for DynamicTable {
    fn default() -> Self {
        Self::new(4096) // Default 4KB capacity
    }
}

/// QPACK static table entries per RFC 9204 Appendix A
const STATIC_TABLE: &[(&str, &str)] = &[
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    ("strict-transport-security", "max-age=31536000; includesubdomains"),
    ("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn static_table_lookup() {
        // Test known entries
        let field = StaticTable::get(1).unwrap();
        assert_eq!(field.name.as_str(), ":authority");
        assert_eq!(field.value.as_str().unwrap(), "");
        
        let field = StaticTable::get(18).unwrap();
        assert_eq!(field.name.as_str(), ":method");
        assert_eq!(field.value.as_str().unwrap(), "GET");
        
        // Test invalid index
        assert!(StaticTable::get(0).is_none());
        assert!(StaticTable::get(1000).is_none());
    }
    
    #[test]
    fn static_table_find() {
        let field = HeaderField::new(
            HeaderName::new(":method").unwrap(),
            HeaderValue::new("GET").unwrap(),
        );
        
        let index = StaticTable::find_field(&field).unwrap();
        assert_eq!(index, 18);
        
        let name = HeaderName::new(":authority").unwrap();
        let index = StaticTable::find_name(&name).unwrap();
        assert_eq!(index, 1);
    }
    
    #[test]
    fn dynamic_table_insert() {
        let mut table = DynamicTable::new(1000);
        
        let field = HeaderField::new(
            HeaderName::new("custom-header").unwrap(),
            HeaderValue::new("custom-value").unwrap(),
        );
        
        let insert_count = table.insert(field.clone()).unwrap();
        assert_eq!(insert_count, 1);
        assert_eq!(table.len(), 1);
        
        let retrieved = table.get(0).unwrap();
        assert_eq!(retrieved.name, field.name);
        assert_eq!(retrieved.value, field.value);
    }
    
    #[test]
    fn dynamic_table_eviction() {
        let mut table = DynamicTable::new(100); // Small capacity
        
        // Insert a large field that almost fills the table
        let large_field = HeaderField::new(
            HeaderName::new("large-header").unwrap(),
            HeaderValue::new("a".repeat(50)).unwrap(),
        );
        
        table.insert(large_field).unwrap();
        assert_eq!(table.len(), 1);
        
        // Insert another field that should evict the first
        let small_field = HeaderField::new(
            HeaderName::new("small").unwrap(),
            HeaderValue::new("small").unwrap(),
        );
        
        table.insert(small_field).unwrap();
        assert_eq!(table.len(), 1); // First field evicted
        assert_eq!(table.draining_index(), 1);
    }
    
    #[test]
    fn dynamic_table_duplicate() {
        let mut table = DynamicTable::new(1000);
        
        let field = HeaderField::new(
            HeaderName::new("test").unwrap(),
            HeaderValue::new("value").unwrap(),
        );
        
        table.insert(field.clone()).unwrap();
        let insert_count = table.duplicate(0).unwrap();
        
        assert_eq!(insert_count, 2);
        assert_eq!(table.len(), 2);
        
        let first = table.get(0).unwrap();
        let second = table.get(1).unwrap();
        assert_eq!(first.name, second.name);
        assert_eq!(first.value, second.value);
    }
    
    #[test]
    fn dynamic_table_index_conversion() {
        let mut table = DynamicTable::new(1000);
        
        let field = HeaderField::new(
            HeaderName::new("test").unwrap(),
            HeaderValue::new("value").unwrap(),
        );
        
        table.insert(field).unwrap();
        
        // Test conversion between absolute and relative indices
        assert_eq!(table.absolute_to_relative(1), Some(0));
        assert_eq!(table.relative_to_absolute(0), Some(1));
        
        // Test invalid indices
        assert_eq!(table.absolute_to_relative(0), None);
        assert_eq!(table.absolute_to_relative(2), None);
        assert_eq!(table.relative_to_absolute(1), None);
    }
}