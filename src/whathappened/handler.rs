//! Event handlers for processing events

use super::Event;
use std::error::Error;
use std::fmt;

/// Error type for event handlers
#[derive(Debug)]
pub struct HandlerError {
    message: String,
}

impl fmt::Display for HandlerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Handler error: {}", self.message)
    }
}

impl Error for HandlerError {}

impl From<String> for HandlerError {
    fn from(message: String) -> Self {
        Self { message }
    }
}

impl From<&str> for HandlerError {
    fn from(message: &str) -> Self {
        Self { message: message.to_string() }
    }
}

/// Trait for event handlers
pub trait EventHandler: Send + Sync {
    /// Handle an event
    fn handle(&self, event: &Event) -> Result<(), HandlerError>;
    
    /// Get handler name
    fn name(&self) -> &str {
        "unnamed"
    }
}

/// Filter handler that only processes events matching criteria
pub struct FilterHandler<F, H>
where
    F: Fn(&Event) -> bool + Send + Sync,
    H: EventHandler,
{
    filter: F,
    handler: H,
}

impl<F, H> FilterHandler<F, H>
where
    F: Fn(&Event) -> bool + Send + Sync,
    H: EventHandler,
{
    /// Create a new filter handler
    pub fn new(filter: F, handler: H) -> Self {
        Self { filter, handler }
    }
}

impl<F, H> EventHandler for FilterHandler<F, H>
where
    F: Fn(&Event) -> bool + Send + Sync,
    H: EventHandler,
{
    fn handle(&self, event: &Event) -> Result<(), HandlerError> {
        if (self.filter)(event) {
            self.handler.handle(event)
        } else {
            Ok(())
        }
    }
    
    fn name(&self) -> &str {
        self.handler.name()
    }
}

/// Batch handler that collects events and processes them in batches
pub struct BatchHandler<H>
where
    H: EventHandler,
{
    handler: H,
    batch_size: usize,
    events: parking_lot::Mutex<Vec<Event>>,
}

impl<H> BatchHandler<H>
where
    H: EventHandler,
{
    /// Create a new batch handler
    pub fn new(handler: H, batch_size: usize) -> Self {
        Self {
            handler,
            batch_size,
            events: parking_lot::Mutex::new(Vec::with_capacity(batch_size)),
        }
    }
    
    /// Process batched events
    fn process_batch(&self, events: &[Event]) -> Result<(), HandlerError> {
        for event in events {
            self.handler.handle(event)?;
        }
        Ok(())
    }
}

impl<H> EventHandler for BatchHandler<H>
where
    H: EventHandler,
{
    fn handle(&self, event: &Event) -> Result<(), HandlerError> {
        let mut events = self.events.lock();
        events.push(event.clone());
        
        if events.len() >= self.batch_size {
            let batch: Vec<_> = events.drain(..).collect();
            drop(events); // Release lock before processing
            self.process_batch(&batch)?;
        }
        
        Ok(())
    }
    
    fn name(&self) -> &str {
        self.handler.name()
    }
}

/// Metrics handler that tracks event statistics
pub struct MetricsHandler {
    counters: parking_lot::RwLock<std::collections::HashMap<String, u64>>,
}

impl MetricsHandler {
    /// Create a new metrics handler
    pub fn new() -> Self {
        Self {
            counters: parking_lot::RwLock::new(std::collections::HashMap::new()),
        }
    }
    
    /// Get current metrics
    pub fn metrics(&self) -> std::collections::HashMap<String, u64> {
        self.counters.read().clone()
    }
}

impl EventHandler for MetricsHandler {
    fn handle(&self, event: &Event) -> Result<(), HandlerError> {
        let mut counters = self.counters.write();
        
        // Count by level
        let level_key = format!("level.{}", event.level.as_str().to_lowercase());
        *counters.entry(level_key).or_insert(0) += 1;
        
        // Count by kind
        let kind_key = match &event.kind {
            super::EventKind::Log => "kind.log",
            super::EventKind::Panic => "kind.panic",
            super::EventKind::Network => "kind.network",
            super::EventKind::Crypto => "kind.crypto",
            super::EventKind::Protocol => "kind.protocol",
            super::EventKind::Performance => "kind.performance",
            super::EventKind::Custom(s) => {
                counters.entry(format!("kind.custom.{}", s)).or_insert(0);
                "kind.custom"
            }
        };
        *counters.entry(kind_key.to_string()).or_insert(0) += 1;
        
        // Total events
        *counters.entry("total".to_string()).or_insert(0) += 1;
        
        Ok(())
    }
    
    fn name(&self) -> &str {
        "metrics"
    }
}

impl Default for MetricsHandler {
    fn default() -> Self {
        Self::new()
    }
}