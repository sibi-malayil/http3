//! WhatHappened: A high-performance event logging system for Rust 2024
//!
//! This module provides an efficient, zero-cost abstraction for logging events
//! with built-in panic handling and structured event tracking.
//! 
//! Uses only std library components for maximum security and minimal dependencies.

use std::sync::{Arc, LazyLock, RwLock};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, SyncSender, Receiver, TrySendError};
use std::panic::{self, PanicHookInfo};
use std::thread;

pub mod macros;
pub mod levels;
pub mod handler;
pub mod event;
pub mod output;
pub mod span;
pub mod error;

#[cfg(feature = "async-tokio")]
pub mod async_support;

pub use levels::{Level, LevelFilter};
pub use event::{Event, EventBuilder, EventKind};
pub use handler::{EventHandler, MetricsHandler, FilterHandler};
pub use output::{Output, ConsoleOutput, FileOutput, BufferedOutput};
pub use span::{Span, SpanHandle, SpanBuilder};
pub use error::{Error, Result, Context};

#[cfg(feature = "async-tokio")]
pub use async_support::{AsyncWhatHappened, AsyncSpan, InstrumentExt};

/// Global event system instance
static WHATHAPPENED: LazyLock<Arc<WhatHappened>> = LazyLock::new(|| {
    Arc::new(WhatHappened::new())
});

thread_local! {
    /// Thread-local event counter for efficient event generation
    static EVENT_COUNTER: AtomicU64 = const { AtomicU64::new(0) };
}

/// Main event system struct
pub struct WhatHappened {
    /// Event handlers
    handlers: Arc<RwLock<Vec<Arc<dyn EventHandler>>>>,
    /// Event output targets
    outputs: Arc<RwLock<Vec<Arc<dyn Output>>>>,
    /// Global event counter
    global_counter: AtomicU64,
    /// Event channel for async processing
    event_tx: SyncSender<Event>,
    /// Panic hook installed flag
    panic_hook_installed: AtomicUsize,
    /// Current log level filter
    level_filter: AtomicUsize,
}

impl WhatHappened {
    /// Create a new WhatHappened instance
    fn new() -> Self {
        let (tx, rx) = mpsc::sync_channel(10_000); // Bounded channel for backpressure
        
        let handlers = Arc::new(RwLock::new(Vec::new()));
        let outputs = Arc::new(RwLock::new(vec![
            Arc::new(ConsoleOutput::new()) as Arc<dyn Output>
        ]));
        
        let instance = Self {
            handlers: handlers.clone(),
            outputs: outputs.clone(),
            global_counter: AtomicU64::new(0),
            event_tx: tx,
            panic_hook_installed: AtomicUsize::new(0),
            level_filter: AtomicUsize::new(Level::Info as usize),
        };
        
        // Start event processing thread
        Self::start_event_processor(rx, handlers, outputs);
        
        instance
    }
    
    /// Start the background event processor
    fn start_event_processor(
        rx: Receiver<Event>,
        handlers: Arc<RwLock<Vec<Arc<dyn EventHandler>>>>,
        outputs: Arc<RwLock<Vec<Arc<dyn Output>>>>
    ) {
        thread::Builder::new()
            .name("whathappened-processor".to_string())
            .spawn(move || {
                while let Ok(event) = rx.recv() {
                    // Process through handlers
                    if let Ok(handlers_guard) = handlers.read() {
                        for handler in handlers_guard.iter() {
                            if let Err(e) = handler.handle(&event) {
                                eprintln!("Handler error: {}", e);
                            }
                        }
                    }
                    
                    // Output event
                    if let Ok(outputs_guard) = outputs.read() {
                        for output in outputs_guard.iter() {
                            if let Err(e) = output.write(&event) {
                                eprintln!("Output error: {}", e);
                            }
                        }
                    }
                }
            })
            .expect("Failed to start event processor thread");
    }
    
    /// Install custom panic handler
    pub fn install_panic_handler(&self) {
        if self.panic_hook_installed.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
            let tx = self.event_tx.clone();
            
            panic::set_hook(Box::new(move |info: &PanicHookInfo<'_>| {
                let location = info.location()
                    .map(|loc| format!("{}:{}:{}", loc.file(), loc.line(), loc.column()))
                    .unwrap_or_else(|| "unknown location".to_string());
                
                let message = if let Some(s) = info.payload().downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = info.payload().downcast_ref::<String>() {
                    s.clone()
                } else {
                    "Box<Any>".to_string()
                };
                
                let event = Event::panic(message, location);
                
                // Try to send panic event, but don't panic if channel is full
                let _ = tx.try_send(event);
                
                // Also print to stderr immediately
                eprintln!("\n!!! PANIC !!!");
                eprintln!("Thread: {:?}", thread::current().name().unwrap_or("unnamed"));
                eprintln!("{}", info);
            }));
        }
    }
    
    /// Log an event
    pub fn log(&self, event: Event) {
        // Check level filter
        if event.level as usize > self.level_filter.load(Ordering::Relaxed) {
            return;
        }
        
        // Try to send event, fall back to direct output if channel is full
        match self.event_tx.try_send(event.clone()) {
            Ok(_) => {},
            Err(TrySendError::Full(_)) => {
                // Channel full, output directly to avoid blocking
                if let Ok(outputs) = self.outputs.read() {
                    if let Some(output) = outputs.first() {
                        let _ = output.write(&event);
                    }
                }
            },
            Err(TrySendError::Disconnected(_)) => {
                // Receiver dropped, ignore
            }
        }
    }
    
    /// Set the global level filter
    pub fn set_level_filter(&self, filter: LevelFilter) {
        self.level_filter.store(filter as usize, Ordering::Relaxed);
    }
    
    /// Add an event handler
    pub fn add_handler(&self, handler: Arc<dyn EventHandler>) {
        if let Ok(mut handlers) = self.handlers.write() {
            handlers.push(handler);
        }
    }
    
    /// Add an output target
    pub fn add_output(&self, output: Arc<dyn Output>) {
        if let Ok(mut outputs) = self.outputs.write() {
            outputs.push(output);
        }
    }
    
    /// Clear all outputs (useful for testing)
    pub fn clear_outputs(&self) {
        if let Ok(mut outputs) = self.outputs.write() {
            outputs.clear();
        }
    }
    
    /// Generate next event ID
    pub fn next_event_id(&self) -> u64 {
        self.global_counter.fetch_add(1, Ordering::Relaxed)
    }
}

/// Initialize the event system
pub fn init() {
    // Force lazy initialization
    let _ = &**WHATHAPPENED;
}

/// Initialize with panic handler
pub fn init_with_panic_handler() {
    init();
    WHATHAPPENED.install_panic_handler();
}

/// Set the global log level filter
pub fn set_level_filter(filter: LevelFilter) {
    WHATHAPPENED.set_level_filter(filter);
}

/// Add a custom event handler
pub fn add_handler(handler: Arc<dyn EventHandler>) {
    WHATHAPPENED.add_handler(handler);
}

/// Add a custom output
pub fn add_output(output: Arc<dyn Output>) {
    WHATHAPPENED.add_output(output);
}

/// Log an event (internal use)
#[doc(hidden)]
pub fn log_event(event: Event) {
    WHATHAPPENED.log(event);
}

/// Get next event ID (internal use)
#[doc(hidden)]
pub fn next_event_id() -> u64 {
    WHATHAPPENED.next_event_id()
}

/// Clear all outputs (mainly for testing)
pub fn clear_outputs() {
    WHATHAPPENED.clear_outputs();
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_initialization() {
        init();
        assert!(true); // Just ensure it doesn't panic
    }
    
    #[test]
    fn test_level_filter() {
        init();
        set_level_filter(LevelFilter::Debug);
        // Would need to capture output to verify filtering works
    }
}