//! Event structure and builder

use super::Level;
use std::time::{SystemTime, UNIX_EPOCH};
use std::thread;
use std::sync::Arc;
use std::backtrace::{Backtrace, BacktraceStatus};

/// Event kinds for categorization
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    /// Normal log event
    Log,
    /// Panic event
    Panic,
    /// Network event
    Network,
    /// Crypto event
    Crypto,
    /// Protocol event
    Protocol,
    /// Performance event
    Performance,
    /// Custom event kind
    Custom(String),
}

/// Structured event data
#[derive(Debug, Clone)]
pub struct Event {
    /// Unique event ID
    pub id: u64,
    /// Event timestamp (microseconds since UNIX epoch)
    pub timestamp: u64,
    /// Event severity level
    pub level: Level,
    /// Event kind/category
    pub kind: EventKind,
    /// Thread ID where event occurred
    pub thread_id: u64,
    /// Thread name if available
    pub thread_name: Option<String>,
    /// Source file
    pub file: &'static str,
    /// Source line
    pub line: u32,
    /// Module path
    pub module_path: &'static str,
    /// Event message
    pub message: String,
    /// Additional context (key-value pairs)
    pub context: Vec<(String, String)>,
    /// Optional backtrace
    pub backtrace: Option<Arc<Backtrace>>,
}

impl Event {
    /// Create a new event builder
    pub fn builder() -> EventBuilder {
        EventBuilder::new()
    }
    
    /// Create a panic event
    pub fn panic(message: String, location: String) -> Self {
        let thread = thread::current();
        let thread_id = format!("{:?}", thread.id()).trim_matches(|c| !char::is_numeric(c)).parse::<u64>().unwrap_or(0);
        let thread_name = thread.name().map(|s| s.to_string());
        
        Self {
            id: super::next_event_id(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_micros() as u64)
                .unwrap_or(0),
            level: Level::Fatal,
            kind: EventKind::Panic,
            thread_id,
            thread_name,
            file: "",
            line: 0,
            module_path: "",
            message,
            context: vec![("location".to_string(), location)],
            backtrace: Some(Arc::new(Backtrace::capture())),
        }
    }
    
    /// Format for display with optional color
    pub fn format(&self, colored: bool) -> String {
        let level_str = if colored {
            self.level.colored()
        } else {
            self.level.to_string()
        };
        
        let timestamp = self.timestamp / 1_000_000; // Convert to seconds
        let micros = self.timestamp % 1_000_000;
        
        let mut output = format!(
            "[{:>5}.{:06}] {} [{}] {}:{}",
            timestamp, micros,
            level_str,
            self.thread_name.as_deref().unwrap_or("unknown"),
            self.file,
            self.line
        );
        
        if !self.module_path.is_empty() {
            output.push_str(&format!(" {}", self.module_path));
        }
        
        output.push_str(&format!(" - {}", self.message));
        
        // Add context if present
        if !self.context.is_empty() {
            output.push_str(" {");
            for (i, (key, value)) in self.context.iter().enumerate() {
                if i > 0 {
                    output.push_str(", ");
                }
                output.push_str(&format!("{}: {}", key, value));
            }
            output.push('}');
        }
        
        output
    }
}

/// Event builder for constructing events
pub struct EventBuilder {
    level: Level,
    kind: EventKind,
    file: &'static str,
    line: u32,
    module_path: &'static str,
    message: String,
    context: Vec<(String, String)>,
    backtrace: bool,
}

impl EventBuilder {
    /// Create a new event builder
    pub fn new() -> Self {
        Self {
            level: Level::Info,
            kind: EventKind::Log,
            file: "",
            line: 0,
            module_path: "",
            message: String::new(),
            context: Vec::new(),
            backtrace: false,
        }
    }
    
    /// Set the event level
    pub fn level(mut self, level: Level) -> Self {
        self.level = level;
        self
    }
    
    /// Set the event kind
    pub fn kind(mut self, kind: EventKind) -> Self {
        self.kind = kind;
        self
    }
    
    /// Set source location
    pub fn location(mut self, file: &'static str, line: u32, module_path: &'static str) -> Self {
        self.file = file;
        self.line = line;
        self.module_path = module_path;
        self
    }
    
    /// Set the message
    pub fn message<S: Into<String>>(mut self, message: S) -> Self {
        self.message = message.into();
        self
    }
    
    /// Add context key-value pair
    pub fn context<K: Into<String>, V: Into<String>>(mut self, key: K, value: V) -> Self {
        self.context.push((key.into(), value.into()));
        self
    }
    
    /// Enable backtrace capture
    pub fn with_backtrace(mut self) -> Self {
        self.backtrace = true;
        self
    }
    
    /// Build the event
    pub fn build(self) -> Event {
        let thread = thread::current();
        let thread_id = format!("{:?}", thread.id()).trim_matches(|c| !char::is_numeric(c)).parse::<u64>().unwrap_or(0);
        let thread_name = thread.name().map(|s| s.to_string());
        
        let backtrace = if self.backtrace {
            let bt = Backtrace::capture();
            if bt.status() == BacktraceStatus::Captured {
                Some(Arc::new(bt))
            } else {
                None
            }
        } else {
            None
        };
        
        Event {
            id: super::next_event_id(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_micros() as u64)
                .unwrap_or(0),
            level: self.level,
            kind: self.kind,
            thread_id,
            thread_name,
            file: self.file,
            line: self.line,
            module_path: self.module_path,
            message: self.message,
            context: self.context,
            backtrace,
        }
    }
    
    /// Build and log the event
    pub fn log(self) {
        super::log_event(self.build());
    }
}

impl Default for EventBuilder {
    fn default() -> Self {
        Self::new()
    }
}