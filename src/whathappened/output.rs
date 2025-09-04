//! Output targets for events

use super::Event;
use std::io::{self, Write};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Trait for event output targets
pub trait Output: Send + Sync {
    /// Write an event to the output
    fn write(&self, event: &Event) -> io::Result<()>;
    
    /// Flush any buffered data
    fn flush(&self) -> io::Result<()> {
        Ok(())
    }
}

/// Console output that writes to stdout/stderr
pub struct ConsoleOutput {
    use_color: bool,
}

impl ConsoleOutput {
    /// Create a new console output
    #[must_use]
    pub fn new() -> Self {
        Self {
            // Simple TTY detection using std only
            use_color: Self::is_tty(),
        }
    }
    
    /// Create console output with explicit color setting
    #[must_use]
    pub fn with_color(use_color: bool) -> Self {
        Self { use_color }
    }
    
    /// Simple TTY detection using environment variables as a heuristic
    fn is_tty() -> bool {
        // Check for explicit color preferences first
        if let Ok(color) = std::env::var("NO_COLOR") {
            if !color.is_empty() {
                return false;
            }
        }
        
        if std::env::var("FORCE_COLOR").is_ok() {
            return true;
        }
        
        // Check if we're in a CI environment (usually no colors)
        if std::env::var("CI").is_ok() {
            return false;
        }
        
        // Check common environment variables that indicate terminal presence
        if let Ok(term) = std::env::var("TERM") {
            if !term.is_empty() && term != "dumb" {
                return true;
            }
        }
        
        // Default to no color for safety
        false
    }
}

impl Output for ConsoleOutput {
    fn write(&self, event: &Event) -> io::Result<()> {
        let formatted = event.format(self.use_color);
        
        // Write to stderr for errors, stdout for others
        if event.level <= super::Level::Error {
            writeln!(io::stderr(), "{}", formatted)?;
            io::stderr().flush()?;
        } else {
            writeln!(io::stdout(), "{}", formatted)?;
            io::stdout().flush()?;
        }
        
        Ok(())
    }
}

impl Default for ConsoleOutput {
    fn default() -> Self {
        Self::new()
    }
}

/// File output that writes to a file
pub struct FileOutput {
    file: Arc<Mutex<File>>,
    path: PathBuf,
}

impl FileOutput {
    /// Create a new file output
    pub fn new<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
            path,
        })
    }
    
    /// Get the file path
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Output for FileOutput {
    fn write(&self, event: &Event) -> io::Result<()> {
        let formatted = event.format(false); // No color in files
        let mut file = self.file.lock().unwrap();
        writeln!(file, "{}", formatted)?;
        file.flush()
    }
}

/// Buffered output that batches writes
pub struct BufferedOutput<O: Output> {
    inner: O,
    buffer: Arc<Mutex<Vec<Event>>>,
    buffer_size: usize,
}

impl<O: Output> BufferedOutput<O> {
    /// Create a new buffered output
    #[must_use]
    pub fn new(inner: O, buffer_size: usize) -> Self {
        Self {
            inner,
            buffer: Arc::new(Mutex::new(Vec::with_capacity(buffer_size))),
            buffer_size,
        }
    }
    
    /// Flush the buffer
    fn flush_buffer(&self) -> io::Result<()> {
        let mut buffer = self.buffer.lock().unwrap();
        
        for event in buffer.drain(..) {
            self.inner.write(&event)?;
        }
        
        self.inner.flush()
    }
}

impl<O: Output> Output for BufferedOutput<O> {
    fn write(&self, event: &Event) -> io::Result<()> {
        let mut buffer = self.buffer.lock().unwrap();
        buffer.push(event.clone());
        
        if buffer.len() >= self.buffer_size {
            // Release lock before flushing
            drop(buffer);
            self.flush_buffer()?;
        }
        
        Ok(())
    }
    
    fn flush(&self) -> io::Result<()> {
        self.flush_buffer()
    }
}

/// JSON output that writes events as JSON
pub struct JsonOutput<O: Output> {
    inner: O,
}

impl<O: Output> JsonOutput<O> {
    /// Create a new JSON output
    #[must_use]
    pub fn new(inner: O) -> Self {
        Self { inner }
    }
}

impl<O: Output> Output for JsonOutput<O> {
    fn write(&self, event: &Event) -> io::Result<()> {
        // Create a simple JSON representation
        let json = format!(
            r#"{{"id":{},"timestamp":{},"level":"{}","kind":"{:?}","thread_id":{},"thread_name":{:?},"file":"{}","line":{},"module":"{}","message":{:?},"context":{:?}}}"#,
            event.id,
            event.timestamp,
            event.level.as_str(),
            event.kind,
            event.thread_id,
            event.thread_name,
            event.file,
            event.line,
            event.module_path,
            event.message,
            event.context
        );
        
        // Create temporary event with JSON message
        let json_event = Event {
            message: json,
            ..event.clone()
        };
        
        self.inner.write(&json_event)
    }
    
    fn flush(&self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Multi-output that writes to multiple outputs
pub struct MultiOutput {
    outputs: Vec<Arc<dyn Output>>,
}

impl MultiOutput {
    /// Create a new multi-output
    #[must_use]
    pub fn new(outputs: Vec<Arc<dyn Output>>) -> Self {
        Self { outputs }
    }
}

impl Output for MultiOutput {
    fn write(&self, event: &Event) -> io::Result<()> {
        for output in &self.outputs {
            output.write(event)?;
        }
        Ok(())
    }
    
    fn flush(&self) -> io::Result<()> {
        for output in &self.outputs {
            output.flush()?;
        }
        Ok(())
    }
}