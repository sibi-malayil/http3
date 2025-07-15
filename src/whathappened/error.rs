//! Error handling with context chaining (like anyhow)

use std::error::Error as StdError;
use std::fmt;
use std::backtrace::Backtrace;
use super::{EventBuilder, Level, EventKind};

/// Error with context chain
#[derive(Debug)]
pub struct Error {
    /// The error message
    message: String,
    /// The underlying error
    source: Option<Box<dyn StdError + Send + Sync + 'static>>,
    /// Context messages
    context: Vec<String>,
    /// Backtrace captured at error creation
    backtrace: Backtrace,
}

impl Error {
    /// Create a new error
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
            context: Vec::new(),
            backtrace: Backtrace::capture(),
        }
    }
    
    /// Create from another error
    pub fn from_err<E: StdError + Send + Sync + 'static>(err: E) -> Self {
        Self {
            message: err.to_string(),
            source: Some(Box::new(err)),
            context: Vec::new(),
            backtrace: Backtrace::capture(),
        }
    }
    
    /// Add context to the error
    pub fn context(mut self, msg: impl Into<String>) -> Self {
        self.context.push(msg.into());
        self
    }
    
    /// Log this error
    pub fn log(&self, level: Level) {
        let mut event = EventBuilder::new()
            .level(level)
            .kind(EventKind::Custom("error".to_string()))
            .location(file!(), line!(), module_path!())
            .message(&self.message);
        
        // Add context chain
        for (i, ctx) in self.context.iter().enumerate() {
            event = event.context(format!("context_{}", i), ctx);
        }
        
        // Add source chain
        if let Some(source) = &self.source {
            event = event.context("source", source.to_string());
            
            // Walk the error chain
            let mut current = source.source();
            let mut depth = 1;
            while let Some(err) = current {
                event = event.context(format!("source_{}", depth), err.to_string());
                current = err.source();
                depth += 1;
            }
        }
        
        event.log();
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)?;
        
        for ctx in &self.context {
            write!(f, ": {}", ctx)?;
        }
        
        if let Some(source) = &self.source {
            write!(f, "\n\nCaused by:")?;
            let mut current = Some(source.as_ref() as &dyn StdError);
            let mut depth = 0;
            
            while let Some(err) = current {
                write!(f, "\n    {}: {}", depth, err)?;
                current = err.source();
                depth += 1;
            }
        }
        
        Ok(())
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as &(dyn StdError + 'static))
    }
}

/// Result type alias
pub type Result<T> = std::result::Result<T, Error>;

/// Extension trait for adding context to Results
pub trait Context<T> {
    /// Add context to an error
    fn context(self, msg: impl Into<String>) -> Result<T>;
    
    /// Add context with a closure (lazy evaluation)
    fn with_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> String;
}

impl<T, E> Context<T> for std::result::Result<T, E>
where
    E: StdError + Send + Sync + 'static,
{
    fn context(self, msg: impl Into<String>) -> Result<T> {
        self.map_err(|e| Error::from_err(e).context(msg))
    }
    
    fn with_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> String,
    {
        self.map_err(|e| Error::from_err(e).context(f()))
    }
}

impl<T> Context<T> for Option<T> {
    fn context(self, msg: impl Into<String>) -> Result<T> {
        self.ok_or_else(|| Error::new(msg))
    }
    
    fn with_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> String,
    {
        self.ok_or_else(|| Error::new(f()))
    }
}

/// Macro for creating errors with formatting
#[macro_export]
macro_rules! whathappened_error {
    ($msg:literal) => {
        $crate::whathappened::error::Error::new($msg)
    };
    ($fmt:literal, $($arg:tt)*) => {
        $crate::whathappened::error::Error::new(format!($fmt, $($arg)*))
    };
}

/// Macro for bailing out with an error
#[macro_export]
macro_rules! whathappened_bail {
    ($msg:literal) => {
        return Err($crate::whathappened_error!($msg))
    };
    ($fmt:literal, $($arg:tt)*) => {
        return Err($crate::whathappened_error!($fmt, $($arg)*))
    };
}

/// Macro for ensuring a condition
#[macro_export]
macro_rules! whathappened_ensure {
    ($cond:expr, $msg:literal) => {
        if !$cond {
            $crate::whathappened_bail!($msg);
        }
    };
    ($cond:expr, $fmt:literal, $($arg:tt)*) => {
        if !$cond {
            $crate::whathappened_bail!($fmt, $($arg)*);
        }
    };
}