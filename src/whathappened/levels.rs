//! Event severity levels

use std::fmt;

/// Event severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum Level {
    /// Critical errors that require immediate attention
    Fatal = 0,
    /// Errors that prevent normal operation
    Error = 1,
    /// Warnings about potential issues
    Warn = 2,
    /// Informational messages
    Info = 3,
    /// Detailed debugging information
    Debug = 4,
    /// Very detailed trace information
    Trace = 5,
}

impl Level {
    /// Get the name of this level
    pub const fn as_str(&self) -> &'static str {
        match self {
            Level::Fatal => "FATAL",
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        }
    }
    
    /// Get a colored representation for terminal output
    pub fn colored(&self) -> String {
        match self {
            Level::Fatal => format!("\x1b[1;35m{}\x1b[0m", self.as_str()), // Bright magenta
            Level::Error => format!("\x1b[1;31m{}\x1b[0m", self.as_str()), // Bright red
            Level::Warn => format!("\x1b[1;33m{}\x1b[0m", self.as_str()),  // Bright yellow
            Level::Info => format!("\x1b[1;32m{}\x1b[0m", self.as_str()),  // Bright green
            Level::Debug => format!("\x1b[1;36m{}\x1b[0m", self.as_str()), // Bright cyan
            Level::Trace => format!("\x1b[1;37m{}\x1b[0m", self.as_str()), // Bright white
        }
    }
}

impl fmt::Display for Level {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Level filter for controlling which events are logged
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum LevelFilter {
    /// Disable all logging
    Off = 0,
    /// Log only fatal events
    Fatal = 1,
    /// Log errors and above
    Error = 2,
    /// Log warnings and above
    Warn = 3,
    /// Log info and above
    Info = 4,
    /// Log debug and above
    Debug = 5,
    /// Log everything
    Trace = 6,
}

impl LevelFilter {
    /// Check if a level is enabled by this filter
    pub fn enabled(&self, level: Level) -> bool {
        level as usize <= *self as usize
    }
}

impl From<Level> for LevelFilter {
    fn from(level: Level) -> Self {
        match level {
            Level::Fatal => LevelFilter::Fatal,
            Level::Error => LevelFilter::Error,
            Level::Warn => LevelFilter::Warn,
            Level::Info => LevelFilter::Info,
            Level::Debug => LevelFilter::Debug,
            Level::Trace => LevelFilter::Trace,
        }
    }
}

impl Default for LevelFilter {
    fn default() -> Self {
        LevelFilter::Info
    }
}