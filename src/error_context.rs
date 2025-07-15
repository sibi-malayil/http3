//! Enhanced error handling with proper error codes and context
//!
//! This module provides utilities for better error handling throughout the codebase,
//! including error context, conversion helpers, and debugging information.

use crate::error::{Error, Result, ConnectionErrorCode, StreamErrorCode, Http3ErrorCode, QpackErrorCode};
use std::fmt;

/// Error context that provides additional debugging information
#[derive(Debug)]
pub struct ErrorContext {
    /// The underlying error
    pub error: Error,
    /// Location where the error occurred (file:line)
    pub location: &'static str,
    /// Additional context about what was happening
    pub context: String,
    /// Stack of operations that led to this error
    pub operation_stack: Vec<String>,
}

impl ErrorContext {
    /// Create a new error context
    pub fn new(error: Error, location: &'static str, context: impl Into<String>) -> Self {
        Self {
            error,
            location,
            context: context.into(),
            operation_stack: Vec::new(),
        }
    }

    /// Add an operation to the stack
    pub fn with_operation(mut self, operation: impl Into<String>) -> Self {
        self.operation_stack.push(operation.into());
        self
    }

    /// Convert to the underlying error
    pub fn into_error(self) -> Error {
        self.error
    }
}

impl fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}", self.error, self.location)?;
        if !self.context.is_empty() {
            write!(f, ": {}", self.context)?;
        }
        if !self.operation_stack.is_empty() {
            write!(f, "\nOperation stack:")?;
            for (i, op) in self.operation_stack.iter().enumerate() {
                write!(f, "\n  {}: {}", i + 1, op)?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for ErrorContext {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Macro for creating error contexts with location information
#[macro_export]
macro_rules! error_context {
    ($error:expr, $context:expr) => {
        $crate::error_context::ErrorContext::new(
            $error,
            concat!(file!(), ":", line!()),
            $context
        )
    };
    ($error:expr, $context:expr, $($op:expr),+) => {{
        let mut ctx = $crate::error_context::ErrorContext::new(
            $error,
            concat!(file!(), ":", line!()),
            $context
        );
        $(
            ctx = ctx.with_operation($op);
        )+
        ctx
    }};
}

/// Error conversion helpers
pub trait ErrorConversion {
    /// Convert to a connection error with appropriate code
    fn to_connection_error(&self, code: ConnectionErrorCode) -> Error;
    
    /// Convert to a stream error with appropriate code
    fn to_stream_error(&self, code: StreamErrorCode) -> Error;
    
    /// Convert to an HTTP/3 error with appropriate code
    fn to_http3_error(&self, code: Http3ErrorCode) -> Error;
    
    /// Convert to a QPACK error with appropriate code
    fn to_qpack_error(&self, code: QpackErrorCode) -> Error;
}

impl ErrorConversion for String {
    fn to_connection_error(&self, code: ConnectionErrorCode) -> Error {
        Error::ConnectionClosed {
            code,
            reason: self.clone(),
        }
    }
    
    fn to_stream_error(&self, code: StreamErrorCode) -> Error {
        Error::StreamError {
            code,
            reason: self.clone(),
        }
    }
    
    fn to_http3_error(&self, code: Http3ErrorCode) -> Error {
        Error::Http3Error {
            code,
            reason: self.clone(),
        }
    }
    
    fn to_qpack_error(&self, code: QpackErrorCode) -> Error {
        Error::QpackError {
            code,
            reason: self.clone(),
        }
    }
}

impl ErrorConversion for &str {
    fn to_connection_error(&self, code: ConnectionErrorCode) -> Error {
        self.to_string().to_connection_error(code)
    }
    
    fn to_stream_error(&self, code: StreamErrorCode) -> Error {
        self.to_string().to_stream_error(code)
    }
    
    fn to_http3_error(&self, code: Http3ErrorCode) -> Error {
        self.to_string().to_http3_error(code)
    }
    
    fn to_qpack_error(&self, code: QpackErrorCode) -> Error {
        self.to_string().to_qpack_error(code)
    }
}

/// Helper trait for Result type to add context
pub trait ResultContext<T> {
    /// Add context to an error
    fn context(self, context: impl Into<String>) -> Result<T>;
    
    /// Add context with location
    fn with_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> String;
}

impl<T> ResultContext<T> for Result<T> {
    fn context(self, context: impl Into<String>) -> Result<T> {
        self.map_err(|e| {
            error_context!(e, context.into()).into_error()
        })
    }
    
    fn with_context<F>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> String,
    {
        self.map_err(|e| {
            error_context!(e, f()).into_error()
        })
    }
}

/// Common error scenarios with proper error codes
pub mod common_errors {
    use super::*;
    
    /// Create a flow control error
    pub fn flow_control_error(reason: impl Into<String>) -> Error {
        reason.into().to_connection_error(ConnectionErrorCode::FlowControlError)
    }
    
    /// Create a stream limit error
    pub fn stream_limit_error(reason: impl Into<String>) -> Error {
        reason.into().to_connection_error(ConnectionErrorCode::StreamLimitError)
    }
    
    /// Create a protocol violation error
    pub fn protocol_violation(reason: impl Into<String>) -> Error {
        reason.into().to_connection_error(ConnectionErrorCode::ProtocolViolation)
    }
    
    /// Create a frame encoding error
    pub fn frame_encoding_error(reason: impl Into<String>) -> Error {
        reason.into().to_connection_error(ConnectionErrorCode::FrameEncodingError)
    }
    
    /// Create an HTTP/3 frame error
    pub fn http3_frame_error(reason: impl Into<String>) -> Error {
        reason.into().to_http3_error(Http3ErrorCode::FrameError)
    }
    
    /// Create an HTTP/3 settings error
    pub fn http3_settings_error(reason: impl Into<String>) -> Error {
        reason.into().to_http3_error(Http3ErrorCode::SettingsError)
    }
    
    /// Create a QPACK compression error
    pub fn qpack_compression_error(reason: impl Into<String>) -> Error {
        reason.into().to_qpack_error(QpackErrorCode::EncoderStreamError)
    }
    
    /// Create a QPACK decompression error
    pub fn qpack_decompression_error(reason: impl Into<String>) -> Error {
        reason.into().to_qpack_error(QpackErrorCode::DecompressionFailed)
    }
}

/// Error recovery strategies
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryStrategy {
    /// Close the connection immediately
    CloseConnection,
    /// Close the affected stream only
    CloseStream,
    /// Retry the operation
    Retry { max_attempts: u32 },
    /// Continue with degraded functionality
    Degrade,
    /// Ignore the error and continue
    Ignore,
}

/// Determine recovery strategy based on error type
pub fn suggest_recovery_strategy(error: &Error) -> RecoveryStrategy {
    match error {
        Error::ConnectionClosed { code, .. } => match code {
            ConnectionErrorCode::NoError => RecoveryStrategy::Ignore,
            ConnectionErrorCode::InternalError |
            ConnectionErrorCode::ProtocolViolation |
            ConnectionErrorCode::CryptoBufferExceeded |
            ConnectionErrorCode::AeadLimitReached => RecoveryStrategy::CloseConnection,
            ConnectionErrorCode::FlowControlError |
            ConnectionErrorCode::StreamLimitError |
            ConnectionErrorCode::StreamStateError => RecoveryStrategy::CloseStream,
            _ => RecoveryStrategy::CloseConnection,
        },
        
        Error::StreamError { code, .. } => match code {
            StreamErrorCode::NoError => RecoveryStrategy::Ignore,
            StreamErrorCode::InternalError => RecoveryStrategy::CloseConnection,
            StreamErrorCode::FlowControlError |
            StreamErrorCode::FinalSizeError |
            StreamErrorCode::StreamLimitError => RecoveryStrategy::CloseStream,
            _ => RecoveryStrategy::CloseStream,
        },
        
        Error::Http3Error { code, .. } => match code {
            Http3ErrorCode::NoError => RecoveryStrategy::Ignore,
            Http3ErrorCode::InternalError |
            Http3ErrorCode::ClosedCriticalStream => RecoveryStrategy::CloseConnection,
            Http3ErrorCode::FrameError |
            Http3ErrorCode::SettingsError => RecoveryStrategy::CloseStream,
            _ => RecoveryStrategy::Degrade,
        },
        
        Error::QpackError { .. } => RecoveryStrategy::Degrade,
        
        Error::Timeout => RecoveryStrategy::Retry { max_attempts: 3 },
        
        Error::Reset | Error::NotConnected => RecoveryStrategy::CloseConnection,
        
        _ => RecoveryStrategy::CloseConnection,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_error_context() {
        let error = Error::Internal("test error".to_string());
        let context = ErrorContext::new(error, "test.rs:42", "during test operation")
            .with_operation("step 1")
            .with_operation("step 2");
        
        let display = format!("{}", context);
        assert!(display.contains("test error"));
        assert!(display.contains("test.rs:42"));
        assert!(display.contains("during test operation"));
        assert!(display.contains("step 1"));
        assert!(display.contains("step 2"));
    }
    
    #[test]
    fn test_error_conversion() {
        let msg = "test error";
        
        let conn_error = msg.to_connection_error(ConnectionErrorCode::FlowControlError);
        match conn_error {
            Error::ConnectionClosed { code, reason } => {
                assert_eq!(code, ConnectionErrorCode::FlowControlError);
                assert_eq!(reason, "test error");
            }
            _ => panic!("Wrong error type"),
        }
    }
    
    #[test]
    fn test_recovery_strategy() {
        let error = Error::ConnectionClosed {
            code: ConnectionErrorCode::ProtocolViolation,
            reason: "test".to_string(),
        };
        assert_eq!(suggest_recovery_strategy(&error), RecoveryStrategy::CloseConnection);
        
        let error = Error::StreamError {
            code: StreamErrorCode::FlowControlError,
            reason: "test".to_string(),
        };
        assert_eq!(suggest_recovery_strategy(&error), RecoveryStrategy::CloseStream);
        
        let error = Error::Timeout;
        assert_eq!(suggest_recovery_strategy(&error), RecoveryStrategy::Retry { max_attempts: 3 });
    }
}