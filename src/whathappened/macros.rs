//! Efficient macros for the WhatHappened logging system

/// Log a fatal error
#[macro_export]
macro_rules! fatal {
    ($($arg:tt)*) => {
        $crate::log_impl!(
            $crate::whathappened::Level::Fatal,
            $crate::whathappened::EventKind::Log,
            $($arg)*
        )
    };
}

/// Log an error
#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::log_impl!(
            $crate::whathappened::Level::Error,
            $crate::whathappened::EventKind::Log,
            $($arg)*
        )
    };
}

/// Log a warning
#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        $crate::log_impl!(
            $crate::whathappened::Level::Warn,
            $crate::whathappened::EventKind::Log,
            $($arg)*
        )
    };
}

/// Log an info message
#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        $crate::log_impl!(
            $crate::whathappened::Level::Info,
            $crate::whathappened::EventKind::Log,
            $($arg)*
        )
    };
}

/// Log a debug message
#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        $crate::log_impl!(
            $crate::whathappened::Level::Debug,
            $crate::whathappened::EventKind::Log,
            $($arg)*
        )
    };
}

/// Log a trace message
#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        $crate::log_impl!(
            $crate::whathappened::Level::Trace,
            $crate::whathappened::EventKind::Log,
            $($arg)*
        )
    };
}

/// Log with custom event kind
#[macro_export]
macro_rules! log_event {
    ($level:expr, $kind:expr, $($arg:tt)*) => {
        $crate::whathappened::macros::log_impl!($level, $kind, $($arg)*)
    };
}

/// Network event logging
#[macro_export]
macro_rules! net_event {
    // Format string with arguments
    ($level:expr, $fmt:expr, $($arg:expr),* $(,)?) => {
        $crate::log_impl!(
            $level,
            $crate::whathappened::EventKind::Network,
            $fmt,
            $($arg),*
        )
    };
    // Simple message without arguments
    ($level:expr, $msg:expr) => {
        $crate::log_impl!(
            $level,
            $crate::whathappened::EventKind::Network,
            $msg
        )
    };
    // With context
    ($level:expr, $msg:expr ; $($key:expr => $value:expr),* $(,)?) => {
        $crate::log_impl!(
            $level,
            $crate::whathappened::EventKind::Network,
            $msg, ; $($key => $value),*
        )
    };
}

/// Crypto event logging
#[macro_export]
macro_rules! crypto_event {
    // Format string with arguments
    ($level:expr, $fmt:expr, $($arg:expr),* $(,)?) => {
        $crate::log_impl!(
            $level,
            $crate::whathappened::EventKind::Crypto,
            $fmt,
            $($arg),*
        )
    };
    // Simple message without arguments
    ($level:expr, $msg:expr) => {
        $crate::log_impl!(
            $level,
            $crate::whathappened::EventKind::Crypto,
            $msg
        )
    };
    // With context
    ($level:expr, $msg:expr ; $($key:expr => $value:expr),* $(,)?) => {
        $crate::log_impl!(
            $level,
            $crate::whathappened::EventKind::Crypto,
            $msg, ; $($key => $value),*
        )
    };
}

/// Protocol event logging
#[macro_export]
macro_rules! protocol_event {
    // Format string with arguments
    ($level:expr, $fmt:expr, $($arg:expr),* $(,)?) => {
        $crate::log_impl!(
            $level,
            $crate::whathappened::EventKind::Protocol,
            $fmt,
            $($arg),*
        )
    };
    // Simple message without arguments
    ($level:expr, $msg:expr) => {
        $crate::log_impl!(
            $level,
            $crate::whathappened::EventKind::Protocol,
            $msg
        )
    };
    // With context
    ($level:expr, $msg:expr ; $($key:expr => $value:expr),* $(,)?) => {
        $crate::log_impl!(
            $level,
            $crate::whathappened::EventKind::Protocol,
            $msg, ; $($key => $value),*
        )
    };
}

/// Performance event logging
#[macro_export]
macro_rules! perf_event {
    // Format string with arguments
    ($level:expr, $fmt:expr, $($arg:expr),* $(,)?) => {
        $crate::log_impl!(
            $level,
            $crate::whathappened::EventKind::Performance,
            $fmt,
            $($arg),*
        )
    };
    // Simple message without arguments
    ($level:expr, $msg:expr) => {
        $crate::log_impl!(
            $level,
            $crate::whathappened::EventKind::Performance,
            $msg
        )
    };
    // With context
    ($level:expr, $msg:expr ; $($key:expr => $value:expr),* $(,)?) => {
        $crate::log_impl!(
            $level,
            $crate::whathappened::EventKind::Performance,
            $msg, ; $($key => $value),*
        )
    };
}

/// Internal implementation macro
#[doc(hidden)]
#[macro_export]
macro_rules! log_impl {
    ($level:expr, $kind:expr, $fmt:expr $(, $arg:expr)* $(,)?) => {{
        // Only evaluate arguments if the level is enabled
        if $crate::whathappened::LevelFilter::from($level).enabled($level) {
            $crate::whathappened::Event::builder()
                .level($level)
                .kind($kind)
                .location(file!(), line!(), module_path!())
                .message(format!($fmt $(, $arg)*))
                .log();
        }
    }};
    
    // With context
    ($level:expr, $kind:expr, $fmt:expr, $($arg:expr),* ; $($key:expr => $value:expr),* $(,)?) => {{
        if $crate::whathappened::LevelFilter::from($level).enabled($level) {
            let mut builder = $crate::whathappened::Event::builder()
                .level($level)
                .kind($kind)
                .location(file!(), line!(), module_path!())
                .message(format!($fmt $(, $arg)*));
            
            $(
                builder = builder.context($key, format!("{:?}", $value));
            )*
            
            builder.log();
        }
    }};
}

/// Log execution time of a block
#[macro_export]
macro_rules! time_block {
    ($name:expr, $block:block) => {{
        let _start = std::time::Instant::now();
        let _name = $name;
        
        let result = $block;
        
        let elapsed = _start.elapsed();
        $crate::perf_event!(
            $crate::whathappened::Level::Debug,
            "Block '{}' took {:?}",
            _name,
            elapsed
        );
        
        result
    }};
}

/// Log and return an error
#[macro_export]
macro_rules! log_error {
    ($result:expr) => {
        match $result {
            Ok(val) => Ok(val),
            Err(err) => {
                $crate::error!("Error: {}", err);
                Err(err)
            }
        }
    };
    
    ($result:expr, $fmt:expr $(, $arg:expr)*) => {
        match $result {
            Ok(val) => Ok(val),
            Err(err) => {
                $crate::error!($fmt $(, $arg)*, "; error={}", err);
                Err(err)
            }
        }
    };
}

/// Assert with logging
#[macro_export]
macro_rules! assert_log {
    ($cond:expr) => {
        if !$cond {
            $crate::fatal!("Assertion failed: {}", stringify!($cond));
            panic!("Assertion failed: {}", stringify!($cond));
        }
    };
    
    ($cond:expr, $fmt:expr $(, $arg:expr)*) => {
        if !$cond {
            $crate::fatal!("Assertion failed: {} - {}", stringify!($cond), format!($fmt $(, $arg)*));
            panic!("Assertion failed: {} - {}", stringify!($cond), format!($fmt $(, $arg)*));
        }
    };
}

/// Debug assert with logging
#[macro_export]
macro_rules! debug_assert_log {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        $crate::assert_log!($($arg)*);
    };
}

// Re-export for macro use
pub use crate::{
    fatal, error, warn, info, debug, trace,
    log_event, net_event, crypto_event, protocol_event, perf_event,
    time_block, log_error, assert_log, debug_assert_log
};