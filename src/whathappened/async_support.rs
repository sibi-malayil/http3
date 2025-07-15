//! Async support for tokio and other runtimes

use super::{Event, EventBuilder};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::pin::Pin;
use std::future::Future;
use std::marker::Unpin;
use tokio::sync::mpsc::{self, UnboundedSender, UnboundedReceiver};

/// Async-friendly event system wrapper
pub struct AsyncWhatHappened {
    tx: UnboundedSender<Event>,
    _handle: tokio::task::JoinHandle<()>,
}

impl AsyncWhatHappened {
    /// Create a new async event processor
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        
        let handle = tokio::spawn(async move {
            Self::process_events(rx).await;
        });
        
        Self {
            tx,
            _handle: handle,
        }
    }
    
    /// Process events asynchronously
    async fn process_events(mut rx: UnboundedReceiver<Event>) {
        while let Some(event) = rx.recv().await {
            // Process through the global sync system
            super::log_event(event);
        }
    }
    
    /// Log an event asynchronously
    pub fn log(&self, event: Event) {
        let _ = self.tx.send(event);
    }
    
    /// Create an async span
    pub fn span(&self, name: impl Into<String>) -> AsyncSpan {
        AsyncSpan::new(name.into(), self.tx.clone())
    }
}

/// Async-aware span
pub struct AsyncSpan {
    name: String,
    tx: UnboundedSender<Event>,
    start: std::time::Instant,
}

impl AsyncSpan {
    fn new(name: String, tx: UnboundedSender<Event>) -> Self {
        // Log span entry
        let _ = tx.send(
            EventBuilder::new()
                .kind(super::EventKind::Custom("async_span.enter".to_string()))
                .message(format!("→ {}", name))
                .build()
        );
        
        Self {
            name,
            tx,
            start: std::time::Instant::now(),
        }
    }
    
    /// Instrument a future
    pub fn instrument<F>(self, future: F) -> Instrumented<F> {
        Instrumented {
            future,
            span: Arc::new(self),
        }
    }
}

impl Drop for AsyncSpan {
    fn drop(&mut self) {
        let duration = self.start.elapsed();
        
        // Log span exit
        let _ = self.tx.send(
            EventBuilder::new()
                .kind(super::EventKind::Custom("async_span.exit".to_string()))
                .message(format!("← {} ({:?})", self.name, duration))
                .context("duration_us", duration.as_micros().to_string())
                .build()
        );
    }
}

/// Future instrumented with a span
pub struct Instrumented<F> {
    future: F,
    span: Arc<AsyncSpan>,
}

impl<F: Future + Unpin> Future for Instrumented<F> {
    type Output = F::Output;
    
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let _span = &self.span; // Keep span alive
        Pin::new(&mut self.future).poll(cx)
    }
}

/// Extension trait for futures
pub trait InstrumentExt: Sized {
    /// Instrument this future with a span
    fn instrument(self, span: AsyncSpan) -> Instrumented<Self> {
        Instrumented {
            future: self,
            span: Arc::new(span),
        }
    }
}

impl<F: Future + Unpin> InstrumentExt for F {}

/// Async-aware logging macros
#[macro_export]
macro_rules! async_debug {
    ($($arg:tt)*) => {{
        let event = $crate::whathappened::EventBuilder::new()
            .level($crate::whathappened::Level::Debug)
            .location(file!(), line!(), module_path!())
            .message(format!($($arg)*))
            .build();
        
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                $crate::whathappened::log_event(event);
            });
        } else {
            $crate::whathappened::log_event(event);
        }
    }};
}

#[macro_export]
macro_rules! async_info {
    ($($arg:tt)*) => {{
        let event = $crate::whathappened::EventBuilder::new()
            .level($crate::whathappened::Level::Info)
            .location(file!(), line!(), module_path!())
            .message(format!($($arg)*))
            .build();
        
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                $crate::whathappened::log_event(event);
            });
        } else {
            $crate::whathappened::log_event(event);
        }
    }};
}

#[macro_export]
macro_rules! async_warn {
    ($($arg:tt)*) => {{
        let event = $crate::whathappened::EventBuilder::new()
            .level($crate::whathappened::Level::Warn)
            .location(file!(), line!(), module_path!())
            .message(format!($($arg)*))
            .build();
        
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                $crate::whathappened::log_event(event);
            });
        } else {
            $crate::whathappened::log_event(event);
        }
    }};
}

#[macro_export]
macro_rules! async_error {
    ($($arg:tt)*) => {{
        let event = $crate::whathappened::EventBuilder::new()
            .level($crate::whathappened::Level::Error)
            .location(file!(), line!(), module_path!())
            .message(format!($($arg)*))
            .build();
        
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                $crate::whathappened::log_event(event);
            });
        } else {
            $crate::whathappened::log_event(event);
        }
    }};
}