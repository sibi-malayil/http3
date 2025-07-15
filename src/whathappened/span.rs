//! Span support for hierarchical context tracking

use super::{EventBuilder, EventKind, Level};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

static SPAN_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// A span represents a unit of work with a beginning and end
#[derive(Debug, Clone)]
pub struct Span {
    pub id: u64,
    pub name: String,
    pub target: &'static str,
    pub level: Level,
    pub parent_id: Option<u64>,
    pub fields: Vec<(String, String)>,
    pub start_time: Instant,
}

/// Handle to an active span
pub struct SpanHandle {
    span: Arc<Span>,
}

impl Span {
    /// Create a new span
    pub fn new(name: impl Into<String>, target: &'static str, level: Level) -> Self {
        Self {
            id: SPAN_ID_COUNTER.fetch_add(1, Ordering::Relaxed),
            name: name.into(),
            target,
            level,
            parent_id: None, // Simplified - no parent tracking for now
            fields: Vec::new(),
            start_time: Instant::now(),
        }
    }
    
    /// Add a field to the span
    pub fn record(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.fields.push((key.into(), value.into()));
    }
    
    /// Enter this span
    pub fn enter(self) -> SpanHandle {
        let span = Arc::new(self);
        
        // Log span entry
        super::log_event(
            EventBuilder::new()
                .level(span.level)
                .kind(EventKind::Custom("span.enter".to_string()))
                .location(span.target, 0, span.target)
                .message(format!("→ {}", span.name))
                .context("span_id", span.id.to_string())
                .build()
        );
        
        SpanHandle { span }
    }
}

impl Drop for SpanHandle {
    fn drop(&mut self) {
        let duration = self.span.start_time.elapsed();
        
        // Log span exit
        super::log_event(
            EventBuilder::new()
                .level(self.span.level)
                .kind(EventKind::Custom("span.exit".to_string()))
                .location(self.span.target, 0, self.span.target)
                .message(format!("← {} ({:?})", self.span.name, duration))
                .context("span_id", self.span.id.to_string())
                .context("duration_us", duration.as_micros().to_string())
                .build()
        );
    }
}

/// Instrument a future with a span (for async support)
pub struct Instrumented<T> {
    inner: T,
    span: Arc<Span>,
}

impl<T> Instrumented<T> {
    pub fn new(inner: T, span: Span) -> Self {
        Self {
            inner,
            span: Arc::new(span),
        }
    }
}

// Async support when tokio feature is enabled
#[cfg(feature = "async-tokio")]
impl<T: std::future::Future + std::marker::Unpin> std::future::Future for Instrumented<T> {
    type Output = T::Output;
    
    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        // Create a temporary span for logging
        let span_clone = (*self.span).clone();
        let _guard = span_clone.enter();
        std::pin::Pin::new(&mut self.inner).poll(cx)
    }
}

/// Span builder for the macro
pub struct SpanBuilder {
    name: String,
    target: &'static str,
    level: Level,
    fields: Vec<(String, String)>,
}

impl SpanBuilder {
    pub fn new(name: impl Into<String>, target: &'static str) -> Self {
        Self {
            name: name.into(),
            target,
            level: Level::Info,
            fields: Vec::new(),
        }
    }
    
    pub fn level(mut self, level: Level) -> Self {
        self.level = level;
        self
    }
    
    pub fn field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.push((key.into(), value.into()));
        self
    }
    
    pub fn enter(self) -> SpanHandle {
        let mut span = Span::new(self.name, self.target, self.level);
        for (k, v) in self.fields {
            span.record(k, v);
        }
        span.enter()
    }
}

/// Create a span
#[macro_export]
macro_rules! span {
    ($name:expr) => {
        $crate::whathappened::span::SpanBuilder::new($name, module_path!()).enter()
    };
    ($name:expr, $($key:ident = $value:expr),*) => {{
        let mut builder = $crate::whathappened::span::SpanBuilder::new($name, module_path!());
        $(
            builder = builder.field(stringify!($key), format!("{:?}", $value));
        )*
        builder.enter()
    }};
    ($level:expr, $name:expr) => {
        $crate::whathappened::span::SpanBuilder::new($name, module_path!())
            .level($level)
            .enter()
    };
    ($level:expr, $name:expr, $($key:ident = $value:expr),*) => {{
        let mut builder = $crate::whathappened::span::SpanBuilder::new($name, module_path!())
            .level($level);
        $(
            builder = builder.field(stringify!($key), format!("{:?}", $value));
        )*
        builder.enter()
    }};
}