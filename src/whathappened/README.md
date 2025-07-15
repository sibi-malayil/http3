# WhatHappened - High-Performance Event Logging System

A modern, efficient event logging system built for Rust 2024 with zero-cost abstractions, structured logging, and comprehensive panic handling.

## Features

- **Zero-Cost Abstractions**: Compile-time optimizations ensure minimal runtime overhead
- **Structured Events**: Rich event metadata including timestamps, thread info, and custom context
- **Panic Handler Integration**: Automatically captures and logs panic information
- **Multi-Level Filtering**: Control log verbosity with compile-time and runtime filters
- **Async Processing**: Non-blocking event processing with bounded channels
- **Pluggable Outputs**: Console, file, JSON, and custom output targets
- **Event Handlers**: Process events with custom logic (metrics, filtering, batching)
- **Thread-Safe**: Lock-free operations where possible, efficient synchronization elsewhere
- **Rust 2024 Features**: Uses LazyLock, improved atomics, and modern Rust patterns

## Usage

### Basic Logging

```rust
use http3::{info, warn, error, debug, trace};

// Initialize the system
http3::whathappened::init();

// Log at different levels
info!("Server started on port {}", 8080);
warn!("Connection pool near capacity: {}/{}", 95, 100);
error!("Failed to process request: {}", err);
debug!("Request headers: {:?}", headers);
trace!("Entering function process_packet");
```

### Structured Logging with Context

```rust
// Add key-value context to any log
info!("User authenticated"; 
    "user_id" => user.id, 
    "ip" => conn.remote_addr(),
    "method" => "OAuth2"
);

// Specialized event types
net_event!(Level::Info, "Connection established"; 
    "remote" => addr, 
    "protocol" => "QUIC"
);

crypto_event!(Level::Debug, "Key rotation"; 
    "algorithm" => "AES-256-GCM",
    "key_id" => new_key_id
);
```

### Performance Tracking

```rust
// Time any block of code
let result = time_block!("database_query", {
    db.query("SELECT * FROM users").await?
});

// Log errors automatically
let data = log_error!(
    fetch_data().await,
    "Failed to fetch user data for id={}", user_id
)?;
```

### Custom Outputs and Handlers

```rust
// Add file output
let file_output = whathappened::FileOutput::new("app.log")?;
whathappened::add_output(Arc::new(file_output));

// Add metrics collection
let metrics = Arc::new(whathappened::MetricsHandler::new());
whathappened::add_handler(metrics.clone());

// Create filtered handler
let error_handler = FilterHandler::new(
    |event| event.level <= Level::Error,
    email_alert_handler
);
whathappened::add_handler(Arc::new(error_handler));
```

### Panic Handling

```rust
// Enable automatic panic capture
whathappened::init_with_panic_handler();

// Panics are automatically logged with full context
// Including thread name, location, and backtrace
```

## Architecture

### Core Components

1. **Event System** (`mod.rs`)
   - Global singleton using `LazyLock`
   - Manages handlers, outputs, and event processing
   - Background thread for async event processing

2. **Event Structure** (`event.rs`)
   - Rich metadata: ID, timestamp, level, thread info
   - Extensible context via key-value pairs
   - Optional backtrace capture

3. **Efficient Macros** (`macros.rs`)
   - Zero-cost when disabled via level filtering
   - Lazy evaluation of expensive arguments
   - Source location capture at compile time

4. **Output Targets** (`output.rs`)
   - Trait-based extensible design
   - Built-in: Console, File, JSON, Buffered, Multi
   - Automatic stdout/stderr routing by level

5. **Event Handlers** (`handler.rs`)
   - Process events before output
   - Filter, batch, collect metrics
   - Chain multiple handlers

### Performance Considerations

- **Lock-Free Where Possible**: Atomic operations for counters and flags
- **Bounded Channels**: Prevent memory exhaustion under load
- **Lazy Initialization**: Components created only when needed
- **Compile-Time Optimization**: Macros expand to minimal code
- **Efficient Formatting**: Avoid string allocation when events are filtered

### Thread Safety

- Thread-local event counters for low contention
- `RwLock` for handler/output lists (read-heavy)
- `Mutex` only where necessary (file writes)
- Atomic operations for global state

## Comparison with Other Logging Crates

### vs `tracing`
- **Simpler**: No spans or complex subscribers
- **Faster**: Less overhead for basic logging
- **Self-Contained**: No external dependencies for core features

### vs `log`
- **Richer**: Structured events with metadata
- **Modern**: Built for async Rust and 2024 edition
- **Integrated**: Panic handling and performance tracking

### vs `slog`
- **Lighter**: Smaller API surface
- **Faster**: Optimized for common cases
- **Easier**: Less configuration needed

## Future Improvements

1. **Sampling**: Reduce high-frequency events
2. **Remote Outputs**: Send events over network
3. **Compression**: For file outputs
4. **Event Replay**: For debugging
5. **WASM Support**: Browser compatibility
6. **No-STD Mode**: For embedded systems

## License

Part of the HTTP/3 project - MIT OR Apache-2.0