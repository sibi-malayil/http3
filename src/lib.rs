#![deny(unsafe_code)]
#![forbid(unsafe_code)]
#![warn(
    clippy::all,
    rust_2018_idioms,
    missing_docs
)]

//! # HTTP/3 Implementation
//!
//! A production-grade HTTP/3 protocol implementation in Rust, built from scratch
//! following RFC 9114 (HTTP/3), RFC 9204 (QPACK), and RFC 9000 (QUIC).
//!
//! ## Features
//!
//! - Complete QUIC transport protocol implementation
//! - HTTP/3 application protocol support
//! - QPACK header compression
//! - Async/await support throughout
//! - Zero-copy packet processing where possible
//! - Production-ready error handling
//!
//! ## Example
//!
//! ```rust,no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use http3::{client::Client, server::Server};
//!
//! // Create a client connection
//! let mut client = Client::connect("https://example.com").await?;
//! let response = client.get("/").await?;
//!
//! // Create a server
//! let server = Server::bind("127.0.0.1:8080").await?;
//! # Ok(())
//! # }
//! ```

/// Error types and handling
pub mod error;
/// Enhanced error handling with context
pub mod error_context;
/// Utility modules for protocol implementation
pub mod util;

pub mod quic;
pub mod http3;
pub mod qpack;
pub mod network;

pub mod connection;
pub mod stream;
pub mod frame;

#[cfg(feature = "tls-rustls")]
pub mod crypto;

pub mod client;
pub mod server;

/// Certificate loading utilities
pub mod certs;

/// WhatHappened: High-performance event logging system
pub mod whathappened;

// Re-export commonly used types
pub use error::{Error, Result};

#[cfg(feature = "logging")]
pub use tracing;

/// HTTP/3 protocol version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Supported QUIC versions
pub const SUPPORTED_VERSIONS: &[u32] = &[0x0000_0001];

/// Default ALPN protocols for HTTP/3
pub const ALPN_H3: &[u8] = b"h3";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_constant() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn supported_versions() {
        assert!(!SUPPORTED_VERSIONS.is_empty());
        assert!(SUPPORTED_VERSIONS.contains(&0x0000_0001));
    }

    #[test]
    fn alpn_protocol() {
        assert_eq!(ALPN_H3, b"h3");
    }
}
