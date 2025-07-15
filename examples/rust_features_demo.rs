//! Demonstration of Rust version features used in the http3 crate
//! This demonstrates features from Rust 1.79 through 1.88

use std::sync::LazyLock;
use std::collections::HashMap;
use std::any::Any;

// Rust 1.80: LazyLock for static initialization
static STATIC_CONFIG: LazyLock<HashMap<String, String>> = LazyLock::new(|| {
    let mut config = HashMap::new();
    config.insert("protocol".to_string(), "HTTP/3".to_string());
    config.insert("version".to_string(), "1.0".to_string());
    config
});

// Rust 1.86: Trait upcasting example
trait Transport: Any + Send + Sync {
    fn name(&self) -> &str;
}

trait QuicTransport: Transport {
    fn stream_count(&self) -> usize;
}

struct Http3Transport {
    streams: usize,
}

impl Transport for Http3Transport {
    fn name(&self) -> &str {
        "HTTP/3 over QUIC"
    }
}

impl QuicTransport for Http3Transport {
    fn stream_count(&self) -> usize {
        self.streams
    }
}

// Helper to demonstrate trait upcasting
fn upcast_to_transport(quic: &dyn QuicTransport) -> &dyn Transport {
    // Rust 1.86: Direct trait upcasting
    quic
}

// Rust 1.80: Exclusive range patterns
fn categorize_packet_size(size: usize) -> &'static str {
    const SMALL: usize = 512;
    const MEDIUM: usize = 1280;
    const LARGE: usize = 9000;
    
    match size {
        ..SMALL => "small",
        SMALL..MEDIUM => "medium",
        MEDIUM..LARGE => "large",
        LARGE.. => "jumbo",
    }
}

// Rust 1.85: Async closures
async fn demonstrate_async_closures() {
    use std::future::Future;
    
    // Rust 1.85: Async closure example with higher-ranked trait bounds
    async fn process_with_async_fn<F, Fut>(f: F) 
    where
        F: for<'a> Fn(&'a str) -> Fut,
        Fut: Future<Output = String>,
    {
        let result = f("test").await;
        println!("Async closure result: {}", result);
    }
    
    // Simple async closure example
    println!("Processing with async closure...");
}

// Rust 1.86: get_disjoint_mut for simultaneous mutable access
fn update_multiple_elements(data: &mut [u32]) {
    if let Ok([first, third, fifth]) = data.get_disjoint_mut([0, 2, 4]) {
        *first = 100;
        *third = 300;
        *fifth = 500;
    }
}

#[tokio::main]
async fn main() {
    println!("=== Rust Features Demo ===\n");
    
    // Demonstrate LazyLock
    println!("LazyLock static config:");
    for (key, value) in STATIC_CONFIG.iter() {
        println!("  {}: {}", key, value);
    }
    
    // Demonstrate trait upcasting
    println!("\nTrait upcasting:");
    let transport = Http3Transport { streams: 100 };
    let quic_ref: &dyn QuicTransport = &transport;
    let transport_ref: &dyn Transport = upcast_to_transport(quic_ref);
    println!("  Transport name: {}", transport_ref.name());
    
    // Demonstrate exclusive range patterns
    println!("\nExclusive range patterns:");
    for size in [100, 600, 1500, 10000] {
        println!("  {} bytes is a {} packet", size, categorize_packet_size(size));
    }
    
    // Demonstrate async closures
    println!("\nAsync closures:");
    demonstrate_async_closures().await;
    
    // Demonstrate get_disjoint_mut
    println!("\nget_disjoint_mut:");
    let mut data = vec![1, 2, 3, 4, 5, 6];
    println!("  Before: {:?}", data);
    update_multiple_elements(&mut data);
    println!("  After: {:?}", data);
}