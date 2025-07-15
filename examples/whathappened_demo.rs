//! Demonstration of the whathappened logging system

use http3::whathappened::{self, Level, EventBuilder, EventKind};
use std::{thread, time::Duration};

fn main() {
    // Initialize with panic handler
    whathappened::init_with_panic_handler();
    
    // Set debug level
    whathappened::set_level_filter(whathappened::LevelFilter::Debug);
    
    // Log some events using the macros
    println!("=== Testing whathappened logging system ===\n");
    
    // Test different log levels
    http3::whathappened::log_event(
        EventBuilder::new()
            .level(Level::Debug)
            .kind(EventKind::Log)
            .location(file!(), line!(), module_path!())
            .message("Debug message")
            .build()
    );
    
    http3::whathappened::log_event(
        EventBuilder::new()
            .level(Level::Info)
            .kind(EventKind::Network)
            .location(file!(), line!(), module_path!())
            .message("Connection established")
            .context("remote", "127.0.0.1:8080")
            .context("protocol", "HTTP/3")
            .build()
    );
    
    http3::whathappened::log_event(
        EventBuilder::new()
            .level(Level::Warn)
            .kind(EventKind::Protocol)
            .location(file!(), line!(), module_path!())
            .message("Retransmission timeout")
            .context("packet_num", "42")
            .build()
    );
    
    http3::whathappened::log_event(
        EventBuilder::new()
            .level(Level::Error)
            .kind(EventKind::Crypto)
            .location(file!(), line!(), module_path!())
            .message("TLS handshake failed")
            .context("reason", "certificate_verify_failed")
            .build()
    );
    
    // Test from multiple threads
    println!("\n=== Testing multi-threaded logging ===\n");
    
    let handles: Vec<_> = (0..3)
        .map(|i| {
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(i * 10));
                
                http3::whathappened::log_event(
                    EventBuilder::new()
                        .level(Level::Info)
                        .kind(EventKind::Performance)
                        .location(file!(), line!(), module_path!())
                        .message(format!("Thread {} reporting", i))
                        .context("thread_id", &i.to_string())
                        .build()
                );
            })
        })
        .collect();
    
    for handle in handles {
        handle.join().unwrap();
    }
    
    // Give events time to be processed
    thread::sleep(Duration::from_millis(100));
    
    println!("\n=== Testing panic handler ===\n");
    
    // This will trigger the panic handler
    thread::spawn(|| {
        http3::whathappened::log_event(
            EventBuilder::new()
                .level(Level::Fatal)
                .kind(EventKind::Log)
                .location(file!(), line!(), module_path!())
                .message("About to panic!")
                .build()
        );
        
        panic!("This is a test panic!");
    }).join().unwrap_err();
    
    // Give panic event time to be processed
    thread::sleep(Duration::from_millis(100));
    
    println!("\n=== Demo complete ===");
}