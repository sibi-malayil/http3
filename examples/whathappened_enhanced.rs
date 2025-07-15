//! Enhanced demonstration of whathappened features

use http3::whathappened::{self, Level, EventKind, Context, Result, Error};
use http3::{debug, info, warn, error, fatal, span, event, net_event, crypto_event, time_block, log_error};
use std::{thread, time::Duration};

fn main() -> Result<()> {
    // Initialize with panic handler
    whathappened::init_with_panic_handler();
    whathappened::set_level_filter(whathappened::LevelFilter::Debug);
    
    println!("=== Enhanced WhatHappened Demo ===\n");
    
    // Test standard logging macros
    debug!("This is a debug message");
    info!("This is an info message");
    warn!("This is a warning message");
    error!("This is an error message");
    
    // Test structured logging
    event!(Level::Info, "User logged in", user_id = 123, ip = "192.168.1.1");
    net_event!(Level::Info, "Connection established", remote = "server.com", port = 443);
    crypto_event!(Level::Warn, "Certificate will expire soon", days_left = 30);
    
    // Test span tracking
    let _span = span!(Level::Info, "processing_request", request_id = "req-123");
    
    {
        let _nested_span = span!(Level::Debug, "database_query", table = "users");
        thread::sleep(Duration::from_millis(50));
        info!("Query completed");
    }
    
    info!("Request processed");
    
    // Test timing
    let result = time_block!("expensive_operation", {
        thread::sleep(Duration::from_millis(100));
        "operation result"
    });
    
    info!("Operation result: {}", result);
    
    // Test error handling
    demo_error_handling()?;
    
    // Test async-style logging (without tokio)
    test_threaded_spans();
    
    // Test rate limiting and conditions
    for i in 0..10 {
        http3::log_rate_limited!(1, Level::Info, "Rate limited message {}", i);
        http3::log_if!(i % 3 == 0, Level::Debug, "Conditional message {}", i);
    }
    
    // Test once logging
    for i in 0..5 {
        http3::log_once!(Level::Warn, "This will only appear once, iteration {}", i);
    }
    
    println!("\n=== Demo complete ===");
    Ok(())
}

fn demo_error_handling() -> Result<()> {
    // Test error context chaining
    let result = std::fs::read_to_string("nonexistent.txt")
        .context("Failed to read configuration file")
        .context("During application startup");
    
    match result {
        Ok(content) => info!("File content: {}", content),
        Err(e) => {
            e.log(Level::Error);
            // Don't propagate the error, just demonstrate
        }
    }
    
    // Test error creation
    let custom_error = Error::new("Custom error occurred")
        .context("In demo function")
        .context("During error handling test");
    
    custom_error.log(Level::Warn);
    
    // Test log_error macro
    let _result = log_error!(
        divide_by_zero(42, 0),
        "Math operation failed"
    );
    
    Ok(())
}

fn divide_by_zero(a: i32, b: i32) -> Result<i32> {
    if b == 0 {
        return Err(Error::new("Division by zero"));
    }
    Ok(a / b)
}

fn test_threaded_spans() {
    let handles: Vec<_> = (0..3)
        .map(|i| {
            thread::spawn(move || {
                let _span = span!(Level::Info, "worker_thread", thread_id = i);
                
                info!("Worker {} starting", i);
                
                let _work_span = span!(Level::Debug, "work_task", task_id = format!("task-{}", i));
                thread::sleep(Duration::from_millis(i * 20));
                
                info!("Worker {} completed", i);
            })
        })
        .collect();
    
    for handle in handles {
        handle.join().unwrap();
    }
}