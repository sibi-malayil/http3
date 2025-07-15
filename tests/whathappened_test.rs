//! Tests for the WhatHappened logging system

use http3::whathappened::{self, Level, LevelFilter, Event, EventKind};
use http3::{info, warn, error, debug, trace};
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

/// Test output that captures events
#[derive(Default)]
struct TestOutput {
    events: Arc<Mutex<VecDeque<Event>>>,
}

impl TestOutput {
    fn new() -> Self {
        Self {
            events: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
    
    fn get_events(&self) -> Vec<Event> {
        self.events.lock().unwrap().drain(..).collect()
    }
}

impl whathappened::Output for TestOutput {
    fn write(&self, event: &Event) -> std::io::Result<()> {
        self.events.lock().unwrap().push_back(event.clone());
        Ok(())
    }
}

#[test]
fn test_basic_logging() {
    whathappened::init();
    whathappened::set_level_filter(LevelFilter::Trace);
    
    // Clear default outputs and add test output
    whathappened::clear_outputs();
    let test_output = Arc::new(TestOutput::new());
    whathappened::add_output(test_output.clone());
    
    // Log at different levels
    trace!("Trace message");
    debug!("Debug message");
    info!("Info message");
    warn!("Warning message");
    error!("Error message");
    
    // Wait for events to process
    std::thread::sleep(std::time::Duration::from_millis(50));
    
    // Check events were captured
    let events = test_output.get_events();
    assert_eq!(events.len(), 5);
    
    // Verify levels
    assert_eq!(events[0].level, Level::Trace);
    assert_eq!(events[1].level, Level::Debug);
    assert_eq!(events[2].level, Level::Info);
    assert_eq!(events[3].level, Level::Warn);
    assert_eq!(events[4].level, Level::Error);
    
    // Verify messages
    assert_eq!(events[0].message, "Trace message");
    assert_eq!(events[4].message, "Error message");
}

#[test]
fn test_level_filtering() {
    whathappened::init();
    
    // Clear and set test output
    whathappened::clear_outputs();
    let test_output = Arc::new(TestOutput::new());
    whathappened::add_output(test_output.clone());
    
    // Set filter to Info - should not see Debug or Trace
    whathappened::set_level_filter(LevelFilter::Info);
    
    trace!("Should not appear");
    debug!("Should not appear");
    info!("Should appear");
    warn!("Should appear");
    
    std::thread::sleep(std::time::Duration::from_millis(50));
    
    let events = test_output.get_events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].message, "Should appear");
    assert_eq!(events[1].message, "Should appear");
}

#[test]
fn test_event_context() {
    whathappened::init();
    whathappened::set_level_filter(LevelFilter::Debug);
    
    whathappened::clear_outputs();
    let test_output = Arc::new(TestOutput::new());
    whathappened::add_output(test_output.clone());
    
    // Log with context
    info!("User action"; "user_id" => 123, "action" => "login");
    
    std::thread::sleep(std::time::Duration::from_millis(50));
    
    let events = test_output.get_events();
    assert_eq!(events.len(), 1);
    
    let event = &events[0];
    assert_eq!(event.message, "User action");
    assert_eq!(event.context.len(), 2);
    assert!(event.context.contains(&("user_id".to_string(), "123".to_string())));
    assert!(event.context.contains(&("action".to_string(), "\"login\"".to_string())));
}

#[test]
fn test_thread_info() {
    whathappened::init();
    
    whathappened::clear_outputs();
    let test_output = Arc::new(TestOutput::new());
    whathappened::add_output(test_output.clone());
    
    // Log from main thread
    info!("Main thread message");
    
    // Log from named thread
    let handle = std::thread::Builder::new()
        .name("test-thread".to_string())
        .spawn(|| {
            info!("Named thread message");
        })
        .unwrap();
    
    handle.join().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(50));
    
    let events = test_output.get_events();
    assert_eq!(events.len(), 2);
    
    // Check thread names
    assert!(events[1].thread_name.as_ref().unwrap().contains("test-thread"));
}

#[test]
fn test_metrics_handler() {
    whathappened::init();
    whathappened::set_level_filter(LevelFilter::Trace);
    
    let metrics = Arc::new(whathappened::MetricsHandler::new());
    whathappened::add_handler(metrics.clone());
    
    // Generate some events
    info!("Info 1");
    info!("Info 2");
    warn!("Warning");
    error!("Error");
    
    std::thread::sleep(std::time::Duration::from_millis(50));
    
    let counts = metrics.metrics();
    assert_eq!(counts.get("level.info"), Some(&2));
    assert_eq!(counts.get("level.warn"), Some(&1));
    assert_eq!(counts.get("level.error"), Some(&1));
    assert_eq!(counts.get("kind.log"), Some(&4));
    assert_eq!(counts.get("total"), Some(&4));
}