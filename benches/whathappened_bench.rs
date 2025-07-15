//! Benchmarks for WhatHappened logging system

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use http3::whathappened::{self, LevelFilter};
use http3::{info, debug, trace};
use std::sync::Arc;

/// Null output that discards everything (for benchmarking)
struct NullOutput;

impl whathappened::Output for NullOutput {
    fn write(&self, _event: &whathappened::Event) -> std::io::Result<()> {
        Ok(())
    }
}

fn bench_logging_disabled(c: &mut Criterion) {
    whathappened::init();
    whathappened::set_level_filter(LevelFilter::Off);
    
    c.bench_function("log_when_disabled", |b| {
        b.iter(|| {
            trace!("This should be completely optimized out: {}", black_box(42));
        })
    });
}

fn bench_logging_simple(c: &mut Criterion) {
    whathappened::init();
    whathappened::clear_outputs();
    whathappened::add_output(Arc::new(NullOutput));
    whathappened::set_level_filter(LevelFilter::Trace);
    
    c.bench_function("simple_info_log", |b| {
        b.iter(|| {
            info!("Simple message");
        })
    });
    
    c.bench_function("formatted_log", |b| {
        let value = 42;
        b.iter(|| {
            info!("Formatted message: value={}", black_box(value));
        })
    });
}

fn bench_logging_with_context(c: &mut Criterion) {
    whathappened::init();
    whathappened::clear_outputs();
    whathappened::add_output(Arc::new(NullOutput));
    whathappened::set_level_filter(LevelFilter::Trace);
    
    c.bench_function("log_with_context", |b| {
        let user_id = 12345;
        let ip = "192.168.1.1";
        b.iter(|| {
            info!("User action"; 
                "user_id" => black_box(user_id), 
                "ip" => black_box(ip),
                "action" => "login"
            );
        })
    });
}

fn bench_level_filtering(c: &mut Criterion) {
    whathappened::init();
    whathappened::clear_outputs();
    whathappened::add_output(Arc::new(NullOutput));
    whathappened::set_level_filter(LevelFilter::Info);
    
    c.bench_function("filtered_debug_log", |b| {
        b.iter(|| {
            // This should be filtered at runtime
            debug!("Debug message that won't be logged: {}", black_box(42));
        })
    });
}

fn bench_multi_threaded(c: &mut Criterion) {
    whathappened::init();
    whathappened::clear_outputs();
    whathappened::add_output(Arc::new(NullOutput));
    whathappened::set_level_filter(LevelFilter::Info);
    
    c.bench_function("concurrent_logging_4_threads", |b| {
        b.iter(|| {
            let handles: Vec<_> = (0..4)
                .map(|i| {
                    std::thread::spawn(move || {
                        for j in 0..10 {
                            info!("Thread {} iteration {}", i, j);
                        }
                    })
                })
                .collect();
            
            for handle in handles {
                handle.join().unwrap();
            }
        })
    });
}

criterion_group!(
    benches,
    bench_logging_disabled,
    bench_logging_simple,
    bench_logging_with_context,
    bench_level_filtering,
    bench_multi_threaded
);
criterion_main!(benches);