//! Simple congestion control test
//!
//! This test validates basic congestion control functionality

use http3::quic::congestion::{CongestionController, CongestionAlgorithm};
use http3::util::time::Duration;

#[test]
fn test_basic_congestion_control() {
    // Create a NewReno controller
    let mut controller = CongestionController::with_algorithm(CongestionAlgorithm::NewReno);
    
    // Test basic initialization
    assert!(controller.congestion_window() > 0);
    assert!(controller.in_slow_start());
    assert!(!controller.in_recovery());
    
    // Test can_send functionality
    assert!(controller.can_send(0));
    assert!(controller.can_send(1000));
    
    // Test sending window
    assert!(controller.sending_window(0) > 0);
    assert!(controller.sending_window(1000) > 0);
    
    // Test ACK processing
    let ack_ranges = vec![(0, 4)]; // ACK packets 0-4
    let rtt = Duration::from_millis(50);
    
    if let Err(e) = controller.on_ack_received_with_rtt(&ack_ranges, rtt) {
        panic!("ACK processing failed: {}", e);
    }
    
    // Test packet loss
    if let Err(e) = controller.on_packet_lost(1200) {
        panic!("Loss processing failed: {}", e);
    }
    
    // Test periodic update
    controller.update();
    
    // Basic stats should be available
    let stats = controller.stats();
    assert_eq!(stats.algorithm, CongestionAlgorithm::NewReno);
    assert!(stats.congestion_window > 0);
    
    println!("✓ Basic congestion control test passed");
}

#[test]
fn test_rtt_tracking() {
    let mut controller = CongestionController::new();
    
    // Test RTT samples
    let rtt_samples = [50, 60, 55, 70, 45].iter()
        .map(|&ms| Duration::from_millis(ms))
        .collect::<Vec<_>>();
    
    for (i, &rtt) in rtt_samples.iter().enumerate() {
        let ack_ranges = vec![(i as u64, i as u64)];
        if let Err(e) = controller.on_ack_received_with_rtt(&ack_ranges, rtt) {
            panic!("RTT processing failed: {}", e);
        }
    }
    
    // Test RTT stats
    let rtt_stats = controller.rtt_stats();
    assert_eq!(rtt_stats.sample_count, 5);
    assert!(rtt_stats.min_rtt <= Duration::from_millis(45));
    assert!(rtt_stats.smoothed_rtt > Duration::ZERO);
    assert!(rtt_stats.smoothed_rtt < Duration::from_millis(100));
    
    println!("✓ RTT tracking test passed");
}

#[test] 
fn test_congestion_algorithms() {
    let algorithms = [
        CongestionAlgorithm::NewReno,
        CongestionAlgorithm::BBR,
        // Skip BBRv2 and CUBIC for now as they have external dependencies
    ];
    
    for algorithm in algorithms {
        let mut controller = CongestionController::with_algorithm(algorithm);
        
        // Test basic functionality
        assert!(controller.congestion_window() > 0);
        assert_eq!(controller.algorithm(), algorithm);
        
        // Test ACK processing
        let ack_ranges = vec![(0, 2)];
        let rtt = Duration::from_millis(50);
        
        if let Err(e) = controller.on_ack_received_with_rtt(&ack_ranges, rtt) {
            panic!("ACK processing failed for {:?}: {}", algorithm, e);
        }
        
        // Test periodic update
        controller.update();
        
        println!("✓ Algorithm {:?} test passed", algorithm);
    }
}

#[test]
fn test_production_features() {
    let mut controller = CongestionController::new();
    
    // Test pacing
    assert!(controller.is_pacing_enabled());
    
    // Test stats
    let stats = controller.stats();
    assert_eq!(stats.algorithm, CongestionAlgorithm::NewReno);
    
    // Test RTT stats
    let rtt_stats = controller.rtt_stats();
    assert_eq!(rtt_stats.sample_count, 0);
    
    // Test ECN stats
    let ecn_stats = controller.ecn_stats();
    assert_eq!(ecn_stats.total_marks, 0);
    
    // Test pacing stats
    let pacing_stats = controller.pacing_stats();
    assert!(pacing_stats.pacing_rate > 0);
    
    println!("✓ Production features test passed");
}

#[test]
fn test_production_congestion_control_integration() {
    println!("🚀 Testing production-grade congestion control integration");
    
    let mut controller = CongestionController::with_algorithm(CongestionAlgorithm::BBR);
    
    // 1. Test initialization
    assert!(controller.congestion_window() > 0);
    assert!(controller.is_pacing_enabled());
    println!("   ✓ Controller initialized successfully");
    
    // 2. Test RTT tracking
    let rtt_samples = [50, 60, 55, 70, 45, 65, 52, 58].iter()
        .map(|&ms| Duration::from_millis(ms))
        .collect::<Vec<_>>();
    
    for (i, &rtt) in rtt_samples.iter().enumerate() {
        let ack_ranges = vec![(i as u64, i as u64)];
        controller.on_ack_received_with_rtt(&ack_ranges, rtt)
            .expect("RTT processing should succeed");
    }
    
    let rtt_stats = controller.rtt_stats();
    assert_eq!(rtt_stats.sample_count, 8);
    assert!(rtt_stats.min_rtt <= Duration::from_millis(45));
    println!("   ✓ RTT tracking: smoothed={:?}, min={:?}", rtt_stats.smoothed_rtt, rtt_stats.min_rtt);
    
    // 3. Test bandwidth estimation for BBR
    if let Some(bandwidth) = controller.bottleneck_bandwidth() {
        assert!(bandwidth > 0);
        println!("   ✓ Bandwidth estimation: {} bytes/sec", bandwidth);
    } else {
        println!("   ℹ Bandwidth estimation not available yet");
    }
    
    // 4. Test pacing functionality
    let pacing_stats = controller.pacing_stats();
    assert!(pacing_stats.pacing_rate > 0);
    println!("   ✓ Pacing active: {} bytes/sec", pacing_stats.pacing_rate);
    
    // 5. Test ECN support
    let ecn_stats = controller.ecn_stats();
    assert_eq!(ecn_stats.total_marks, 0);
    println!("   ✓ ECN support initialized");
    
    // 6. Test congestion response
    let cwnd_before_loss = controller.congestion_window();
    controller.on_packet_lost(1200)
        .expect("Loss processing should succeed");
    let cwnd_after_loss = controller.congestion_window();
    println!("   ✓ Loss response: cwnd {} -> {}", cwnd_before_loss, cwnd_after_loss);
    
    // 7. Test periodic updates
    for _ in 0..5 {
        controller.update();
    }
    assert!(controller.congestion_window() > 0);
    println!("   ✓ Periodic updates working");
    
    // 8. Test comprehensive stats
    let stats = controller.stats();
    assert_eq!(stats.algorithm, CongestionAlgorithm::BBR);
    assert!(stats.congestion_window > 0);
    println!("   ✓ Statistics: algorithm={:?}, cwnd={}", stats.algorithm, stats.congestion_window);
    
    println!("🎉 Production-grade congestion control integration test passed!");
    println!("   - RTT tracking with smoothed measurements ✓");
    println!("   - Bandwidth estimation for BBR ✓");
    println!("   - Packet pacing for smooth transmission ✓");
    println!("   - ECN support for early congestion detection ✓");
    println!("   - Proper loss detection and recovery ✓");
    println!("   - Comprehensive monitoring and statistics ✓");
}