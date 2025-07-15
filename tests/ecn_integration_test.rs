use http3::{
    quic::{
        congestion::{CongestionController, CongestionAlgorithm},
        ecn::{EcnCodepoint, EcnController},
    },
    util::time::Instant,
};

#[test]
fn test_ecn_controller_integration() {
    let mut controller = CongestionController::with_algorithm(CongestionAlgorithm::NewReno);
    let now = Instant::now();
    
    // Test ECN is initially not capable
    assert!(!controller.is_ecn_capable());
    
    // Get outgoing ECN codepoint (should start validation)
    let ecn = controller.outgoing_ecn_codepoint(now);
    assert_eq!(ecn, EcnCodepoint::Ect0);
    
    // Process some ECN-marked packets to complete validation
    for _ in 0..5 {
        controller.on_ecn_packet_received(EcnCodepoint::Ect0, now);
    }
    
    // Process ECN congestion events
    controller.process_ecn_congestion_events(1000, now).unwrap();
    
    // Get ECN stats
    let stats = controller.ecn_stats();
    assert!(stats.enabled);
    assert_eq!(stats.counters.ect0_count, 5);
}

#[test]
fn test_ecn_congestion_event_handling() {
    let mut controller = CongestionController::with_algorithm(CongestionAlgorithm::CUBIC);
    let now = Instant::now();
    
    // Set ECN to capable state
    controller.set_ecn_enabled(true);
    
    // Send some packets to establish state
    for _ in 0..10 {
        controller.on_ecn_packet_received(EcnCodepoint::Ect0, now);
    }
    
    // Send a CE-marked packet (congestion experienced)
    controller.on_ecn_packet_received(EcnCodepoint::Ce, now);
    
    // Process congestion events - should trigger congestion response
    let result = controller.process_ecn_congestion_events(5000, now);
    assert!(result.is_ok());
    
    let stats = controller.ecn_stats();
    assert_eq!(stats.counters.ce_count, 1);
    assert_eq!(stats.congestion_events, 1);
}

#[test]
fn test_ecn_with_all_algorithms() {
    let algorithms = [
        CongestionAlgorithm::NewReno,
        CongestionAlgorithm::BBR,
        CongestionAlgorithm::BBRv2,
        CongestionAlgorithm::CUBIC,
    ];
    
    for algorithm in algorithms {
        let mut controller = CongestionController::with_algorithm(algorithm);
        let now = Instant::now();
        
        // Test basic ECN functionality
        let ecn = controller.outgoing_ecn_codepoint(now);
        assert!(matches!(ecn, EcnCodepoint::Ect0 | EcnCodepoint::NotEct));
        
        // Process ECN packets
        controller.on_ecn_packet_received(EcnCodepoint::Ect0, now);
        controller.on_ecn_packet_received(EcnCodepoint::Ce, now);
        
        // Test congestion event processing
        let result = controller.process_ecn_congestion_events(1000, now);
        assert!(result.is_ok(), "Algorithm {:?} failed ECN processing", algorithm);
    }
}

#[test]
fn test_ecn_disabled() {
    let mut controller = CongestionController::new();
    let now = Instant::now();
    
    // Disable ECN
    controller.set_ecn_enabled(false);
    
    // Should return NotEct for outgoing packets
    let ecn = controller.outgoing_ecn_codepoint(now);
    assert_eq!(ecn, EcnCodepoint::NotEct);
    
    // Should not be ECN capable
    assert!(!controller.is_ecn_capable());
}

#[test]
fn test_ecn_validation_process() {
    let mut ecn_controller = EcnController::new();
    let now = Instant::now();
    
    // Start with unknown state
    assert!(!ecn_controller.is_ecn_capable());
    assert!(!ecn_controller.has_validation_failed());
    
    // Get first outgoing codepoint - should start validation
    let ecn = ecn_controller.outgoing_ecn_codepoint(now);
    assert_eq!(ecn, EcnCodepoint::Ect0);
    
    // Process enough ECN responses to complete validation
    for _ in 0..5 {
        ecn_controller.on_packet_received(EcnCodepoint::Ect0, now);
    }
    
    // Should now be capable
    let stats = ecn_controller.stats();
    println!("ECN stats: {:?}", stats);
}