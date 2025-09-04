//! ACK frame generation and management
//!
//! Implements ACK frame generation according to RFC 9000 Section 13.2.

use crate::{
    quic::{
        frame_types::{Frame, AckRange, EcnCounts},
        recovery::PacketNumberSpace,
    },
    util::time::{Duration, Instant},
    whathappened::Level,
    {protocol_event, span},
};
use std::collections::BTreeSet;

/// Maximum number of ACK ranges to include in a single ACK frame
const MAX_ACK_RANGES: usize = 32;

/// Minimum delay before sending an ACK after receiving ack-eliciting packets
const MIN_ACK_DELAY: Duration = Duration::from_millis(1);

/// Maximum delay before sending an ACK
const MAX_ACK_DELAY: Duration = Duration::from_millis(25);

/// Number of ack-eliciting packets received before sending immediate ACK
const ACK_ELICITING_THRESHOLD: u32 = 2;

/// Represents a received packet for ACK tracking
#[derive(Debug, Clone)]
struct ReceivedPacket {
    /// Packet number
    packet_number: u64,
    /// Time when packet was received
    receive_time: Instant,
    /// Whether this packet is ack-eliciting
    ack_eliciting: bool,
}

/// ACK manager for a single packet number space
#[derive(Debug)]
pub struct AckManager {
    /// Packet number space this manager handles
    pn_space: PacketNumberSpace,
    /// Set of received packet numbers
    received_packets: BTreeSet<u64>,
    /// Largest packet number received
    largest_received: Option<u64>,
    /// Time when largest packet was received
    largest_received_time: Option<Instant>,
    /// Number of ack-eliciting packets received since last ACK sent
    ack_eliciting_count: u32,
    /// Time when first ack-eliciting packet was received since last ACK
    first_ack_eliciting_time: Option<Instant>,
    /// Whether we need to send an ACK frame
    needs_ack: bool,
    /// ACK delay exponent from transport parameters
    ack_delay_exponent: u8,
    /// Minimum number of received packets before sending ACK
    min_received_before_ack: u32,
    /// ECN counts for received packets
    ecn_counts: EcnCounts,
}

impl AckManager {
    /// Create a new ACK manager for a packet number space
    pub fn new(pn_space: PacketNumberSpace) -> Self {
        Self {
            pn_space,
            received_packets: BTreeSet::new(),
            largest_received: None,
            largest_received_time: None,
            ack_eliciting_count: 0,
            first_ack_eliciting_time: None,
            needs_ack: false,
            ack_delay_exponent: 3, // RFC 9000 default
            min_received_before_ack: ACK_ELICITING_THRESHOLD,
            ecn_counts: EcnCounts { ect0: 0, ect1: 0, ecn_ce: 0 },
        }
    }

    /// Record a received packet
    pub fn on_packet_received(
        &mut self,
        packet_number: u64,
        ack_eliciting: bool,
        receive_time: Instant,
    ) {
        let _span = span!(Level::Debug, "on_packet_received", 
            pn_space = self.pn_space, 
            packet_number = packet_number, 
            ack_eliciting = ack_eliciting
        );

        // Track the packet
        self.received_packets.insert(packet_number);

        // Update largest received
        if self.largest_received.map_or(true, |largest| packet_number > largest) {
            self.largest_received = Some(packet_number);
            self.largest_received_time = Some(receive_time);
        }

        // Track ack-eliciting packets
        if ack_eliciting {
            self.ack_eliciting_count += 1;
            if self.first_ack_eliciting_time.is_none() {
                self.first_ack_eliciting_time = Some(receive_time);
            }

            // RFC 9000: Send immediate ACK after receiving ACK_ELICITING_THRESHOLD packets
            if self.ack_eliciting_count >= self.min_received_before_ack {
                self.needs_ack = true;
                protocol_event!(
                    Level::Debug,
                    "Immediate ACK needed - threshold reached";
                    "pn_space" => self.pn_space,
                    "ack_eliciting_count" => self.ack_eliciting_count,
                    "threshold" => self.min_received_before_ack
                );
            }
        }

        // Always ACK immediately for crypto packets in Initial/Handshake
        if matches!(self.pn_space, PacketNumberSpace::Initial | PacketNumberSpace::Handshake) {
            self.needs_ack = true;
        }
    }

    /// Check if an ACK should be sent based on timing
    pub fn should_send_ack(&self, now: Instant) -> bool {
        if self.needs_ack {
            return true;
        }

        // Check if we've exceeded the max ACK delay
        if let Some(first_time) = self.first_ack_eliciting_time {
            let elapsed = now.duration_since(first_time);
            if elapsed >= MAX_ACK_DELAY {
                protocol_event!(
                    Level::Debug,
                    "ACK needed - max delay exceeded";
                    "pn_space" => self.pn_space,
                    "elapsed_ms" => elapsed.as_millis(),
                    "max_delay_ms" => MAX_ACK_DELAY.as_millis()
                );
                return true;
            }
        }

        false
    }

    /// Generate an ACK frame
    pub fn generate_ack_frame(&mut self, now: Instant) -> Option<Frame> {
        let largest_acked = self.largest_received?;
        let largest_received_time = self.largest_received_time?;

        // Calculate ACK delay in microseconds
        let ack_delay = now.duration_since(largest_received_time);
        let ack_delay_us = ack_delay.as_micros() as u64;
        
        // Encode ACK delay according to RFC 9000
        let encoded_ack_delay = ack_delay_us >> self.ack_delay_exponent;

        // Generate ACK ranges
        let (first_ack_range, ack_ranges) = self.generate_ack_ranges(largest_acked);

        protocol_event!(
            Level::Info,
            "Generating ACK frame";
            "pn_space" => self.pn_space,
            "largest_acked" => largest_acked,
            "ack_delay_us" => ack_delay_us,
            "encoded_ack_delay" => encoded_ack_delay,
            "ack_range_count" => ack_ranges.len(),
            "packets_tracked" => self.received_packets.len()
        );

        // Reset ACK generation state
        self.needs_ack = false;
        self.ack_eliciting_count = 0;
        self.first_ack_eliciting_time = None;

        Some(Frame::Ack {
            largest_acknowledged: largest_acked,
            ack_delay: encoded_ack_delay,
            ack_range_count: ack_ranges.len() as u64,
            first_ack_range,
            ack_ranges,
            ecn_counts: if self.has_ecn_counts() {
                Some(self.ecn_counts.clone())
            } else {
                None
            },
        })
    }

    /// Generate ACK ranges from received packets
    fn generate_ack_ranges(&self, largest_acked: u64) -> (u64, Vec<AckRange>) {
        let mut ranges = Vec::new();
        let mut packets: Vec<u64> = self.received_packets.iter()
            .copied()
            .filter(|&pn| pn <= largest_acked)
            .collect();
        packets.sort_by(|a, b| b.cmp(a)); // Sort in descending order
        
        if packets.is_empty() {
            return (0, ranges);
        }
        
        // Start with the largest packet
        let mut current_start = packets[0];
        let mut current_end = packets[0];
        let mut first_ack_range = 0;
        let mut is_first_range = true;
        
        for i in 1..packets.len() {
            let pn = packets[i];
            
            if pn == current_start - 1 {
                // Extend current range downward
                current_start = pn;
            } else {
                // Gap found, close current range
                let range_length = current_end - current_start;
                
                if is_first_range {
                    // This is the first ACK range
                    first_ack_range = range_length;
                    is_first_range = false;
                } else {
                    // Calculate gap: number of missing packets between ranges
                    // Gap is from the END of the new range to the START of the previous range
                    let gap = current_start - pn - 1;
                    ranges.push(AckRange { gap, ack_range_length: range_length });
                }
                
                // Start new range
                current_start = pn;
                current_end = pn;
                
                // Limit number of ranges
                if ranges.len() >= MAX_ACK_RANGES {
                    break;
                }
            }
        }
        
        // Handle the last range if we haven't set first_ack_range yet
        if is_first_range {
            first_ack_range = current_end - current_start;
        } else if ranges.len() < MAX_ACK_RANGES {
            // Add the final range
            let range_length = current_end - current_start;
            // Gap is calculated from the start of this range to the end of previous range
            // Since we're going in descending order, we need to find the previous range's start
            let prev_range_start = if ranges.is_empty() {
                largest_acked - first_ack_range
            } else {
                // Work backwards to find the start of the previous range
                let mut pos = largest_acked - first_ack_range;
                for r in &ranges {
                    pos -= r.gap + 1 + r.ack_range_length;
                }
                pos
            };
            let gap = prev_range_start - current_end - 1;
            ranges.push(AckRange { gap, ack_range_length: range_length });
        }

        (first_ack_range, ranges)
    }

    /// Check if we have ECN counts to report
    fn has_ecn_counts(&self) -> bool {
        self.ecn_counts.ect0 > 0 || self.ecn_counts.ect1 > 0 || self.ecn_counts.ecn_ce > 0
    }

    /// Update ECN counts for a received packet
    pub fn update_ecn_counts(&mut self, ect0: bool, ect1: bool, ce: bool) {
        if ect0 {
            self.ecn_counts.ect0 += 1;
        }
        if ect1 {
            self.ecn_counts.ect1 += 1;
        }
        if ce {
            self.ecn_counts.ecn_ce += 1;
        }
    }

    /// Clear old packet numbers to limit memory usage
    pub fn cleanup_old_packets(&mut self, threshold: u64) {
        if let Some(largest) = self.largest_received {
            // Keep only recent packet numbers
            self.received_packets.retain(|&pn| pn > largest.saturating_sub(threshold));
        }
    }

    /// Get the largest acknowledged packet number
    pub fn largest_acknowledged(&self) -> Option<u64> {
        self.largest_received
    }

    /// Reset the ACK manager
    pub fn reset(&mut self) {
        self.received_packets.clear();
        self.largest_received = None;
        self.largest_received_time = None;
        self.ack_eliciting_count = 0;
        self.first_ack_eliciting_time = None;
        self.needs_ack = false;
        self.ecn_counts = EcnCounts { ect0: 0, ect1: 0, ecn_ce: 0 };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ack_generation_single_packet() {
        let mut manager = AckManager::new(PacketNumberSpace::ApplicationData);
        let now = Instant::now();
        
        // Receive a single packet
        manager.on_packet_received(5, true, now);
        
        // Should not need immediate ACK (threshold not reached)
        assert!(!manager.needs_ack);
        
        // But should need ACK after delay
        let later = now + MAX_ACK_DELAY + Duration::from_millis(1);
        assert!(manager.should_send_ack(later));
        
        // Generate ACK frame
        let ack_frame = manager.generate_ack_frame(later).unwrap();
        if let Frame::Ack { largest_acknowledged, first_ack_range, ack_ranges, .. } = ack_frame {
            assert_eq!(largest_acknowledged, 5);
            assert_eq!(first_ack_range, 0); // Single packet
            assert!(ack_ranges.is_empty());
        } else {
            panic!("Expected ACK frame");
        }
    }

    #[test]
    fn test_ack_generation_multiple_ranges() {
        let mut manager = AckManager::new(PacketNumberSpace::ApplicationData);
        let now = Instant::now();
        
        // Receive packets with gaps: 1, 2, 3, 5, 6, 9
        manager.on_packet_received(1, true, now);
        manager.on_packet_received(2, true, now);
        manager.on_packet_received(3, true, now);
        manager.on_packet_received(5, true, now);
        manager.on_packet_received(6, true, now);
        manager.on_packet_received(9, true, now);
        
        // Generate ACK frame
        let ack_frame = manager.generate_ack_frame(now).unwrap();
        if let Frame::Ack { largest_acknowledged, first_ack_range, ack_ranges, .. } = ack_frame {
            assert_eq!(largest_acknowledged, 9);
            
            // We have packets: 1,2,3,5,6,9
            // ACK frame represents: [9], gap 1, [6,5], gap 2, [3,2,1]
            assert_eq!(largest_acknowledged, 9);
            assert_eq!(first_ack_range, 0); // Just packet 9
            assert_eq!(ack_ranges.len(), 2);
            
            // First additional range: gap of 1 (packet 7 missing), then [6,5] (length 1)
            assert_eq!(ack_ranges[0].gap, 1);
            assert_eq!(ack_ranges[0].ack_range_length, 1);
            
            // Second additional range: gap of 2 (packets 4,3 missing), then [3,2,1] (length 2)  
            assert_eq!(ack_ranges[1].gap, 2);
            assert_eq!(ack_ranges[1].ack_range_length, 2);
        } else {
            panic!("Expected ACK frame");
        }
    }

    #[test]
    fn test_immediate_ack_threshold() {
        let mut manager = AckManager::new(PacketNumberSpace::ApplicationData);
        let now = Instant::now();
        
        // First ack-eliciting packet
        manager.on_packet_received(1, true, now);
        assert!(!manager.needs_ack);
        
        // Second ack-eliciting packet - should trigger immediate ACK
        manager.on_packet_received(2, true, now);
        assert!(manager.needs_ack);
    }

    #[test]
    fn test_crypto_space_immediate_ack() {
        let mut manager = AckManager::new(PacketNumberSpace::Initial);
        let now = Instant::now();
        
        // Even one packet in Initial space should trigger immediate ACK
        manager.on_packet_received(0, true, now);
        assert!(manager.needs_ack);
    }
}