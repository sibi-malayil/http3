//! QUIC loss detection and recovery implementation
//!
//! Implements loss detection and recovery according to RFC 9002.

use crate::{
    quic::{
        packet::{Packet, PacketType},
        frame_types::Frame,
        congestion::CongestionController,
        ack_manager::AckManager,
    },
    util::time::{Duration, Instant},
    whathappened::Level,
    {perf_event, span},
};
use std::collections::BTreeMap;

// RFC 9002 Constants
/// Timer granularity per RFC 9002 (1ms)
const K_GRANULARITY: Duration = Duration::from_millis(1);

/// Initial RTT per RFC 9002 (333ms)
const K_INITIAL_RTT: Duration = Duration::from_millis(333);

/// Packet threshold for loss detection per RFC 9002 (3 packets)
const K_PACKET_THRESHOLD: u64 = 3;

/// Time reordering threshold per RFC 9002 (9/8)
const K_TIME_THRESHOLD_NUMERATOR: u32 = 9;
const K_TIME_THRESHOLD_DENOMINATOR: u32 = 8;

/// OWASP Security: Maximum lost frames to prevent memory exhaustion
const MAX_LOST_FRAMES: usize = 1000;

/// Packet number space as defined in RFC 9002 Section 6
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketNumberSpace {
    /// Initial packet number space
    Initial,
    /// Handshake packet number space
    Handshake,
    /// Application data packet number space
    ApplicationData,
}

impl From<PacketType> for PacketNumberSpace {
    fn from(packet_type: PacketType) -> Self {
        match packet_type {
            PacketType::Initial => PacketNumberSpace::Initial,
            PacketType::Handshake => PacketNumberSpace::Handshake,
            PacketType::ZeroRtt | PacketType::OneRtt => PacketNumberSpace::ApplicationData,
            PacketType::Retry => PacketNumberSpace::Initial, // Retry doesn't have packet number
        }
    }
}

/// Information about a sent packet
#[derive(Debug, Clone)]
struct SentPacket {
    /// Packet number
    packet_number: u64,
    /// Time when packet was sent
    sent_time: Instant,
    /// Size of the packet in bytes
    size: usize,
    /// Whether the packet is ack-eliciting
    ack_eliciting: bool,
    /// Whether the packet contains only ACK frames
    ack_only: bool,
    /// Frames contained in the packet for retransmission
    frames: Vec<Frame>,
    /// Packet number space
    pn_space: PacketNumberSpace,
}

/// Per packet number space state
#[derive(Debug)]
struct PacketNumberSpaceData {
    /// Packets sent but not yet acknowledged
    sent_packets: BTreeMap<u64, SentPacket>,
    /// Largest acknowledged packet number
    largest_acked: Option<u64>,
    /// Time of last ack-eliciting packet sent
    last_ack_eliciting_sent: Option<Instant>,
    /// Number of ack-eliciting packets in flight
    ack_eliciting_in_flight: u32,
    /// Total bytes in flight
    bytes_in_flight: usize,
}

impl PacketNumberSpaceData {
    fn new() -> Self {
        Self {
            sent_packets: BTreeMap::new(),
            largest_acked: None,
            last_ack_eliciting_sent: None,
            ack_eliciting_in_flight: 0,
            bytes_in_flight: 0,
        }
    }
}

/// RTT estimation following RFC 9002 Section 5
#[derive(Debug, Clone)]
struct RttEstimator {
    /// Smoothed RTT
    smoothed_rtt: Duration,
    /// RTT variation
    rtt_var: Duration,
    /// Minimum RTT observed
    min_rtt: Duration,
    /// Latest RTT sample
    latest_rtt: Option<Duration>,
    /// First RTT sample flag
    first_rtt_sample: bool,
    /// ACK delay exponent from transport parameters
    ack_delay_exponent: u8,
    /// Maximum ACK delay from transport parameters
    max_ack_delay: Duration,
}

impl RttEstimator {
    fn new() -> Self {
        Self {
            smoothed_rtt: K_INITIAL_RTT,                    // RFC 9002: 333ms
            rtt_var: K_INITIAL_RTT / 2,                    // RFC 9002: 166ms
            min_rtt: Duration::MAX,
            latest_rtt: None,
            first_rtt_sample: true,
            ack_delay_exponent: 3,                         // RFC 9000 default
            max_ack_delay: Duration::from_millis(25),      // RFC 9000 default
        }
    }

    /// Update RTT estimates per RFC 9002 Section 5
    fn update_rtt(&mut self, latest_rtt: Duration, ack_delay: Duration) {
        // RFC 9002 Section 5.1: RTT Sample
        self.latest_rtt = Some(latest_rtt);
        
        // RFC 9002 Section 5.2: min_rtt ignores ack delay
        let old_min_rtt = self.min_rtt;
        self.min_rtt = self.min_rtt.min(latest_rtt);
        
        perf_event!(
            Level::Debug,
            "RTT sample received";
            "latest_rtt_us" => latest_rtt.as_micros(),
            "ack_delay_us" => ack_delay.as_micros(),
            "min_rtt_us" => self.min_rtt.as_micros(),
            "min_rtt_updated" => (self.min_rtt < old_min_rtt)
        );

        // RFC 9002 Section 5.3: First RTT sample
        if self.first_rtt_sample {
            self.smoothed_rtt = latest_rtt;
            self.rtt_var = latest_rtt / 2;
            self.first_rtt_sample = false;
            
            perf_event!(
                Level::Info,
                "First RTT sample established";
                "smoothed_rtt_us" => self.smoothed_rtt.as_micros(),
                "rtt_var_us" => self.rtt_var.as_micros()
            );
            return;
        }

        // RFC 9002 Section 5.3: Estimating smoothed_rtt and rttvar
        // adjusted_rtt = latest_rtt
        // if (latest_rtt >= min_rtt + ack_delay):
        //   adjusted_rtt = latest_rtt - ack_delay
        let adjusted_rtt = if latest_rtt >= self.min_rtt.saturating_add(ack_delay) {
            latest_rtt.saturating_sub(ack_delay)
        } else {
            latest_rtt
        };

        // RFC 9002: smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt
        self.smoothed_rtt = self.smoothed_rtt
            .saturating_mul(7)
            .saturating_add(adjusted_rtt)
            .checked_div(8)
            .unwrap_or(self.smoothed_rtt);

        // RFC 9002: rttvar_sample = abs(smoothed_rtt - adjusted_rtt)
        let rtt_var_sample = if self.smoothed_rtt > adjusted_rtt {
            self.smoothed_rtt - adjusted_rtt
        } else {
            adjusted_rtt - self.smoothed_rtt
        };

        // RFC 9002: rttvar = 3/4 * rttvar + 1/4 * rttvar_sample
        let old_rtt_var = self.rtt_var;
        self.rtt_var = self.rtt_var
            .saturating_mul(3)
            .saturating_add(rtt_var_sample)
            .checked_div(4)
            .unwrap_or(self.rtt_var);
        
        perf_event!(
            Level::Debug,
            "RTT estimates updated";
            "adjusted_rtt_us" => adjusted_rtt.as_micros(),
            "smoothed_rtt_us" => self.smoothed_rtt.as_micros(),
            "rtt_var_us" => self.rtt_var.as_micros(),
            "old_rtt_var_us" => old_rtt_var.as_micros(),
            "rtt_var_change_us" => (self.rtt_var.as_micros() as i128 - old_rtt_var.as_micros() as i128),
            "rtt_var_sample_us" => rtt_var_sample.as_micros()
        );
    }

    /// Get the current RTT estimate
    fn rtt(&self) -> Duration {
        self.smoothed_rtt
    }

    /// Calculate probe timeout per RFC 9002 Section 6.2
    fn probe_timeout(&self) -> Duration {
        // RFC 9002 Section 6.2.1:
        // PTO = smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
        let granularity = Duration::from_millis(1);
        self.smoothed_rtt
            .saturating_add(self.rtt_var.saturating_mul(4).max(granularity))
            .saturating_add(self.max_ack_delay)
    }

    /// Probe timeout for specific packet number space per RFC 9002 Section 6.2.1
    /// max_ack_delay MUST be 0 for Initial and Handshake spaces
    pub fn probe_timeout_for_space(&self, space: PacketNumberSpace) -> Duration {
        let granularity = K_GRANULARITY;
        let base_pto = self.smoothed_rtt
            .saturating_add(self.rtt_var.saturating_mul(4).max(granularity));
        
        match space {
            PacketNumberSpace::Initial | PacketNumberSpace::Handshake => {
                // RFC 9002 Section 6.2.1: max_ack_delay = 0 for Initial/Handshake
                base_pto
            }
            PacketNumberSpace::ApplicationData => {
                // Include max_ack_delay for Application Data
                base_pto.saturating_add(self.max_ack_delay)
            }
        }
    }
}

/// Loss recovery manager implementing RFC 9002 algorithms
pub struct RecoveryManager {
    /// Per packet number space data
    spaces: [PacketNumberSpaceData; 3],
    /// ACK managers for each packet number space
    ack_managers: [AckManager; 3],
    /// Round-trip time estimator
    rtt_estimator: RttEstimator,
    /// Loss detection timer
    loss_detection_timer: Option<Instant>,
    /// Probe timeout backoff
    pto_count: u32,
    /// Total packets sent
    packets_sent_count: u64,
    /// Total packets received  
    packets_recv_count: u64,
    /// Time threshold for loss detection (RFC 9002 Section 6.1.2)
    time_reordering_fraction: u32, // Default 9/8
    /// Packet threshold for loss detection (RFC 9002 Section 6.1.1) 
    packet_reordering_threshold: u64, // Default 3
    /// Whether we're using time-based loss detection
    using_time_loss_detection: bool,
    /// RFC 9002 Section 6.2.2: Handshake completion detection
    handshake_confirmed: bool,
    /// When handshake was confirmed
    handshake_completion_time: Option<Instant>,
    /// RFC 9002 Section 8.1: Anti-amplification protection
    bytes_sent: u64,
    /// Bytes received from peer (for anti-amplification)
    bytes_received: u64,
    /// Whether peer address is validated
    address_validated: bool,
    /// Congestion controller
    congestion_controller: CongestionController,
}

impl RecoveryManager {
    /// Create a new recovery manager
    pub fn new() -> Self {
        Self {
            spaces: [
                PacketNumberSpaceData::new(),
                PacketNumberSpaceData::new(),
                PacketNumberSpaceData::new(),
            ],
            ack_managers: [
                AckManager::new(PacketNumberSpace::Initial),
                AckManager::new(PacketNumberSpace::Handshake),
                AckManager::new(PacketNumberSpace::ApplicationData),
            ],
            rtt_estimator: RttEstimator::new(),
            loss_detection_timer: None,
            pto_count: 0,
            packets_sent_count: 0,
            packets_recv_count: 0,
            time_reordering_fraction: K_TIME_THRESHOLD_NUMERATOR,
            packet_reordering_threshold: K_PACKET_THRESHOLD,
            using_time_loss_detection: true,
            handshake_confirmed: false,
            handshake_completion_time: None,
            bytes_sent: 0,
            bytes_received: 0,
            address_validated: false,
            congestion_controller: CongestionController::new(),
        }
    }

    /// Get packet number space index
    fn space_index(space: PacketNumberSpace) -> usize {
        match space {
            PacketNumberSpace::Initial => 0,
            PacketNumberSpace::Handshake => 1,
            PacketNumberSpace::ApplicationData => 2,
        }
    }

    /// Record a packet being sent
    pub fn on_packet_sent(
        &mut self, 
        packet: &Packet,
        frames: Vec<Frame>,
    ) {
        let packet_number = match packet.header().packet_number() {
            Some(pn) => pn as u64,
            None => {
                // Retry packets don't have packet numbers
                return;
            }
        };
        let packet_size = packet.payload().len();
        let packet_type = packet.header().packet_type();
        let sent_time = Instant::now();
        let pn_space = PacketNumberSpace::from(packet_type);
        let ack_eliciting = self.is_ack_eliciting(&frames);
        let ack_only = frames.iter().all(|f| matches!(f, Frame::Ack { .. }));
        
        perf_event!(
            Level::Debug,
            "Packet sent";
            "packet_number" => packet_number,
            "packet_size" => packet_size,
            "ack_eliciting" => ack_eliciting,
            "pn_space" => pn_space,
            "frame_count" => frames.len()
        );
        
        let sent_packet = SentPacket {
            packet_number,
            sent_time,
            size: packet_size,
            ack_eliciting,
            ack_only,
            frames,
            pn_space,
        };

        let space_idx = Self::space_index(pn_space);
        let space = &mut self.spaces[space_idx];
        
        if ack_eliciting {
            space.ack_eliciting_in_flight += 1;
            space.last_ack_eliciting_sent = Some(sent_time);
        }
        
        space.bytes_in_flight += sent_packet.size;
        space.sent_packets.insert(packet_number, sent_packet);
        
        self.packets_sent_count += 1;
        
        // Set loss detection timer
        self.set_loss_detection_timer();
    }

    /// Process received acknowledgment per RFC 9002 Section 6
    /// 
    /// # Security Considerations (OWASP)
    /// - Validates input ranges to prevent integer overflow
    /// - Limits processing to prevent DoS attacks
    /// - Ensures ack_delay is within acceptable bounds
    pub fn on_ack_received(
        &mut self, 
        pn_space: PacketNumberSpace,
        largest_acked: u64,
        ack_ranges: &[(u64, u64)], 
        ack_delay: Duration
    ) -> Result<Vec<Frame>, crate::error::Error> {
        let _span = span!(Level::Debug, "on_ack_received", pn_space = pn_space, largest_acked = largest_acked);
        
        perf_event!(
            Level::Debug,
            "ACK received";
            "pn_space" => pn_space,
            "largest_acked" => largest_acked,
            "ack_ranges_count" => ack_ranges.len(),
            "ack_delay_us" => ack_delay.as_micros()
        );
        
        // OWASP: Input validation
        if ack_ranges.len() > 64 {  // RFC 9000 Section 19.3.1: max 64 ACK ranges
            return Err(crate::error::Error::ProtocolViolation(
                "Too many ACK ranges".to_string()
            ));
        }
        
        // Validate ranges are ordered and non-overlapping
        let mut prev_start = None;
        for &(start, end) in ack_ranges {
            if start > end {
                return Err(crate::error::Error::ProtocolViolation(
                    "Invalid ACK range: start > end".to_string()
                ));
            }
            // RFC 9000: ACK ranges must be in descending order (higher packet numbers first)
            if let Some(prev) = prev_start {
                if start >= prev {
                    return Err(crate::error::Error::ProtocolViolation(
                        "ACK ranges not in descending order".to_string()
                    ));
                }
            }
            prev_start = Some(start);
        }
        let now = Instant::now();
        let space_idx = Self::space_index(pn_space);
        let space = &mut self.spaces[space_idx];
        
        // RFC 9002 Section 6.1: Update largest acknowledged
        // OWASP: Validate monotonic increase
        if let Some(prev_largest) = space.largest_acked {
            if largest_acked < prev_largest {
                return Err(crate::error::Error::ProtocolViolation(
                    "Largest acknowledged decreased".to_string()
                ));
            }
        }
        space.largest_acked = Some(largest_acked);
        
        let mut newly_acked_packets = Vec::new();
        let mut lost_frames = Vec::new();

        // RFC 9002 Section 6: Process acknowledgments
        for &(start, end) in ack_ranges {
            // OWASP: Prevent DoS by limiting range size
            if end - start > 1000 {
                return Err(crate::error::Error::ProtocolViolation(
                    "ACK range too large".to_string()
                ));
            }
            
            for pn in start..=end {
                if let Some(packet) = space.sent_packets.remove(&pn) {
                    if packet.ack_eliciting {
                        space.ack_eliciting_in_flight = space.ack_eliciting_in_flight.saturating_sub(1);
                    }
                    space.bytes_in_flight = space.bytes_in_flight.saturating_sub(packet.size);
                    newly_acked_packets.push(packet);
                }
            }
        }

        if !newly_acked_packets.is_empty() {
            // RFC 9002 Section 5.1: RTT Sample
            // Find the latest acknowledged packet that was ack-eliciting
            if let Some(latest_packet) = newly_acked_packets.iter()
                .filter(|p| p.ack_eliciting)
                .max_by_key(|p| p.packet_number) 
            {
                let latest_rtt = now.duration_since(latest_packet.sent_time);
                
                // RFC 9002 Section 5.3: ACK Delay Decoding
                let ack_delay_decoded = if pn_space == PacketNumberSpace::ApplicationData {
                    let exponent = self.rtt_estimator.ack_delay_exponent;
                    // OWASP: Prevent overflow in shift operation
                    if exponent > 20 {
                        return Err(crate::error::Error::ProtocolViolation(
                            "ACK delay exponent too large".to_string()
                        ));
                    }
                    let multiplier = 1u64.checked_shl(exponent as u32).unwrap_or(u64::MAX);
                    Duration::from_micros(
                        ack_delay.as_micros().saturating_mul(multiplier as u128) as u64
                    ).min(self.rtt_estimator.max_ack_delay)
                } else {
                    // RFC 9002: ACK delay is 0 for Initial and Handshake
                    Duration::ZERO
                };
                
                self.rtt_estimator.update_rtt(latest_rtt, ack_delay_decoded);
            }

            // RFC 9002 Section 6.2.1: Reset PTO count
            self.pto_count = 0;

            // Notify congestion controller of acknowledgment
            let _ = self.congestion_controller.on_ack_received(ack_ranges);

            // RFC 9002 Section 6.1: Detect lost packets
            lost_frames.extend(self.detect_lost_packets(pn_space)?);
        }

        // RFC 9002 Section 6.2: Update loss detection timer
        self.set_loss_detection_timer();
        Ok(lost_frames)
    }

    /// Process a received packet
    pub fn on_packet_received(
        &mut self, 
        packet_number: u64,
        packet_type: crate::quic::packet::PacketType,
        ack_eliciting: bool,
        received_time: Instant,
    ) {
        self.packets_recv_count += 1;
        let pn_space = PacketNumberSpace::from(packet_type);
        let space_idx = Self::space_index(pn_space);
        let space_data = &mut self.spaces[space_idx];
        
        // Update largest acknowledged for this space
        if packet_number > space_data.largest_acked.unwrap_or(0) {
            space_data.largest_acked = Some(packet_number);
        }
        
        // Track in ACK manager
        self.ack_managers[space_idx].on_packet_received(packet_number, ack_eliciting, received_time);
        
        // Note: RTT is updated when we receive ACKs for sent packets,
        // not when we receive packets. This is just tracking receipt.
    }

    /// Check for loss detection timeout and return frames to retransmit
    pub fn check_loss_detection(&mut self) -> Option<Vec<Frame>> {
        if let Some(timer) = self.loss_detection_timer {
            if Instant::now() >= timer {
                perf_event!(
                    Level::Warn,
                    "Loss detection timeout triggered";
                    "pto_count" => self.pto_count,
                    "rtt_us" => self.rtt_estimator.smoothed_rtt.as_micros()
                );
                return Some(self.on_loss_detection_timeout());
            }
        }
        None
    }

    /// Handle loss detection timeout with enhanced retransmission logic
    fn on_loss_detection_timeout(&mut self) -> Vec<Frame> {
        let mut probe_frames = Vec::new();
        
        // Find the packet number space with in-flight data
        let earliest_loss_time = self.get_earliest_loss_time();
        
        if earliest_loss_time.is_some() {
            // Time-based loss detection
            for space in PacketNumberSpace::Initial as u8..=PacketNumberSpace::ApplicationData as u8 {
                let pn_space = match space {
                    0 => PacketNumberSpace::Initial,
                    1 => PacketNumberSpace::Handshake,
                    2 => PacketNumberSpace::ApplicationData,
                    _ => continue,
                };
                match self.detect_lost_packets(pn_space) {
                    Ok(frames) => {
                        // Prioritize frames for retransmission
                        let prioritized_frames = self.prioritize_frames_for_retransmission(frames);
                        probe_frames.extend(prioritized_frames);
                    },
                    Err(_) => {
                        // On error, skip this space and continue with other spaces
                    }
                }
            }
        } else {
            // PTO expired - send enhanced probe packets
            self.pto_count += 1;
            
            perf_event!(
                Level::Info,
                "PTO timeout - generating probe packets";
                "pto_count" => self.pto_count,
                "handshake_confirmed" => self.handshake_confirmed
            );
            
            // Use enhanced probe packet generation
            let enhanced_probes = self.generate_enhanced_probe_packets();
            for (_space, frames) in enhanced_probes {
                probe_frames.extend(frames);
            }
            
            // If no enhanced probes, fallback to simple PING
            if probe_frames.is_empty() && self.has_any_ack_eliciting_in_flight() {
                probe_frames.push(Frame::Ping);
            }
        }
        
        // OWASP: Limit probe frames to prevent memory exhaustion
        if probe_frames.len() > MAX_LOST_FRAMES {
            probe_frames.truncate(MAX_LOST_FRAMES);
        }

        self.set_loss_detection_timer();
        probe_frames
    }

    /// Enhanced probe packet generation per RFC 9002 Section 6.2.2
    /// Uses Rust 2024 edition features for cleaner code
    fn generate_enhanced_probe_packets(&mut self) -> Vec<(PacketNumberSpace, Vec<Frame>)> {
        let mut probe_packets = Vec::new();
        let mut probes_sent = 0;
        const MAX_PROBE_PACKETS: usize = 2; // RFC 9002: May send up to 2 probe packets
        
        // RFC 9002 Section 6.2.2: Priority order based on handshake state
        let spaces_to_check = if self.handshake_confirmed {
            [PacketNumberSpace::ApplicationData, PacketNumberSpace::Handshake, PacketNumberSpace::Initial]
        } else {
            [PacketNumberSpace::Handshake, PacketNumberSpace::Initial, PacketNumberSpace::ApplicationData]
        };
        
        for space in spaces_to_check {
            let space_idx = Self::space_index(space);
            let space_data = &self.spaces[space_idx];
            
            // Check conditions for sending probe packets
            if space_data.ack_eliciting_in_flight > 0 && probes_sent < MAX_PROBE_PACKETS {
                let frames = self.create_probe_frames_for_space(space);
                if !frames.is_empty() {
                    probe_packets.push((space, frames));
                    probes_sent += 1;
                }
            }
        }
        
        // Ensure at least one probe packet if we have any in-flight data
        if probe_packets.is_empty() && self.has_any_ack_eliciting_in_flight() {
            probe_packets.push((PacketNumberSpace::ApplicationData, vec![Frame::Ping]));
        }
        
        probe_packets
    }

    /// Create probe frames for a specific packet number space with enhanced logic
    fn create_probe_frames_for_space(&self, space: PacketNumberSpace) -> Vec<Frame> {
        let mut frames = Vec::new();
        let space_idx = Self::space_index(space);
        let space_data = &self.spaces[space_idx];
        
        match space {
            PacketNumberSpace::Initial | PacketNumberSpace::Handshake => {
                // RFC 9002: For Initial/Handshake, prioritize CRYPTO frames
                if let Some(crypto_frame) = self.find_crypto_frame_to_retransmit(space_data) {
                    frames.push(crypto_frame);
                }
                // Always include PING to ensure ack-eliciting
                frames.push(Frame::Ping);
            }
            PacketNumberSpace::ApplicationData => {
                // RFC 9002: For Application Data, include new data if available
                // For now, just use PING - in full implementation would check for new data
                frames.push(Frame::Ping);
                
                // Retransmit important STREAM frames with reassembly
                let stream_frames = self.find_stream_frames_to_retransmit(space_data);
                frames.extend(stream_frames);
                
                // Add connection-level frames if needed
                if let Some(flow_control_frame) = self.find_flow_control_frame_to_retransmit(space_data) {
                    frames.push(flow_control_frame);
                }
            }
        }
        
        frames
    }

    /// Find CRYPTO frame suitable for retransmission
    fn find_crypto_frame_to_retransmit(&self, space_data: &PacketNumberSpaceData) -> Option<Frame> {
        // Find the most recent CRYPTO frame
        space_data.sent_packets.values()
            .rev() // Start from most recent
            .flat_map(|packet| &packet.frames)
            .find(|frame| matches!(frame, Frame::Crypto { .. }))
            .cloned()
    }

    /// Find STREAM frame suitable for retransmission  
    fn find_stream_frame_to_retransmit(&self, space_data: &PacketNumberSpaceData) -> Option<Frame> {
        // Find a STREAM frame with data
        space_data.sent_packets.values()
            .rev() // Start from most recent
            .flat_map(|packet| &packet.frames)
            .find(|frame| {
                matches!(frame, Frame::Stream { data, .. } if !data.is_empty())
            })
            .cloned()
    }
    
    /// Find multiple STREAM frames suitable for retransmission with reassembly
    fn find_stream_frames_to_retransmit(&self, space_data: &PacketNumberSpaceData) -> Vec<Frame> {
        let mut stream_frames = Vec::new();
        let mut seen_streams = std::collections::HashSet::new();
        
        // Collect STREAM frames, prioritizing recent ones and avoiding duplicates per stream
        for packet in space_data.sent_packets.values().rev() {
            for frame in &packet.frames {
                if let Frame::Stream { stream_id, data, fin, .. } = frame {
                    if !data.is_empty() && seen_streams.insert(*stream_id) {
                        // Prioritize FIN frames and frames with significant data
                        if *fin || data.len() > 100 {
                            stream_frames.push(frame.clone());
                        }
                    }
                }
            }
            // Limit to prevent excessive retransmissions
            if stream_frames.len() >= 5 {
                break;
            }
        }
        
        stream_frames
    }
    
    /// Find flow control frames suitable for retransmission
    fn find_flow_control_frame_to_retransmit(&self, space_data: &PacketNumberSpaceData) -> Option<Frame> {
        // Find important flow control frames
        space_data.sent_packets.values()
            .rev()
            .flat_map(|packet| &packet.frames)
            .find(|frame| {
                matches!(frame, 
                    Frame::MaxData { .. } | 
                    Frame::MaxStreamData { .. } | 
                    Frame::MaxStreams { .. } |
                    Frame::DataBlocked { .. } |
                    Frame::StreamDataBlocked { .. } |
                    Frame::StreamsBlocked { .. }
                )
            })
            .cloned()
    }

    /// Check if any packet number space has ack-eliciting packets in flight
    fn has_any_ack_eliciting_in_flight(&self) -> bool {
        self.spaces.iter().any(|space| space.ack_eliciting_in_flight > 0)
    }

    /// Detect lost packets using time and packet thresholds per RFC 9002 Section 6.1
    /// Enhanced with better frame filtering and prioritization
    /// 
    /// # Security Considerations (OWASP)
    /// - Prevents memory exhaustion by limiting frame collection
    /// - Uses saturating arithmetic to prevent overflows
    fn detect_lost_packets(&mut self, pn_space: PacketNumberSpace) -> Result<Vec<Frame>, crate::error::Error> {
        let _span = span!(Level::Debug, "detect_lost_packets", pn_space = pn_space);
        let now = Instant::now();
        let space_idx = Self::space_index(pn_space);
        let space = &mut self.spaces[space_idx];
        
        let largest_acked = match space.largest_acked {
            Some(la) => la,
            None => return Ok(Vec::new()),
        };
        
        // RFC 9002 Section 6.1.2: Calculate loss delay
        let loss_delay = if self.using_time_loss_detection {
            let rtt = self.rtt_estimator.rtt();
            // RFC 9002: time_threshold = max(9/8 * max(smoothed_rtt, latest_rtt), granularity)
            
            rtt.saturating_mul(self.time_reordering_fraction)
                .checked_div(K_TIME_THRESHOLD_DENOMINATOR)
                .unwrap_or(K_GRANULARITY)
                .max(K_GRANULARITY)
        } else {
            Duration::MAX
        };
        
        let mut lost_frames = Vec::new();
        let mut lost_packets = Vec::new();
        
        // OWASP: Limit frames to prevent memory exhaustion
        const MAX_LOST_FRAMES: usize = 1000;
        
        // RFC 9002 Section 6.1: Check each unacknowledged packet
        for (&pn, packet) in space.sent_packets.iter() {
            if pn > largest_acked {
                continue;
            }
            
            let time_since_sent = now.duration_since(packet.sent_time);
            
            // RFC 9002 Section 6.1: A packet is declared lost if:
            // 1. It was sent kTimeThreshold before largest acknowledged packet
            // 2. It is kPacketThreshold older than largest acknowledged packet
            let time_threshold_loss = time_since_sent > loss_delay;
            let packet_threshold_loss = largest_acked.saturating_sub(pn) >= self.packet_reordering_threshold;
            
            if time_threshold_loss || packet_threshold_loss {
                lost_packets.push(pn);
                
                // RFC 9002: Collect frames for retransmission with enhanced filtering
                for frame in &packet.frames {
                    if Self::should_retransmit_frame_static(frame) {
                        if lost_frames.len() >= MAX_LOST_FRAMES {
                            return Err(crate::error::Error::Internal(
                                "Too many lost frames".to_string()
                            ));
                        }
                        lost_frames.push(frame.clone());
                    }
                }
            }
        }
        
        // RFC 9002 Section 6.1.1: Remove lost packets from in-flight
        for pn in lost_packets {
            if let Some(packet) = space.sent_packets.remove(&pn) {
                if packet.ack_eliciting {
                    space.ack_eliciting_in_flight = space.ack_eliciting_in_flight.saturating_sub(1);
                }
                space.bytes_in_flight = space.bytes_in_flight.saturating_sub(packet.size);
                
                perf_event!(
                    Level::Warn,
                    "Packet declared lost";
                    "packet_number" => pn,
                    "pn_space" => pn_space,
                    "packet_size" => packet.size,
                    "time_since_sent_ms" => now.duration_since(packet.sent_time).as_millis()
                );

                // RFC 9002: Inform congestion controller of loss event
                let _ = self.congestion_controller.on_packet_lost(packet.size as u64);
            }
        }
        
        if !lost_frames.is_empty() {
            perf_event!(
                Level::Info,
                "Packets lost - frames to retransmit";
                "pn_space" => pn_space,
                "lost_frame_count" => lost_frames.len()
            );
        }
        
        Ok(lost_frames)
    }
    
    /// Enhanced frame filtering for retransmission eligibility
    fn should_retransmit_frame_static(frame: &Frame) -> bool {
        match frame {
            // Never retransmit ACK or PADDING frames
            Frame::Ack { .. } | Frame::Padding => false,
            
            // Always retransmit CRYPTO frames (handshake data)
            Frame::Crypto { .. } => true,
            
            // Retransmit STREAM frames with data or FIN
            Frame::Stream { data, fin, .. } => !data.is_empty() || *fin,
            
            // Retransmit important connection control frames
            Frame::MaxData { .. } | Frame::MaxStreamData { .. } | Frame::MaxStreams { .. } => true,
            
            // Retransmit blocking signals
            Frame::DataBlocked { .. } | Frame::StreamDataBlocked { .. } | Frame::StreamsBlocked { .. } => true,
            
            // Retransmit stream control frames
            Frame::ResetStream { .. } | Frame::StopSending { .. } => true,
            
            // Retransmit connection management frames
            Frame::NewConnectionId { .. } | Frame::RetireConnectionId { .. } => true,
            
            // Retransmit path validation frames
            Frame::PathChallenge { .. } | Frame::PathResponse { .. } => true,
            
            // Always retransmit connection close and handshake done
            Frame::ConnectionClose { .. } | Frame::HandshakeDone => true,
            
            // Retransmit tokens and pings
            Frame::NewToken { .. } | Frame::Ping => true,
        }
    }
    
    /// Prioritize frames for retransmission based on importance
    fn prioritize_frames_for_retransmission(&self, frames: Vec<Frame>) -> Vec<Frame> {
        let mut prioritized = frames;
        
        // Sort frames by priority (higher priority first)
        prioritized.sort_by(|a, b| {
            self.get_frame_priority(a).cmp(&self.get_frame_priority(b)).reverse()
        });
        
        prioritized
    }
    
    /// Get priority score for frame type (higher = more important)
    fn get_frame_priority(&self, frame: &Frame) -> u8 {
        match frame {
            // Critical handshake data (highest priority)
            Frame::Crypto { .. } => 100,
            
            // Connection termination
            Frame::ConnectionClose { .. } => 90,
            
            // Handshake completion
            Frame::HandshakeDone => 85,
            
            // Stream control (high priority)
            Frame::ResetStream { .. } | Frame::StopSending { .. } => 80,
            
            // Stream data with FIN (important for connection cleanup)
            Frame::Stream { fin: true, .. } => 75,
            
            // Flow control updates
            Frame::MaxData { .. } | Frame::MaxStreamData { .. } | Frame::MaxStreams { .. } => 70,
            
            // Regular stream data
            Frame::Stream { .. } => 60,
            
            // Blocking signals
            Frame::DataBlocked { .. } | Frame::StreamDataBlocked { .. } | Frame::StreamsBlocked { .. } => 50,
            
            // Connection management
            Frame::NewConnectionId { .. } | Frame::RetireConnectionId { .. } => 40,
            
            // Path validation
            Frame::PathChallenge { .. } | Frame::PathResponse { .. } => 30,
            
            // Tokens and keepalives
            Frame::NewToken { .. } | Frame::Ping => 20,
            
            // Never retransmitted (lowest priority)
            Frame::Ack { .. } | Frame::Padding => 0,
        }
    }

    /// Get earliest time at which a packet should be declared lost
    fn get_earliest_loss_time(&self) -> Option<Instant> {
        let mut earliest_time = None;
        let loss_delay = self.rtt_estimator.rtt()
            .saturating_mul(self.time_reordering_fraction)
            .checked_div(K_TIME_THRESHOLD_DENOMINATOR)
            .unwrap_or(K_GRANULARITY)
            .max(K_GRANULARITY);
        
        for space in &self.spaces {
            if let Some(largest_acked) = space.largest_acked {
                for packet in space.sent_packets.values() {
                    if packet.packet_number > largest_acked {
                        continue;
                    }
                    
                    let loss_time = packet.sent_time + loss_delay;
                    earliest_time = match earliest_time {
                        None => Some(loss_time),
                        Some(t) => Some(t.min(loss_time)),
                    };
                }
            }
        }
        
        earliest_time
    }

    /// Set the loss detection timer per RFC 9002 Section 6.2
    fn set_loss_detection_timer(&mut self) {
        // RFC 9002 Section 6.2: Get earliest loss time
        let earliest_loss_time = self.get_earliest_loss_time();
        
        if let Some(loss_time) = earliest_loss_time {
            // Set timer for time-based loss detection
            self.loss_detection_timer = Some(loss_time);
            return;
        }
        
        // RFC 9002 Section 6.2.2: Check handshake confirmation for PTO behavior
        self.set_pto_timer();
    }

    /// Set PTO timer based on handshake state per RFC 9002 Section 6.2.2
    fn set_pto_timer(&mut self) {
        let mut earliest_sent_time = None;
        let mut pto_space = None;
        
        // RFC 9002 Section 6.2.2: Priority order for packet number spaces
        let spaces_to_check: &[PacketNumberSpace] = if self.handshake_confirmed {
            // After handshake confirmation, check all spaces
            &[PacketNumberSpace::Initial, PacketNumberSpace::Handshake, PacketNumberSpace::ApplicationData]
        } else {
            // Before handshake confirmation, check all spaces but prioritize Initial and Handshake
            &[PacketNumberSpace::Initial, PacketNumberSpace::Handshake, PacketNumberSpace::ApplicationData]
        };
        
        for &space in spaces_to_check {
            let space_idx = Self::space_index(space);
            let space_data = &self.spaces[space_idx];
            
            if space_data.ack_eliciting_in_flight > 0 {
                // Find earliest sent packet in this space
                if let Some((&_pn, packet)) = space_data.sent_packets.iter().next() {
                    if earliest_sent_time.is_none() || packet.sent_time < earliest_sent_time.unwrap() {
                        earliest_sent_time = Some(packet.sent_time);
                        pto_space = Some(space);
                    }
                }
            }
        }
        
        if let (Some(sent_time), Some(space)) = (earliest_sent_time, pto_space) {
            // RFC 9002 Section 6.2.1: Calculate PTO for specific space
            let pto = self.rtt_estimator.probe_timeout_for_space(space);
            let backoff = 2_u32.pow(self.pto_count);
            
            let timeout = sent_time + pto * backoff;
            self.loss_detection_timer = Some(timeout);
        } else {
            // No ack-eliciting packets in flight
            self.loss_detection_timer = None;
        }
    }

    /// Check if frames are ack-eliciting
    fn is_ack_eliciting(&self, frames: &[Frame]) -> bool {
        frames.iter().any(|frame| {
            !matches!(frame, 
                Frame::Ack { .. } | 
                Frame::Padding | 
                Frame::ConnectionClose { .. }
            )
        })
    }

    /// Check if we need to send ACK frames
    pub fn get_ack_frames(&mut self) -> Vec<Frame> {
        let now = Instant::now();
        let mut ack_frames = Vec::new();
        
        for (idx, ack_manager) in self.ack_managers.iter_mut().enumerate() {
            if ack_manager.should_send_ack(now) {
                if let Some(ack_frame) = ack_manager.generate_ack_frame(now) {
                    perf_event!(
                        Level::Debug,
                        "Generating ACK frame";
                        "space_index" => idx,
                        "packet_number_space" => match idx {
                            0 => "Initial",
                            1 => "Handshake",
                            2 => "Application",
                            _ => "Unknown"
                        }
                    );
                    ack_frames.push(ack_frame);
                }
            }
        }
        
        ack_frames
    }
    
    /// Generate ACK frame for a specific packet number space
    pub fn generate_ack_frame(&mut self, pn_space: PacketNumberSpace) -> Option<Frame> {
        let space_idx = Self::space_index(pn_space);
        self.ack_managers[space_idx].generate_ack_frame(Instant::now())
    }
    
    /// Discard state for a packet number space (e.g., after handshake completion)
    pub fn discard_space(&mut self, pn_space: PacketNumberSpace) {
        let space_idx = Self::space_index(pn_space);
        self.spaces[space_idx] = PacketNumberSpaceData::new();
        self.ack_managers[space_idx].reset();
        self.set_loss_detection_timer();
    }

    /// Get total packets sent
    pub fn packets_sent(&self) -> u64 {
        self.packets_sent_count
    }

    /// Get total packets received
    pub fn packets_recv(&self) -> u64 {
        self.packets_recv_count
    }
    
    /// Set ACK delay exponent from transport parameters
    pub fn set_ack_delay_exponent(&mut self, exponent: u8) {
        self.rtt_estimator.ack_delay_exponent = exponent;
    }
    
    /// Set maximum ACK delay from transport parameters
    pub fn set_max_ack_delay(&mut self, max_delay: Duration) {
        self.rtt_estimator.max_ack_delay = max_delay;
    }

    /// Get current RTT estimate
    pub fn rtt(&self) -> Duration {
        self.rtt_estimator.rtt()
    }

    /// Get current PTO value
    pub fn probe_timeout(&self) -> Duration {
        self.rtt_estimator.probe_timeout()
    }

    /// RFC 9002 Section 8.1: Anti-amplification protection
    /// Check if we can send a packet of given size without violating amplification limits
    pub fn can_send_packet(&self, packet_size: usize) -> bool {
        if self.address_validated {
            return true;
        }
        
        // RFC 9002 Section 8.1: Limit to 3x bytes received until address validated
        let amplification_limit = self.bytes_received * 3;
        self.bytes_sent + packet_size as u64 <= amplification_limit
    }

    /// Mark peer address as validated (e.g., after receiving a valid ACK)
    pub fn validate_address(&mut self) {
        self.address_validated = true;
    }
    
    /// Get current congestion window size
    pub fn congestion_window(&self) -> u64 {
        self.congestion_controller.congestion_window()
    }
    
    /// Get bytes in flight for congestion control
    pub fn bytes_in_flight(&self) -> u64 {
        self.spaces.iter().map(|space| space.bytes_in_flight as u64).sum()
    }
    
    /// Check if we can send a packet based on congestion control
    pub fn can_send_packet_cc(&self, packet_size: u64) -> bool {
        let bytes_in_flight = self.bytes_in_flight();
        let congestion_window = self.congestion_window();
        
        perf_event!(
            Level::Debug,
            "Checking congestion control";
            "bytes_in_flight" => bytes_in_flight,
            "congestion_window" => congestion_window,
            "packet_size" => packet_size,
            "can_send" => (bytes_in_flight + packet_size <= congestion_window)
        );
        
        bytes_in_flight + packet_size <= congestion_window
    }
    
    /// RFC 9002 Section 6.2.2: Mark handshake as confirmed
    pub fn confirm_handshake(&mut self) {
        if !self.handshake_confirmed {
            self.handshake_confirmed = true;
            self.handshake_completion_time = Some(Instant::now());
            
            perf_event!(
                Level::Info,
                "Handshake confirmed";
                "rtt_us" => self.rtt_estimator.smoothed_rtt.as_micros()
            );
            
            // RFC 9002: Reset loss detection timer when handshake confirmed
            self.set_loss_detection_timer();
        }
    }

    /// Check if handshake is confirmed
    pub fn is_handshake_confirmed(&self) -> bool {
        self.handshake_confirmed
    }

    /// Update bytes sent (for anti-amplification tracking)
    pub fn update_bytes_sent(&mut self, bytes: usize) {
        self.bytes_sent += bytes as u64;
    }

    /// Update bytes received (for anti-amplification tracking)
    pub fn update_bytes_received(&mut self, bytes: usize) {
        self.bytes_received += bytes as u64;
    }

    /// Get access to RTT estimator (for testing)
    #[cfg(test)]
    pub fn rtt_estimator(&self) -> &RttEstimator {
        &self.rtt_estimator
    }
    
    // Test-only method to access probe_timeout_for_space through rtt_estimator  
    #[cfg(test)]
    pub fn probe_timeout_for_space(&self, space: PacketNumberSpace) -> Duration {
        self.rtt_estimator.probe_timeout_for_space(space)
    }

    /// Get PTO count (for testing)
    #[cfg(test)]
    pub fn pto_count(&self) -> u32 {
        self.pto_count
    }

    /// Trigger loss detection timeout (for testing)
    #[cfg(test)]
    pub fn trigger_loss_detection_timeout(&mut self) -> Vec<Frame> {
        self.on_loss_detection_timeout()
    }

    /// Create probe frames for space (for testing)
    #[cfg(test)]
    pub fn create_probe_frames_for_space_test(&self, space: PacketNumberSpace) -> Vec<Frame> {
        self.create_probe_frames_for_space(space)
    }

    /// Generate enhanced probe packets (for testing)
    #[cfg(test)]
    pub fn generate_enhanced_probe_packets_test(&mut self) -> Vec<(PacketNumberSpace, Vec<Frame>)> {
        self.generate_enhanced_probe_packets()
    }


    /// Get statistics
    pub fn stats(&self) -> RecoveryStats {
        RecoveryStats {
            packets_sent: self.packets_sent_count,
            packets_recv: self.packets_recv_count,
            rtt: self.rtt_estimator.rtt(),
            rtt_var: self.rtt_estimator.rtt_var,
            min_rtt: self.rtt_estimator.min_rtt,
            latest_rtt: self.rtt_estimator.latest_rtt,
            pto_count: self.pto_count,
            bytes_in_flight: self.bytes_in_flight() as usize,
            ack_eliciting_in_flight: self.spaces.iter()
                .map(|s| s.ack_eliciting_in_flight)
                .sum(),
        }
    }
}

impl Default for RecoveryManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Recovery statistics
#[derive(Debug, Clone)]
pub struct RecoveryStats {
    /// Total packets sent
    pub packets_sent: u64,
    /// Total packets received
    pub packets_recv: u64,
    /// Smoothed round-trip time
    pub rtt: Duration,
    /// RTT variance
    pub rtt_var: Duration,
    /// Minimum RTT
    pub min_rtt: Duration,
    /// Latest RTT sample
    pub latest_rtt: Option<Duration>,
    /// PTO backoff count
    pub pto_count: u32,
    /// Total bytes in flight
    pub bytes_in_flight: usize,
    /// Number of ack-eliciting packets in flight
    pub ack_eliciting_in_flight: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        quic::packet::{ConnectionId, PacketHeader, ShortHeader},
        error::Result,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_packet_number_space_conversion() {
        assert_eq!(PacketNumberSpace::from(PacketType::Initial), PacketNumberSpace::Initial);
        assert_eq!(PacketNumberSpace::from(PacketType::Handshake), PacketNumberSpace::Handshake);
        assert_eq!(PacketNumberSpace::from(PacketType::ZeroRtt), PacketNumberSpace::ApplicationData);
        assert_eq!(PacketNumberSpace::from(PacketType::OneRtt), PacketNumberSpace::ApplicationData);
    }

    #[test] 
    fn test_rtt_estimation() {
        let mut estimator = RttEstimator::new();
        
        // First sample
        estimator.update_rtt(Duration::from_millis(100), Duration::ZERO);
        assert_eq!(estimator.smoothed_rtt, Duration::from_millis(100));
        assert_eq!(estimator.rtt_var, Duration::from_millis(50));
        
        // Second sample with higher RTT
        estimator.update_rtt(Duration::from_millis(150), Duration::ZERO);
        // Verify smoothing is applied
        assert!(estimator.smoothed_rtt > Duration::from_millis(100));
        assert!(estimator.smoothed_rtt < Duration::from_millis(150));
    }

    #[test]
    fn test_loss_detection_timer() -> Result<()> {
        let mut recovery = RecoveryManager::new();
        
        // Initially no timer
        assert!(recovery.loss_detection_timer.is_none());
        
        // Send a packet
        let header = PacketHeader::Short(ShortHeader::new(
            false,
            false, 
            ConnectionId::random(8)?,
            1,
        ));
        let packet = Packet::new(
            header,
            vec![0u8; 100].into(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081),
        );
        
        recovery.on_packet_sent(
            &packet,
            vec![Frame::Ping],
        );
        
        // Timer should be set
        assert!(recovery.loss_detection_timer.is_some());
        
        Ok(())
    }

    #[test]
    fn test_packet_loss_detection() -> Result<()> {
        let mut recovery = RecoveryManager::new();
        
        // Send multiple packets
        for i in 0..5 {
            let header = PacketHeader::Short(ShortHeader::new(
                false,
                false,
                ConnectionId::random(8)?,
                i,
            ));
            let packet = Packet::new(
                header,
                vec![0u8; 100].into(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081),
            );
            recovery.on_packet_sent(
                &packet,
                vec![Frame::Stream {
                    stream_id: 0.into(),
                    offset: 0,
                    data: vec![0u8; 100].into(),
                    fin: false,
                    length: None,
                }],
            );
        }
        
        // ACK packets 3 and 4, triggering loss of 0-1 by packet threshold
        let lost_frames = recovery.on_ack_received(
            PacketNumberSpace::ApplicationData,
            4,
            &[(3, 4)],
            Duration::ZERO,
        );
        
        // Should detect loss of packets 0-1 (packet threshold = 3)
        assert!(!lost_frames?.is_empty());
        
        Ok(())
    }
}