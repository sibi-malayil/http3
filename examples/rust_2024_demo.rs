//! Demonstration of Rust 2024 features used in the http3 crate

use http3::quic::transport::TransportParameters;
use http3::util::VarInt;

fn main() {
    // Create transport parameters for demonstration
    let mut params = TransportParameters::default();
    params.ack_delay_exponent = Some(VarInt::from_u32(25)); // Too large (max is 20)
    params.max_ack_delay = Some(VarInt::from_u32(16384)); // Too large (max is 2^14 - 1)
    params.active_connection_id_limit = Some(VarInt::from_u32(1)); // Too small (min is 2)
    params.max_udp_payload_size = Some(VarInt::from_u32(500)); // Too small (min is 1200)
    
    // This validation method uses Rust 2024 let chains
    match params.validate() {
        Ok(()) => println!("Transport parameters are valid"),
        Err(e) => println!("Validation error: {}", e),
    }
    
    // Fix the parameters
    params.ack_delay_exponent = Some(VarInt::from_u32(3));
    params.max_ack_delay = Some(VarInt::from_u32(8192)); // Valid: less than 2^14
    params.active_connection_id_limit = Some(VarInt::from_u32(4));
    params.max_udp_payload_size = Some(VarInt::from_u32(1200));
    
    match params.validate() {
        Ok(()) => println!("Transport parameters are now valid!"),
        Err(e) => println!("Still invalid: {}", e),
    }
    
    // Demonstrate the let chain feature in action
    println!("\nRust 2024 let chains allow cleaner validation code:");
    println!("- Multiple conditions can be chained with &&");
    println!("- Destructuring and pattern matching in conditions");
    println!("- More readable than nested if-let statements");
}