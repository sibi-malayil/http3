//! Simple test for transport parameter functionality

#[test]
fn test_transport_params_basic() {
    use http3::quic::transport::TransportParameters;
    use http3::util::varint::VarInt;
    
    // Create default parameters
    let params = TransportParameters::default();
    
    // Verify defaults
    assert_eq!(params.max_idle_timeout, Some(VarInt::from_u32(30000)));
    assert_eq!(params.initial_max_data, Some(VarInt::from_u32(1024 * 1024)));
    assert!(!params.disable_active_migration);
    
    // Validate parameters
    assert!(params.validate().is_ok());
    
    println!("Transport parameters created and validated successfully");
}

#[test] 
fn test_transport_params_encoding() {
    use http3::quic::transport::TransportParameters;
    use http3::util::varint::VarInt;
    
    let mut params = TransportParameters::default();
    params.max_idle_timeout = Some(VarInt::from_u32(60000));
    params.initial_max_data = Some(VarInt::from_u32(2048 * 1024));
    
    // Encode parameters
    let encoded = params.encode().unwrap();
    assert!(!encoded.is_empty());
    
    // Decode parameters
    let decoded = TransportParameters::decode(encoded).unwrap();
    assert_eq!(decoded.max_idle_timeout, params.max_idle_timeout);
    assert_eq!(decoded.initial_max_data, params.initial_max_data);
    
    println!("Transport parameters encoded and decoded successfully");
}

#[test]
fn test_flow_control_from_params() {
    use http3::quic::connection::FlowControlLimits;
    use http3::quic::transport::TransportParameters;
    use http3::util::varint::VarInt;
    
    let mut params = TransportParameters::default();
    params.initial_max_data = Some(VarInt::from_u32(5000));
    params.initial_max_streams_bidi = Some(VarInt::from_u32(20));
    
    let flow_control = FlowControlLimits::new(&params);
    
    assert_eq!(flow_control.max_data, 5000);
    assert_eq!(flow_control.max_streams_bidi, 20);
    assert_eq!(flow_control.data_sent, 0);
    
    println!("Flow control limits created from transport parameters successfully");
}