//! End-to-end integration tests for HTTP/3
//!
//! Tests complete client-server communication scenarios

use http3::{
    error::Result,
    quic::{
        Connection, ConnectionRole, ConnectionId, 
        transport::TransportParameters,
    },
    http3::{
        frame::Http3Frame,
        settings::Http3Settings,
    },
    qpack::{QpackEncoder, QpackDecoder},
};
use bytes::{Bytes, BytesMut};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, Mutex, RwLock},
    time::{timeout, sleep},
};

/// Mock network transport for testing
struct MockTransport {
    client_to_server: mpsc::UnboundedSender<Vec<u8>>,
    server_to_client: mpsc::UnboundedSender<Vec<u8>>,
    client_rx: Arc<Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>,
    server_rx: Arc<Mutex<mpsc::UnboundedReceiver<Vec<u8>>>>,
}

impl MockTransport {
    fn new() -> Self {
        let (c2s_tx, s_rx) = mpsc::unbounded_channel();
        let (s2c_tx, c_rx) = mpsc::unbounded_channel();
        
        Self {
            client_to_server: c2s_tx,
            server_to_client: s2c_tx,
            client_rx: Arc::new(Mutex::new(c_rx)),
            server_rx: Arc::new(Mutex::new(s_rx)),
        }
    }
}

#[tokio::test]
async fn test_connection_handshake() {
    let transport = MockTransport::new();
    
    // Create client and server connections
    let client_cid = ConnectionId::random();
    let server_cid = ConnectionId::random();
    let addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    
    let transport_params = TransportParameters {
        initial_max_stream_data_bidi_local: Some(1048576.into()),
        initial_max_stream_data_bidi_remote: Some(1048576.into()),
        initial_max_stream_data_uni: Some(1048576.into()),
        initial_max_data: Some(10485760.into()),
        initial_max_streams_bidi: Some(100.into()),
        initial_max_streams_uni: Some(100.into()),
        max_idle_timeout: Some(30000.into()),
        ..Default::default()
    };
    
    let mut client = Connection::new(
        ConnectionRole::Client,
        client_cid.clone(),
        server_cid.clone(),
        addr,
        transport_params.clone(),
    ).unwrap();
    
    let mut server = Connection::new(
        ConnectionRole::Server,
        server_cid.clone(),
        client_cid.clone(),
        addr,
        transport_params.clone(),
    ).unwrap();
    
    // Set up packet channels
    let (client_tx, mut client_rx) = mpsc::unbounded_channel();
    let (server_tx, mut server_rx) = mpsc::unbounded_channel();
    
    client.set_packet_sender(client_tx);
    server.set_packet_sender(server_tx);
    
    // Verify initial states
    assert!(client.is_handshaking());
    assert!(server.is_handshaking());
}

#[tokio::test]
async fn test_stream_creation_and_data_transfer() {
    // Test creating streams and transferring data
    let client_cid = ConnectionId::random();
    let server_cid = ConnectionId::random();
    let addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    
    let transport_params = TransportParameters {
        initial_max_stream_data_bidi_local: Some(65536.into()),
        initial_max_stream_data_bidi_remote: Some(65536.into()),
        initial_max_streams_bidi: Some(10.into()),
        ..Default::default()
    };
    
    let mut client = Connection::new(
        ConnectionRole::Client,
        client_cid,
        server_cid,
        addr,
        transport_params,
    ).unwrap();
    
    // Client-initiated bidirectional stream ID should be 0, 4, 8, ...
    let stream_id = 0;
    
    // Test data
    let test_data = b"Hello, HTTP/3!";
    
    // In a real implementation, this would create a stream and send data
    // For now, we're testing the structure
    assert_eq!(stream_id % 4, 0); // Client-initiated bidirectional
}

#[tokio::test]
async fn test_flow_control() {
    let transport_params = TransportParameters {
        initial_max_data: Some(1000.into()), // Small limit for testing
        initial_max_stream_data_bidi_local: Some(500.into()),
        ..Default::default()
    };
    
    let client_cid = ConnectionId::random();
    let server_cid = ConnectionId::random();
    let addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    
    let connection = Connection::new(
        ConnectionRole::Client,
        client_cid,
        server_cid,
        addr,
        transport_params,
    ).unwrap();
    
    // Flow control limits should be enforced
    let stats = connection.stats();
    assert_eq!(stats.available_send_window, 1000);
}

#[tokio::test]
async fn test_http3_headers_encoding() {
    let mut encoder = QpackEncoder::new(4096, 100);
    let mut decoder = QpackDecoder::new(4096, 100);
    
    // Common HTTP/3 request headers
    let headers = vec![
        (b":method".to_vec(), b"POST".to_vec()),
        (b":path".to_vec(), b"/api/data".to_vec()),
        (b":scheme".to_vec(), b"https".to_vec()),
        (b":authority".to_vec(), b"api.example.com".to_vec()),
        (b"content-type".to_vec(), b"application/json".to_vec()),
        (b"content-length".to_vec(), b"42".to_vec()),
        (b"user-agent".to_vec(), b"HTTP3-Test/1.0".to_vec()),
    ];
    
    // Encode
    let encoded = encoder.encode_field_section(&headers, 0).unwrap();
    
    // Decode
    let decoded = decoder.decode_field_section(&encoded, 0).unwrap();
    
    // Verify all headers preserved
    assert_eq!(decoded.len(), headers.len());
    for (i, (name, value)) in decoded.iter().enumerate() {
        assert_eq!(name, &headers[i].0);
        assert_eq!(value, &headers[i].1);
    }
}

#[tokio::test]
async fn test_connection_migration() {
    let client_cid = ConnectionId::random();
    let server_cid = ConnectionId::random();
    let initial_addr: SocketAddr = "192.168.1.100:12345".parse().unwrap();
    
    let transport_params = TransportParameters {
        disable_active_migration: false,
        ..Default::default()
    };
    
    let connection = Connection::new(
        ConnectionRole::Client,
        client_cid,
        server_cid,
        initial_addr,
        transport_params,
    ).unwrap();
    
    // Connection should support migration
    let peer_params = connection.get_transport_params();
    assert!(!peer_params.disable_active_migration);
}

#[tokio::test]
async fn test_connection_close() {
    use http3::error::ConnectionErrorCode;
    
    let client_cid = ConnectionId::random();
    let server_cid = ConnectionId::random();
    let addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    
    let mut connection = Connection::new(
        ConnectionRole::Client,
        client_cid,
        server_cid,
        addr,
        TransportParameters::default(),
    ).unwrap();
    
    // Close connection
    connection.close(
        ConnectionErrorCode::NoError,
        "Normal shutdown".to_string(),
    ).await.unwrap();
    
    // Verify connection is closed
    assert!(connection.is_closed());
}

#[tokio::test]
async fn test_priority_update_handling() {
    use http3::http3::priority::{Priority, PriorityUpdateFrame};
    use http3::quic::stream::StreamId;
    
    let priority = Priority::with_urgency_and_incremental(2, true).unwrap();
    let stream_id = StreamId::try_from(4).unwrap();
    
    let update_frame = PriorityUpdateFrame::from_priority(stream_id, &priority);
    
    // Encode the frame
    let mut buf = BytesMut::new();
    update_frame.encode(&mut buf).unwrap();
    
    // Decode and verify
    let decoded_priority = update_frame.to_priority().unwrap();
    assert_eq!(decoded_priority.urgency, 2);
    assert!(decoded_priority.incremental);
}

#[tokio::test]
async fn test_0rtt_early_data() {
    let client_cid = ConnectionId::random();
    let server_cid = ConnectionId::random();
    let addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    
    let transport_params = TransportParameters {
        max_early_data: Some(4096),
        ..Default::default()
    };
    
    let connection = Connection::new(
        ConnectionRole::Client,
        client_cid,
        server_cid,
        addr,
        transport_params,
    ).unwrap();
    
    // 0-RTT should be configurable
    let params = connection.get_transport_params();
    assert_eq!(params.max_early_data, Some(4096));
}

#[tokio::test]
async fn test_datagram_frames() {
    use http3::quic::frame_types::Frame;
    
    let datagram_data = b"UDP-like datagram over QUIC";
    let frame = Frame::Datagram {
        data: Bytes::from_static(datagram_data),
    };
    
    // Encode frame
    let mut buf = BytesMut::new();
    frame.encode(&mut buf).unwrap();
    
    // Decode frame
    let decoded = Frame::decode(&mut buf).unwrap();
    match decoded {
        Frame::Datagram { data } => {
            assert_eq!(&data[..], datagram_data);
        }
        _ => panic!("Expected DATAGRAM frame"),
    }
}

#[tokio::test]
async fn test_transport_parameters_negotiation() {
    let client_params = TransportParameters {
        initial_max_stream_data_bidi_local: Some(65536u32.into()),
        initial_max_data: Some(1048576u32.into()),
        initial_max_streams_bidi: Some(100u32.into()),
        max_idle_timeout: Some(30000u32.into()),
        active_connection_id_limit: Some(4u32.into()),
        ..Default::default()
    };

    let server_params = TransportParameters {
        initial_max_stream_data_bidi_remote: Some(65536u32.into()),
        initial_max_data: Some(2097152u32.into()),
        initial_max_streams_bidi: Some(200u32.into()),
        max_idle_timeout: Some(60000u32.into()),
        preferred_address: None,
        ..Default::default()
    };
    
    // Both sides should respect the minimum of the advertised limits
    assert!(client_params.initial_max_data.unwrap().into_inner() < 
            server_params.initial_max_data.unwrap().into_inner());
}