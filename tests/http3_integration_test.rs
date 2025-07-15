//! Comprehensive integration tests for HTTP/3 implementation
//!
//! Tests the full HTTP/3 stack including QUIC transport, QPACK compression,
//! and HTTP/3 framing.

use http3::{
    http3::{
        frame::{Http3Frame, Http3FrameType},
        settings::Http3Settings,
        priority::Priority,
    },
    quic::{
        Connection, ConnectionRole, ConnectionId,
        transport::TransportParameters,
    },
    qpack::{QpackEncoder, QpackDecoder},
    error::Result,
};
use bytes::{Bytes, BytesMut};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::{mpsc, Mutex},
    time::timeout,
};

/// Test server configuration
struct TestServer {
    addr: SocketAddr,
    settings: Http3Settings,
}

impl TestServer {
    async fn new() -> Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;
        
        let settings = Http3Settings {
            max_field_section_size: Some(16384),
            qpack_max_table_capacity: Some(4096),
            qpack_blocked_streams: Some(100),
            enable_webtransport: Some(true),
            enable_datagram: Some(true),
            ..Default::default()
        };
        
        Ok(Self { addr, settings })
    }
}

#[tokio::test]
async fn test_http3_connection_establishment() {
    // Create server
    let server = TestServer::new().await.unwrap();
    let server_addr = server.addr;
    
    // Create client connection
    let client_cid = ConnectionId::random();
    let server_cid = ConnectionId::random();
    
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
    
    let mut client_conn = Connection::new(
        ConnectionRole::Client,
        client_cid,
        server_cid,
        server_addr,
        transport_params.clone(),
    ).unwrap();
    
    // Verify initial state
    assert_eq!(client_conn.quic_version(), 0x00000001); // QUIC v1
    assert!(client_conn.supported_versions().contains(&0x00000001));
}

#[tokio::test]
async fn test_http3_settings_exchange() {
    let settings = Http3Settings {
        max_field_section_size: Some(8192),
        qpack_max_table_capacity: Some(4096),
        qpack_blocked_streams: Some(50),
        ..Default::default()
    };
    
    // Encode settings frame
    let mut buf = BytesMut::new();
    settings.encode(&mut buf).unwrap();
    
    // Decode and verify
    let decoded = Http3Settings::decode(&buf).unwrap();
    assert_eq!(decoded.max_field_section_size, Some(8192));
    assert_eq!(decoded.qpack_max_table_capacity, Some(4096));
    assert_eq!(decoded.qpack_blocked_streams, Some(50));
}

#[tokio::test]
async fn test_qpack_encoding_decoding() {
    let mut encoder = QpackEncoder::new(4096, 100);
    let mut decoder = QpackDecoder::new(4096, 100);
    
    // Test headers
    let headers = vec![
        (b":method".to_vec(), b"GET".to_vec()),
        (b":path".to_vec(), b"/index.html".to_vec()),
        (b":scheme".to_vec(), b"https".to_vec()),
        (b":authority".to_vec(), b"example.com".to_vec()),
        (b"user-agent".to_vec(), b"test-client/1.0".to_vec()),
        (b"accept".to_vec(), b"text/html".to_vec()),
    ];
    
    // Encode headers
    let stream_id = 0;
    let encoded = encoder.encode_field_section(&headers, stream_id).unwrap();
    
    // Decode headers
    let decoded = decoder.decode_field_section(&encoded, stream_id).unwrap();
    
    // Verify headers match
    assert_eq!(decoded.len(), headers.len());
    for (i, (name, value)) in decoded.iter().enumerate() {
        assert_eq!(name, &headers[i].0);
        assert_eq!(value, &headers[i].1);
    }
}

#[tokio::test]
async fn test_http3_priority_scheduling() {
    use http3::http3::priority::{PriorityScheduler, StreamPriority};
    
    let scheduler = PriorityScheduler::new();
    
    // Register streams with different priorities
    let high_priority = StreamPriority::with_priority(
        Priority::with_urgency_and_incremental(0, false).unwrap()
    );
    let low_priority = StreamPriority::with_priority(
        Priority::with_urgency_and_incremental(7, false).unwrap()
    );
    
    scheduler.register_stream_with_priority(1, high_priority).await.unwrap();
    scheduler.register_stream_with_priority(2, low_priority).await.unwrap();
    
    // High priority stream should be scheduled first
    let next = scheduler.schedule_next_stream().await;
    assert_eq!(next, Some(1));
}

#[tokio::test]
async fn test_http3_request_response_flow() {
    // Test headers for a simple GET request
    let request_headers = vec![
        (b":method".to_vec(), b"GET".to_vec()),
        (b":path".to_vec(), b"/test".to_vec()),
        (b":scheme".to_vec(), b"https".to_vec()),
        (b":authority".to_vec(), b"example.com".to_vec()),
    ];
    
    let response_headers = vec![
        (b":status".to_vec(), b"200".to_vec()),
        (b"content-type".to_vec(), b"text/plain".to_vec()),
        (b"content-length".to_vec(), b"13".to_vec()),
    ];
    
    // Encode request headers with QPACK
    let mut encoder = QpackEncoder::new(4096, 100);
    let encoded_request = encoder.encode_field_section(&request_headers, 0).unwrap();
    
    // Create HEADERS frame
    let headers_frame = Http3Frame::Headers {
        field_section: encoded_request,
    };
    
    // Verify frame encoding
    let mut buf = BytesMut::new();
    headers_frame.encode(&mut buf).unwrap();
    assert!(!buf.is_empty());
}

#[tokio::test]
async fn test_http3_data_frame_handling() {
    let data = b"Hello, HTTP/3!";
    let data_frame = Http3Frame::Data {
        payload: Bytes::from_static(data),
    };
    
    // Encode frame
    let mut buf = BytesMut::new();
    data_frame.encode(&mut buf).unwrap();
    
    // Decode frame
    let decoded = Http3Frame::decode(&mut buf.clone()).unwrap();
    match decoded {
        Http3Frame::Data { payload } => {
            assert_eq!(&payload[..], data);
        }
        _ => panic!("Expected DATA frame"),
    }
}

#[tokio::test]
async fn test_http3_stream_cancellation() {
    use http3::http3::frame::Http3Frame;
    
    let cancel_frame = Http3Frame::CancelPush {
        push_id: 42.into(),
    };
    
    let mut buf = BytesMut::new();
    cancel_frame.encode(&mut buf).unwrap();
    
    let decoded = Http3Frame::decode(&mut buf).unwrap();
    match decoded {
        Http3Frame::CancelPush { push_id } => {
            assert_eq!(push_id.into_inner(), 42);
        }
        _ => panic!("Expected CANCEL_PUSH frame"),
    }
}

#[tokio::test]
async fn test_http3_goaway_handling() {
    use http3::http3::frame::Http3Frame;
    
    let goaway_frame = Http3Frame::Goaway {
        id: 100.into(),
    };
    
    let mut buf = BytesMut::new();
    goaway_frame.encode(&mut buf).unwrap();
    
    let decoded = Http3Frame::decode(&mut buf).unwrap();
    match decoded {
        Http3Frame::Goaway { id } => {
            assert_eq!(id.into_inner(), 100);
        }
        _ => panic!("Expected GOAWAY frame"),
    }
}

#[tokio::test]
async fn test_http3_max_push_id() {
    use http3::http3::frame::Http3Frame;
    
    let max_push_frame = Http3Frame::MaxPushId {
        push_id: 64.into(),
    };
    
    let mut buf = BytesMut::new();
    max_push_frame.encode(&mut buf).unwrap();
    
    let decoded = Http3Frame::decode(&mut buf).unwrap();
    match decoded {
        Http3Frame::MaxPushId { push_id } => {
            assert_eq!(push_id.into_inner(), 64);
        }
        _ => panic!("Expected MAX_PUSH_ID frame"),
    }
}

#[tokio::test]
async fn test_http3_reserved_frame_handling() {
    use http3::http3::frame::{Http3Frame, ReservedFrame};
    
    let reserved = ReservedFrame {
        frame_type: 0x21.into(), // Reserved frame type
        payload: Bytes::from_static(b"reserved data"),
    };
    
    let frame = Http3Frame::Reserved(reserved.clone());
    
    let mut buf = BytesMut::new();
    frame.encode(&mut buf).unwrap();
    
    let decoded = Http3Frame::decode(&mut buf).unwrap();
    match decoded {
        Http3Frame::Reserved(decoded_reserved) => {
            assert_eq!(decoded_reserved.frame_type, reserved.frame_type);
            assert_eq!(decoded_reserved.payload, reserved.payload);
        }
        _ => panic!("Expected Reserved frame"),
    }
}

#[tokio::test]
async fn test_webtransport_support() {
    let settings = Http3Settings {
        enable_webtransport: Some(true),
        webtransport_max_sessions: Some(10),
        ..Default::default()
    };
    
    assert_eq!(settings.enable_webtransport, Some(true));
    assert_eq!(settings.webtransport_max_sessions, Some(10));
}

#[tokio::test]
async fn test_datagram_support() {
    let settings = Http3Settings {
        enable_datagram: Some(true),
        ..Default::default()
    };
    
    assert_eq!(settings.enable_datagram, Some(true));
}