use http3::{
    http3::{
        webtransport::{
            WebTransportManager, WebTransportConfig, WebTransportStreamType, 
            WebTransportStreamEvent, SessionState, SessionId,
        },
        datagram::DatagramResult,
        connection::ConnectionRole,
    },
    quic::{
        stream::{StreamId, StreamType},
        connection::ConnectionRole as QuicConnectionRole,
    },
    qpack::field::{HeaderField, HeaderName, HeaderValue},
};
use bytes::Bytes;

#[test]
fn test_webtransport_session_establishment() {
    let mut manager = WebTransportManager::default_for_role(ConnectionRole::Server);
    let stream_id = StreamId::new(4, StreamType::Bidirectional, QuicConnectionRole::Client).unwrap();
    
    let headers = vec![
        HeaderField::new(HeaderName::from(":method"), HeaderValue::from("CONNECT")),
        HeaderField::new(HeaderName::from(":protocol"), HeaderValue::from("webtransport")),
        HeaderField::new(HeaderName::from(":authority"), HeaderValue::from("example.com")),
        HeaderField::new(HeaderName::from(":path"), HeaderValue::from("/webtransport")),
        HeaderField::new(HeaderName::from("origin"), HeaderValue::from("https://example.com")),
    ];

    // Establish session
    let session_id = manager.establish_session(stream_id, &headers).unwrap();
    assert_eq!(session_id.value(), 1);

    // Verify session was created
    let session = manager.get_session(session_id).unwrap();
    assert_eq!(session.state, SessionState::Active);
    assert_eq!(session.origin, "https://example.com");
    assert_eq!(session.path, "/webtransport");
    assert_eq!(session.stream_id, stream_id);

    // Verify statistics
    let stats = manager.stats();
    assert_eq!(stats.sessions_established, 1);
    assert_eq!(stats.active_sessions, 1);
}

#[test]
fn test_webtransport_stream_management() {
    let mut manager = WebTransportManager::default_for_role(ConnectionRole::Client);
    let main_stream = StreamId::new(4, StreamType::Bidirectional, QuicConnectionRole::Client).unwrap();
    
    let headers = vec![
        HeaderField::new(HeaderName::from(":protocol"), HeaderValue::from("webtransport")),
        HeaderField::new(HeaderName::from(":authority"), HeaderValue::from("test.example.com")),
        HeaderField::new(HeaderName::from(":path"), HeaderValue::from("/api/v1")),
    ];

    let session_id = manager.establish_session(main_stream, &headers).unwrap();
    
    // Add bidirectional stream
    let bidi_stream = StreamId::new(8, StreamType::Bidirectional, QuicConnectionRole::Client).unwrap();
    manager.add_stream(session_id, bidi_stream, WebTransportStreamType::Bidirectional).unwrap();
    
    // Add unidirectional streams
    let uni_out_stream = StreamId::new(12, StreamType::Unidirectional, QuicConnectionRole::Client).unwrap();
    manager.add_stream(session_id, uni_out_stream, WebTransportStreamType::UnidirectionalOutgoing).unwrap();
    
    let uni_in_stream = StreamId::new(16, StreamType::Unidirectional, QuicConnectionRole::Server).unwrap();
    manager.add_stream(session_id, uni_in_stream, WebTransportStreamType::UnidirectionalIncoming).unwrap();

    // Verify session has streams
    let session = manager.get_session(session_id).unwrap();
    assert_eq!(session.streams.len(), 3);
    assert!(session.streams.contains_key(&bidi_stream));
    assert!(session.streams.contains_key(&uni_out_stream));
    assert!(session.streams.contains_key(&uni_in_stream));

    // Check stream events
    let events: Vec<_> = (0..3).map(|_| manager.next_stream_event().unwrap()).collect();
    assert_eq!(events.len(), 3);
    
    for event in &events {
        match event {
            WebTransportStreamEvent::StreamCreated { session_id: sid, stream_id, stream_type } => {
                assert_eq!(*sid, session_id);
                assert!(session.streams.contains_key(stream_id));
                match stream_id {
                    id if *id == bidi_stream => assert_eq!(*stream_type, WebTransportStreamType::Bidirectional),
                    id if *id == uni_out_stream => assert_eq!(*stream_type, WebTransportStreamType::UnidirectionalOutgoing),
                    id if *id == uni_in_stream => assert_eq!(*stream_type, WebTransportStreamType::UnidirectionalIncoming),
                    _ => panic!("Unexpected stream ID"),
                }
            }
            _ => panic!("Expected StreamCreated event"),
        }
    }

    // Verify session statistics
    assert_eq!(session.stats.streams_created, 3);
    
    // Global statistics
    let stats = manager.stats();
    assert_eq!(stats.streams_created, 3);
}

#[test]
fn test_webtransport_datagram_communication() {
    let mut client_manager = WebTransportManager::default_for_role(ConnectionRole::Client);
    let mut server_manager = WebTransportManager::default_for_role(ConnectionRole::Server);
    
    let client_stream = StreamId::new(4, StreamType::Bidirectional, QuicConnectionRole::Client).unwrap();
    let server_stream = StreamId::new(8, StreamType::Bidirectional, QuicConnectionRole::Server).unwrap();
    
    let headers = vec![
        HeaderField::new(HeaderName::from(":protocol"), HeaderValue::from("webtransport")),
        HeaderField::new(HeaderName::from(":authority"), HeaderValue::from("chat.example.com")),
        HeaderField::new(HeaderName::from(":path"), HeaderValue::from("/chat")),
    ];

    // Establish sessions
    let client_session = client_manager.establish_session(client_stream, &headers).unwrap();
    let server_session = server_manager.establish_session(server_stream, &headers).unwrap();
    
    // Client sends datagram
    let client_message = Bytes::from_static(b"Hello from client!");
    let result = client_manager.send_datagram(client_session, client_message.clone()).unwrap();
    assert_eq!(result, DatagramResult::Queued);
    
    // Get datagram frame from client
    let client_frame = client_manager.next_datagram_frame(client_stream);
    assert!(client_frame.is_some());
    
    // Simulate server receiving the datagram
    server_manager.on_datagram_received(server_stream, client_message.clone()).unwrap();
    
    // Server should have received datagram
    let received = server_manager.next_received_datagram().unwrap();
    assert_eq!(received.session_id, server_session);
    assert_eq!(received.data, client_message);
    
    // Server sends response
    let server_message = Bytes::from_static(b"Hello from server!");
    let result = server_manager.send_datagram(server_session, server_message.clone()).unwrap();
    assert_eq!(result, DatagramResult::Queued);
    
    // Simulate client receiving server response
    client_manager.on_datagram_received(client_stream, server_message.clone()).unwrap();
    
    let received = client_manager.next_received_datagram().unwrap();
    assert_eq!(received.session_id, client_session);
    assert_eq!(received.data, server_message);
    
    // Verify statistics
    let client_stats = client_manager.stats();
    assert_eq!(client_stats.datagrams_sent, 1);
    assert_eq!(client_stats.datagrams_received, 1);
    assert_eq!(client_stats.datagram_bytes_sent, client_message.len() as u64);
    assert_eq!(client_stats.datagram_bytes_received, server_message.len() as u64);
    
    let server_stats = server_manager.stats();
    assert_eq!(server_stats.datagrams_sent, 1);
    assert_eq!(server_stats.datagrams_received, 1);
}

#[test]
fn test_webtransport_stream_data_events() {
    let mut manager = WebTransportManager::default_for_role(ConnectionRole::Server);
    let main_stream = StreamId::new(4, StreamType::Bidirectional, QuicConnectionRole::Client).unwrap();
    let data_stream = StreamId::new(8, StreamType::Bidirectional, QuicConnectionRole::Client).unwrap();
    
    let headers = vec![
        HeaderField::new(HeaderName::from(":protocol"), HeaderValue::from("webtransport")),
        HeaderField::new(HeaderName::from(":authority"), HeaderValue::from("api.example.com")),
        HeaderField::new(HeaderName::from(":path"), HeaderValue::from("/api")),
    ];

    let session_id = manager.establish_session(main_stream, &headers).unwrap();
    manager.add_stream(session_id, data_stream, WebTransportStreamType::Bidirectional).unwrap();
    
    // Clear the stream created event
    manager.next_stream_event();
    
    // Send stream data
    let test_data = Bytes::from_static(b"Stream data payload");
    manager.on_stream_data(data_stream, test_data.clone(), false).unwrap();
    
    // Check stream data event
    let event = manager.next_stream_event().unwrap();
    match event {
        WebTransportStreamEvent::StreamData { session_id: sid, stream_id, data, fin } => {
            assert_eq!(sid, session_id);
            assert_eq!(stream_id, data_stream);
            assert_eq!(data, test_data);
            assert!(!fin);
        }
        _ => panic!("Expected StreamData event"),
    }
    
    // Send final data
    let final_data = Bytes::from_static(b"Final chunk");
    manager.on_stream_data(data_stream, final_data.clone(), true).unwrap();
    
    let event = manager.next_stream_event().unwrap();
    match event {
        WebTransportStreamEvent::StreamData { session_id: sid, stream_id, data, fin } => {
            assert_eq!(sid, session_id);
            assert_eq!(stream_id, data_stream);
            assert_eq!(data, final_data);
            assert!(fin);
        }
        _ => panic!("Expected StreamData event"),
    }
}

#[test]
fn test_webtransport_session_limits() {
    let config = WebTransportConfig {
        max_sessions: 2,
        max_streams_per_session: 1,
        ..Default::default()
    };
    let mut manager = WebTransportManager::new(config, ConnectionRole::Server);
    
    let headers = vec![
        HeaderField::new(HeaderName::from(":protocol"), HeaderValue::from("webtransport")),
        HeaderField::new(HeaderName::from(":authority"), HeaderValue::from("example.com")),
        HeaderField::new(HeaderName::from(":path"), HeaderValue::from("/test")),
    ];
    
    // Create maximum number of sessions
    let stream1 = StreamId::new(4, StreamType::Bidirectional, QuicConnectionRole::Client).unwrap();
    let stream2 = StreamId::new(8, StreamType::Bidirectional, QuicConnectionRole::Client).unwrap();
    let stream3 = StreamId::new(12, StreamType::Bidirectional, QuicConnectionRole::Client).unwrap();
    
    let session1 = manager.establish_session(stream1, &headers).unwrap();
    let session2 = manager.establish_session(stream2, &headers).unwrap();
    
    // Third session should fail
    let result = manager.establish_session(stream3, &headers);
    assert!(result.is_err());
    
    // Test stream limits per session
    let data_stream1 = StreamId::new(16, StreamType::Bidirectional, QuicConnectionRole::Client).unwrap();
    let data_stream2 = StreamId::new(20, StreamType::Bidirectional, QuicConnectionRole::Client).unwrap();
    
    // First stream should succeed
    manager.add_stream(session1, data_stream1, WebTransportStreamType::Bidirectional).unwrap();
    
    // Second stream should fail due to per-session limit
    let result = manager.add_stream(session1, data_stream2, WebTransportStreamType::Bidirectional);
    assert!(result.is_err());
}

#[test]
fn test_webtransport_session_cleanup() {
    let mut manager = WebTransportManager::default_for_role(ConnectionRole::Server);
    let main_stream = StreamId::new(4, StreamType::Bidirectional, QuicConnectionRole::Client).unwrap();
    let data_stream1 = StreamId::new(8, StreamType::Bidirectional, QuicConnectionRole::Client).unwrap();
    let data_stream2 = StreamId::new(12, StreamType::Unidirectional, QuicConnectionRole::Client).unwrap();
    
    let headers = vec![
        HeaderField::new(HeaderName::from(":protocol"), HeaderValue::from("webtransport")),
        HeaderField::new(HeaderName::from(":authority"), HeaderValue::from("example.com")),
        HeaderField::new(HeaderName::from(":path"), HeaderValue::from("/cleanup-test")),
    ];

    let session_id = manager.establish_session(main_stream, &headers).unwrap();
    manager.add_stream(session_id, data_stream1, WebTransportStreamType::Bidirectional).unwrap();
    manager.add_stream(session_id, data_stream2, WebTransportStreamType::UnidirectionalOutgoing).unwrap();
    
    // Verify session has streams
    assert_eq!(manager.get_session(session_id).unwrap().streams.len(), 2);
    assert!(manager.stream_to_session.contains_key(&main_stream));
    assert!(manager.stream_to_session.contains_key(&data_stream1));
    assert!(manager.stream_to_session.contains_key(&data_stream2));
    
    // Close session
    manager.close_session(session_id).unwrap();
    
    // Verify cleanup
    assert!(manager.get_session(session_id).is_none());
    assert!(!manager.stream_to_session.contains_key(&main_stream));
    assert!(!manager.stream_to_session.contains_key(&data_stream1));
    assert!(!manager.stream_to_session.contains_key(&data_stream2));
    
    // Check that stream closed events were generated
    let mut closed_events = 0;
    while let Some(event) = manager.next_stream_event() {
        match event {
            WebTransportStreamEvent::StreamClosed { session_id: sid, .. } => {
                assert_eq!(sid, session_id);
                closed_events += 1;
            }
            _ => {} // Ignore other events
        }
    }
    assert_eq!(closed_events, 2); // Two data streams should generate close events
    
    // Verify statistics
    let stats = manager.stats();
    assert_eq!(stats.sessions_established, 1);
    assert_eq!(stats.sessions_closed, 1);
    assert_eq!(stats.active_sessions, 0);
}

#[test]
fn test_webtransport_invalid_protocol() {
    let mut manager = WebTransportManager::default_for_role(ConnectionRole::Server);
    let stream_id = StreamId::new(4, StreamType::Bidirectional, QuicConnectionRole::Client).unwrap();
    
    // Test missing protocol header
    let headers_no_protocol = vec![
        HeaderField::new(HeaderName::from(":authority"), HeaderValue::from("example.com")),
        HeaderField::new(HeaderName::from(":path"), HeaderValue::from("/test")),
    ];
    
    let result = manager.establish_session(stream_id, &headers_no_protocol);
    assert!(result.is_err());
    
    // Test wrong protocol
    let headers_wrong_protocol = vec![
        HeaderField::new(HeaderName::from(":protocol"), HeaderValue::from("http")),
        HeaderField::new(HeaderName::from(":authority"), HeaderValue::from("example.com")),
        HeaderField::new(HeaderName::from(":path"), HeaderValue::from("/test")),
    ];
    
    let result = manager.establish_session(stream_id, &headers_wrong_protocol);
    assert!(result.is_err());
}

#[test]
fn test_webtransport_datagram_size_limits() {
    let config = WebTransportConfig {
        max_datagram_size: 100,
        ..Default::default()
    };
    let mut manager = WebTransportManager::new(config, ConnectionRole::Client);
    let stream_id = StreamId::new(4, StreamType::Bidirectional, QuicConnectionRole::Client).unwrap();
    
    let headers = vec![
        HeaderField::new(HeaderName::from(":protocol"), HeaderValue::from("webtransport")),
        HeaderField::new(HeaderName::from(":authority"), HeaderValue::from("example.com")),
        HeaderField::new(HeaderName::from(":path"), HeaderValue::from("/size-test")),
    ];

    let session_id = manager.establish_session(stream_id, &headers).unwrap();
    
    // Small datagram should work
    let small_data = Bytes::from(vec![0u8; 50]);
    let result = manager.send_datagram(session_id, small_data).unwrap();
    assert_eq!(result, DatagramResult::Queued);
    
    // Large datagram should be rejected
    let large_data = Bytes::from(vec![0u8; 200]);
    let result = manager.send_datagram(session_id, large_data).unwrap();
    assert_eq!(result, DatagramResult::TooLarge);
}

#[test]
fn test_webtransport_disabled_datagrams() {
    let config = WebTransportConfig {
        enable_datagrams: false,
        ..Default::default()
    };
    let mut manager = WebTransportManager::new(config, ConnectionRole::Client);
    let stream_id = StreamId::new(4, StreamType::Bidirectional, QuicConnectionRole::Client).unwrap();
    
    let headers = vec![
        HeaderField::new(HeaderName::from(":protocol"), HeaderValue::from("webtransport")),
        HeaderField::new(HeaderName::from(":authority"), HeaderValue::from("example.com")),
        HeaderField::new(HeaderName::from(":path"), HeaderValue::from("/no-datagrams")),
    ];

    let session_id = manager.establish_session(stream_id, &headers).unwrap();
    
    let data = Bytes::from_static(b"Test data");
    let result = manager.send_datagram(session_id, data);
    assert!(result.is_err());
}

#[test]
fn test_webtransport_multiple_sessions() {
    let mut manager = WebTransportManager::default_for_role(ConnectionRole::Server);
    
    let headers1 = vec![
        HeaderField::new(HeaderName::from(":protocol"), HeaderValue::from("webtransport")),
        HeaderField::new(HeaderName::from(":authority"), HeaderValue::from("api.example.com")),
        HeaderField::new(HeaderName::from(":path"), HeaderValue::from("/session1")),
    ];
    
    let headers2 = vec![
        HeaderField::new(HeaderName::from(":protocol"), HeaderValue::from("webtransport")),
        HeaderField::new(HeaderName::from(":authority"), HeaderValue::from("api.example.com")),
        HeaderField::new(HeaderName::from(":path"), HeaderValue::from("/session2")),
    ];
    
    let stream1 = StreamId::new(4, StreamType::Bidirectional, QuicConnectionRole::Client).unwrap();
    let stream2 = StreamId::new(8, StreamType::Bidirectional, QuicConnectionRole::Client).unwrap();
    
    // Create two sessions
    let session1 = manager.establish_session(stream1, &headers1).unwrap();
    let session2 = manager.establish_session(stream2, &headers2).unwrap();
    
    assert_ne!(session1, session2);
    assert_eq!(manager.sessions.len(), 2);
    
    // Verify session lookup by stream
    assert_eq!(manager.get_session_for_stream(stream1), Some(session1));
    assert_eq!(manager.get_session_for_stream(stream2), Some(session2));
    
    // Test datagram isolation
    let data1 = Bytes::from_static(b"Session 1 data");
    let data2 = Bytes::from_static(b"Session 2 data");
    
    manager.send_datagram(session1, data1.clone()).unwrap();
    manager.send_datagram(session2, data2.clone()).unwrap();
    
    // Simulate reception
    manager.on_datagram_received(stream1, data1.clone()).unwrap();
    manager.on_datagram_received(stream2, data2.clone()).unwrap();
    
    // Check received datagrams
    let received1 = manager.next_received_datagram().unwrap();
    let received2 = manager.next_received_datagram().unwrap();
    
    // Verify correct session association
    assert!(
        (received1.session_id == session1 && received1.data == data1 && 
         received2.session_id == session2 && received2.data == data2) ||
        (received1.session_id == session2 && received1.data == data2 && 
         received2.session_id == session1 && received2.data == data1)
    );
}

#[test]
fn test_webtransport_statistics_tracking() {
    let mut manager = WebTransportManager::default_for_role(ConnectionRole::Client);
    let stream_id = StreamId::new(4, StreamType::Bidirectional, QuicConnectionRole::Client).unwrap();
    
    let headers = vec![
        HeaderField::new(HeaderName::from(":protocol"), HeaderValue::from("webtransport")),
        HeaderField::new(HeaderName::from(":authority"), HeaderValue::from("stats.example.com")),
        HeaderField::new(HeaderName::from(":path"), HeaderValue::from("/stats-test")),
    ];

    // Initial stats
    let initial_stats = manager.stats();
    assert_eq!(initial_stats.sessions_established, 0);
    assert_eq!(initial_stats.active_sessions, 0);
    
    // Establish session
    let session_id = manager.establish_session(stream_id, &headers).unwrap();
    
    let stats_after_session = manager.stats();
    assert_eq!(stats_after_session.sessions_established, 1);
    assert_eq!(stats_after_session.active_sessions, 1);
    
    // Add streams
    let data_stream = StreamId::new(8, StreamType::Bidirectional, QuicConnectionRole::Client).unwrap();
    manager.add_stream(session_id, data_stream, WebTransportStreamType::Bidirectional).unwrap();
    
    let stats_after_stream = manager.stats();
    assert_eq!(stats_after_stream.streams_created, 1);
    
    // Send datagrams
    let data = Bytes::from_static(b"Statistics test data");
    manager.send_datagram(session_id, data.clone()).unwrap();
    manager.send_datagram(session_id, data.clone()).unwrap();
    
    let stats_after_datagrams = manager.stats();
    assert_eq!(stats_after_datagrams.datagrams_sent, 2);
    assert_eq!(stats_after_datagrams.datagram_bytes_sent, (data.len() * 2) as u64);
    
    // Simulate receiving datagrams
    manager.on_datagram_received(stream_id, data.clone()).unwrap();
    
    let final_stats = manager.stats();
    assert_eq!(final_stats.datagrams_received, 1);
    assert_eq!(final_stats.datagram_bytes_received, data.len() as u64);
    
    // Close session
    manager.close_session(session_id).unwrap();
    
    let closed_stats = manager.stats();
    assert_eq!(closed_stats.sessions_closed, 1);
    assert_eq!(closed_stats.active_sessions, 0);
}

#[test]
fn test_webtransport_session_expiry() {
    let config = WebTransportConfig {
        session_idle_timeout: 0, // Immediate expiry for testing
        ..Default::default()
    };
    let mut manager = WebTransportManager::new(config, ConnectionRole::Server);
    let stream_id = StreamId::new(4, StreamType::Bidirectional, QuicConnectionRole::Client).unwrap();
    
    let headers = vec![
        HeaderField::new(HeaderName::from(":protocol"), HeaderValue::from("webtransport")),
        HeaderField::new(HeaderName::from(":authority"), HeaderValue::from("example.com")),
        HeaderField::new(HeaderName::from(":path"), HeaderValue::from("/expiry-test")),
    ];

    let session_id = manager.establish_session(stream_id, &headers).unwrap();
    assert_eq!(manager.sessions.len(), 1);
    
    // Wait a bit to ensure session expires
    std::thread::sleep(std::time::Duration::from_millis(1));
    
    // Cleanup expired sessions
    let cleaned_up = manager.cleanup_expired_sessions();
    assert_eq!(cleaned_up, 1);
    assert_eq!(manager.sessions.len(), 0);
    
    let stats = manager.stats();
    assert_eq!(stats.active_sessions, 0);
    assert_eq!(stats.sessions_closed, 1);
}