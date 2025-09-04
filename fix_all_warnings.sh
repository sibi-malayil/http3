#!/bin/bash

echo "Fixing all warnings in HTTP/3 implementation..."

# Fix unused imports in priority_manager.rs
sed -i '/StreamPriority, PRIORITY_UPDATE_FRAME_TYPE/d' src/http3/priority_manager.rs
sed -i '/Http3FrameType/d' src/http3/priority_manager.rs  
sed -i '/util::varint::VarInt/d' src/http3/priority_manager.rs
sed -i 's/{debug, info, warn, error, protocol_event, span, time_block}/{protocol_event}/' src/http3/priority_manager.rs

# Fix unused imports in server_push.rs
sed -i '/common_errors/d' src/http3/server_push.rs
sed -i '/Http3Frame/d' src/http3/server_push.rs
sed -i '/settings::Settings/d' src/http3/server_push.rs
sed -i '/HeaderName, HeaderValue/d' src/http3/server_push.rs
sed -i '/VecDeque/d' src/http3/server_push.rs

# Fix unused imports in connection_manager.rs
sed -i '/common_errors/d' src/http3/connection_manager.rs
sed -i '/Http3FrameType/d' src/http3/connection_manager.rs
sed -i '/PushStreamState/d' src/http3/connection_manager.rs
sed -i '/HeaderName, HeaderValue/d' src/http3/connection_manager.rs
sed -i '/BytesMut/d' src/http3/connection_manager.rs

# Fix unused imports in stream_multiplexer.rs
sed -i 's/error::{Error, Result, Http3ErrorCode}/error::{Result, Http3ErrorCode}/' src/http3/stream_multiplexer.rs
sed -i '/common_errors/d' src/http3/stream_multiplexer.rs
sed -i '/StreamsBlockedFrame/d' src/http3/stream_multiplexer.rs
sed -i 's/priority::{Priority, PriorityScheduler, StreamPriority}/priority::{PriorityScheduler, StreamPriority}/' src/http3/stream_multiplexer.rs
sed -i '/StreamInfo, StreamState/d' src/http3/stream_multiplexer.rs
sed -i '/use bytes::{Bytes, BytesMut}/d' src/http3/stream_multiplexer.rs

# Fix unused imports in datagram.rs
sed -i 's/error::{Error, Result, Http3ErrorCode}/error::{Result, Http3ErrorCode}/' src/http3/datagram.rs
sed -i '/StreamType/d' src/http3/datagram.rs
sed -i '/quic::connection::ConnectionRole/d' src/http3/datagram.rs

# Fix unused imports in webtransport.rs
sed -i 's/error::{Error, Result, Http3ErrorCode}/error::{Result, Http3ErrorCode}/' src/http3/webtransport.rs
sed -i '/DatagramFrame/d' src/http3/webtransport.rs
sed -i '/StreamType/d' src/http3/webtransport.rs
sed -i '/HeaderName, HeaderValue/d' src/http3/webtransport.rs

# Fix unused imports in qpack modules
sed -i '/DynamicTableManager, InsertionPolicy/d' src/qpack/encoder.rs
sed -i 's/error::{Error, Result}/error::Result/' src/qpack/encoder_enhanced.rs
sed -i '/HeaderName, HeaderValue/d' src/qpack/encoder_enhanced.rs
sed -i '/VecDeque/d' src/qpack/encoder_enhanced.rs

# Fix unused imports in stream_manager.rs
sed -i '/EventKind/d' src/qpack/stream_manager.rs
sed -i '/quic::stream::StreamId/d' src/qpack/stream_manager.rs
sed -i 's/{debug, info, warn, error, protocol_event, span, time_block}/{protocol_event}/' src/qpack/stream_manager.rs
sed -i '/VecDeque/d' src/qpack/stream_manager.rs

# Fix unused imports in dynamic_table_manager.rs
sed -i 's/error::{Error, Result, QpackErrorCode}/error::{Result, QpackErrorCode}/' src/qpack/dynamic_table_manager.rs
sed -i '/common_errors/d' src/qpack/dynamic_table_manager.rs
sed -i '/HeaderName, HeaderValue/d' src/qpack/dynamic_table_manager.rs
sed -i '/encoder::Encoder/d' src/qpack/dynamic_table_manager.rs
sed -i '/decoder::Decoder/d' src/qpack/dynamic_table_manager.rs
sed -i '/DecoderInstruction/d' src/qpack/dynamic_table_manager.rs
sed -i '/use bytes::{Bytes, BytesMut, BufMut}/d' src/qpack/dynamic_table_manager.rs

# Fix unused imports in instruction_processor.rs
sed -i '/Config/d' src/qpack/instruction_processor.rs
sed -i '/common_errors/d' src/qpack/instruction_processor.rs
sed -i '/dynamic_table_manager::DynamicTableManager/d' src/qpack/instruction_processor.rs
sed -i 's/use bytes::{Bytes, BytesMut, Buf}/use bytes::{Bytes, Buf}/' src/qpack/instruction_processor.rs

# Fix unused imports in network.rs
sed -i 's/{Level, EventKind}/{Level}/' src/network.rs
sed -i 's/{debug, info, warn, error, net_event, span}/{net_event, span}/' src/network.rs

# Fix unused imports in client modules
sed -i '/network::NetworkEndpoint/d' src/client/builder.rs
sed -i 's/use tokio::sync::{mpsc, broadcast, RwLock}/use tokio::sync::Mutex/' src/server/builder.rs
sed -i '/std::collections::HashMap/d' src/server/builder.rs

# Fix unused imports in crypto_enhanced.rs
sed -i '/, Keys/d' src/quic/crypto_enhanced.rs

# Fix unused imports in recovery.rs
sed -i 's/packet::{Packet, PacketType, PacketHeader}/packet::{Packet, PacketType}/' src/quic/recovery.rs
sed -i 's/{Level, EventKind}/{Level}/' src/quic/recovery.rs
sed -i 's/{debug, info, warn, error, perf_event, span, time_block}/{perf_event, span}/' src/quic/recovery.rs

# Fix unused imports in congestion.rs
sed -i 's/ecn::{EcnController, EcnCodepoint, EcnCongestionEvent, EcnStats}/ecn::{EcnController, EcnCongestionEvent, EcnStats}/' src/quic/congestion.rs

# Fix unused imports in bbr.rs
sed -i 's/error::{Error, Result, Http3ErrorCode}/error::Result/' src/quic/bbr.rs
sed -i '/ErrorConversion, common_errors/d' src/quic/bbr.rs

# Fix unused imports in ack_manager.rs
sed -i 's/error::{Error, Result}/error::Result/' src/quic/ack_manager.rs
sed -i 's/{Level, EventKind}/{Level}/' src/quic/ack_manager.rs
sed -i 's/{debug, info, warn, error, protocol_event, span, time_block}/{protocol_event, span}/' src/quic/ack_manager.rs

# Fix unused imports in migration.rs
sed -i '/use bytes::{Bytes, BytesMut}/d' src/quic/migration.rs

# Fix unused imports in unreliable.rs
sed -i 's/error::{Error, Result, ConnectionErrorCode}/error::{Result, ConnectionErrorCode}/' src/quic/unreliable.rs
sed -i 's/collections::{VecDeque, HashMap}/collections::VecDeque/' src/quic/unreliable.rs

# Fix unused imports in version.rs
sed -i 's/packet::{ConnectionId, PacketHeader, LongHeader}/packet::ConnectionId/' src/quic/version.rs

# Fix unused imports in http3 modules
sed -i 's/{Level, EventKind}/{Level}/' src/http3/connection.rs
sed -i 's/{debug, info, warn, error, protocol_event, span, time_block}/{protocol_event, span}/' src/http3/connection.rs
sed -i 's/priority::{Priority, StreamPriority, PriorityScheduler}/priority::{Priority, StreamPriority}/' src/http3/stream.rs
sed -i 's/{Level, EventKind}/{Level}/' src/http3/stream.rs
sed -i 's/{debug, info, warn, error, protocol_event, span, time_block}/{protocol_event, span}/' src/http3/stream.rs
sed -i 's/{Level, EventKind}/{Level}/' src/http3/priority.rs
sed -i 's/{debug, info, warn, error, protocol_event, span, time_block}/{protocol_event}/' src/http3/priority.rs
sed -i 's/collections::{HashMap, BTreeMap, VecDeque}/collections::{HashMap, VecDeque}/' src/http3/priority.rs
sed -i '/use std::time::Duration/d' src/http3/priority.rs

# Remove unused ResultContext
sed -i '/error_context::ResultContext/d' src/quic/stream_manager.rs

echo "Fixing completed. Running cargo check..."
cargo check --all-features