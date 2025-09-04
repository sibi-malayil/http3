/// HTTP/3 server connection

use crate::{
    error::{Error, Result},
    http3::{Request, Response, connection::Connection as Http3Connection},
    quic::{connection::Connection as QuicConnection, stream::StreamId},
    qpack::{decoder::Decoder, encoder::Encoder, Config},
};
use bytes::{BytesMut, BufMut, Bytes};
use std::{
    net::SocketAddr,
    sync::Arc,
};
use tokio::sync::Mutex;

/// HTTP/3 server connection
pub struct ServerConnection {
    /// Underlying HTTP/3 connection
    h3_conn: Http3Connection,
    /// Underlying QUIC connection
    quic_conn: Arc<Mutex<QuicConnection>>,
    /// Peer address
    peer_addr: SocketAddr,
    /// QPACK decoder for incoming headers
    qpack_decoder: Arc<Mutex<Decoder>>,
    /// QPACK encoder for outgoing headers
    qpack_encoder: Arc<Mutex<Encoder>>,
}

impl ServerConnection {
    /// Create a new server connection
    pub fn new(
        quic_conn: Arc<Mutex<QuicConnection>>,
        peer_addr: SocketAddr,
    ) -> Result<Self> {
        // Create HTTP/3 connection
        let h3_conn = Http3Connection::new(quic_conn.clone())?;
        
        // Create QPACK encoder and decoder with default settings
        let qpack_config = Config {
            max_table_capacity: 4096,
            max_blocked_streams: 100,
            use_huffman: true,
        };
        
        let qpack_decoder = Arc::new(Mutex::new(Decoder::new(qpack_config.clone())));
        let qpack_encoder = Arc::new(Mutex::new(Encoder::new(qpack_config)));

        Ok(Self {
            h3_conn,
            quic_conn,
            peer_addr,
            qpack_decoder,
            qpack_encoder,
        })
    }

    /// Receive a request from the client
    pub fn recv_request(&mut self) -> Result<Option<(Request, StreamId)>> {
        // For now, return a placeholder implementation
        // In a real implementation, this would process incoming HTTP/3 frames
        // through the connection's frame processing pipeline
        
        // TODO: Implement proper HTTP/3 request reception using the frame-based approach
        // This requires integration with the QUIC connection's packet processing
        // and the HTTP/3 connection's frame handling
        
        Ok(None)
    }

    /// Send a response to the client
    pub async fn send_response(&mut self, stream_id: StreamId, response: Response) -> Result<()> {
        // Prepare headers for QPACK encoding
        let mut headers = Vec::new();
        
        // Add status pseudo-header
        headers.push(crate::qpack::field::HeaderField::new(
            crate::qpack::field::HeaderName::new(b":status".to_vec())?,
            crate::qpack::field::HeaderValue::new(response.status().to_string().into_bytes())?,
        ));
        
        // Add regular headers
        for (name, value) in response.headers() {
            headers.push(crate::qpack::field::HeaderField::new(
                crate::qpack::field::HeaderName::new(name.as_bytes().to_vec())?,
                crate::qpack::field::HeaderValue::new(value.as_bytes().to_vec())?,
            ));
        }
        
        // Encode headers using QPACK
        let mut encoder = self.qpack_encoder.lock().await;
        let encoded_headers = encoder.encode_field_section(stream_id.into_inner(), &headers, false)?;
        
        // Create HEADERS frame
        let mut frame_data = BytesMut::new();
        
        // Write frame type (0x01 for HEADERS)
        write_varint(&mut frame_data, 0x01);
        
        // Write frame length
        write_varint(&mut frame_data, encoded_headers.len() as u64);
        
        // Write encoded headers
        frame_data.extend_from_slice(&encoded_headers);
        
        // Send HEADERS frame
        let mut quic_conn = self.quic_conn.lock().await;
        quic_conn.stream_send(stream_id, frame_data.freeze(), false).await?;
        
        // Send DATA frame if there's a body
        if !response.body().is_empty() {
            let mut data_frame = BytesMut::new();
            
            // Write frame type (0x00 for DATA)
            write_varint(&mut data_frame, 0x00);
            
            // Write frame length
            write_varint(&mut data_frame, response.body().len() as u64);
            
            // Write body data
            data_frame.extend_from_slice(response.body());
            
            // Send DATA frame and close stream
            quic_conn.stream_send(stream_id, data_frame.freeze(), true).await?;
        } else {
            // Close stream with empty data
            quic_conn.stream_send(stream_id, Bytes::new(), true).await?;
        }
        
        Ok(())
    }

    /// Get the peer address
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

/// Read a variable-length integer from a cursor
fn read_varint(cursor: &mut std::io::Cursor<&[u8]>) -> Result<u64> {
    use std::io::Read;
    
    let mut first_byte = [0u8; 1];
    cursor.read_exact(&mut first_byte)
        .map_err(Error::Io)?;
    
    let len = match first_byte[0] >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };
    
    let mut value = (first_byte[0] & 0x3f) as u64;
    
    for _ in 1..len {
        let mut byte = [0u8; 1];
        cursor.read_exact(&mut byte)
            .map_err(Error::Io)?;
        value = (value << 8) | byte[0] as u64;
    }
    
    Ok(value)
}

/// Write a variable-length integer to a buffer
fn write_varint(buf: &mut BytesMut, value: u64) {
    if value < 64 {
        buf.put_u8(value as u8);
    } else if value < 16384 {
        buf.put_u8(0x40 | (value >> 8) as u8);
        buf.put_u8((value & 0xff) as u8);
    } else if value < 1073741824 {
        buf.put_u8(0x80 | (value >> 24) as u8);
        buf.put_u8(((value >> 16) & 0xff) as u8);
        buf.put_u8(((value >> 8) & 0xff) as u8);
        buf.put_u8((value & 0xff) as u8);
    } else {
        buf.put_u8(0xc0 | (value >> 56) as u8);
        buf.put_u8(((value >> 48) & 0xff) as u8);
        buf.put_u8(((value >> 40) & 0xff) as u8);
        buf.put_u8(((value >> 32) & 0xff) as u8);
        buf.put_u8(((value >> 24) & 0xff) as u8);
        buf.put_u8(((value >> 16) & 0xff) as u8);
        buf.put_u8(((value >> 8) & 0xff) as u8);
        buf.put_u8((value & 0xff) as u8);
    }
}