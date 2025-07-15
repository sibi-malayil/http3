/// HTTP/3 server connection

use crate::{
    error::{Error, Result},
    http3::{Request, Response, connection::Connection as Http3Connection},
    quic::{connection::Connection as QuicConnection, stream::StreamId},
};
use std::{
    net::SocketAddr,
    sync::Arc,
};
use tokio::sync::Mutex;

/// HTTP/3 server connection
pub struct ServerConnection {
    /// Underlying HTTP/3 connection
    h3_conn: Http3Connection,
    /// Peer address
    peer_addr: SocketAddr,
}

impl ServerConnection {
    /// Create a new server connection
    pub async fn new(
        quic_conn: Arc<Mutex<QuicConnection>>,
        peer_addr: SocketAddr,
    ) -> Result<Self> {
        // Create HTTP/3 connection
        let h3_conn = Http3Connection::new(quic_conn)?;

        Ok(Self {
            h3_conn,
            peer_addr,
        })
    }

    /// Receive a request from the client
    pub async fn recv_request(&mut self) -> Result<Option<(Request, StreamId)>> {
        // TODO: Implement request reception
        // This is a placeholder that needs to be implemented
        // It should:
        // 1. Wait for incoming streams
        // 2. Read HTTP/3 frames
        // 3. Parse headers and body
        // 4. Return the request and stream ID
        
        Err(Error::NotImplemented("Request reception not yet implemented".to_string()))
    }

    /// Send a response to the client
    pub async fn send_response(&mut self, stream_id: StreamId, response: Response) -> Result<()> {
        // TODO: Implement response sending
        // This is a placeholder that needs to be implemented
        // It should:
        // 1. Encode response headers using QPACK
        // 2. Send HEADERS frame
        // 3. Send DATA frames for body
        
        Err(Error::NotImplemented("Response sending not yet implemented".to_string()))
    }

    /// Get the peer address
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}