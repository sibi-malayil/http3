//! HTTP/3 client connection management
//!
//! Implements high-level HTTP/3 client connection handling.

use crate::{
    error::{Error, Result},
    http3::{
        connection::Connection as Http3Connection,
        stream::{Stream, StreamEvent},
    },
    qpack::field::{HeaderField, HeaderName, HeaderValue},
    quic::connection::Connection as QuicConnection,
};
use bytes::{Bytes, BytesMut};
use std::{
    collections::HashMap,
    sync::Arc,
};
use tokio::sync::{mpsc, Mutex};
use url::Url;

/// HTTP request method
#[derive(Debug, Clone, PartialEq)]
pub enum Method {
    /// GET method
    Get,
    /// POST method
    Post,
    /// PUT method
    Put,
    /// DELETE method
    Delete,
    /// HEAD method
    Head,
    /// OPTIONS method
    Options,
    /// CONNECT method
    Connect,
    /// TRACE method
    Trace,
    /// PATCH method
    Patch,
}

impl Method {
    /// Convert to string representation
    pub fn as_str(&self) -> &str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
            Method::Head => "HEAD",
            Method::Options => "OPTIONS",
            Method::Connect => "CONNECT",
            Method::Trace => "TRACE",
            Method::Patch => "PATCH",
        }
    }
}

/// HTTP/3 client connection
pub struct ClientConnection {
    /// HTTP/3 connection
    h3_conn: Arc<Mutex<Http3Connection>>,
    /// URL of the server
    server_url: Url,
    /// Active request streams
    active_streams: Arc<Mutex<HashMap<u64, mpsc::UnboundedReceiver<StreamEvent>>>>,
}

impl ClientConnection {
    /// Create a new client connection
    pub async fn new(quic_conn: Arc<Mutex<QuicConnection>>, server_url: Url) -> Result<Self> {
        let mut h3_conn = Http3Connection::new(quic_conn)?;
        h3_conn.initialize().await?;
        
        Ok(Self {
            h3_conn: Arc::new(Mutex::new(h3_conn)),
            server_url,
            active_streams: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Send an HTTP request
    pub async fn request(
        &self,
        method: Method,
        path: &str,
        headers: Option<Vec<HeaderField>>,
        body: Option<Bytes>,
    ) -> Result<Response> {
        // Create request stream
        let stream = {
            let h3_conn = self.h3_conn.lock().await;
            h3_conn.create_request_stream().await?
        };
        
        let stream_id = {
            let stream = stream.lock().await;
            stream.id().into_inner()
        };
        
        // Create event receiver
        let event_rx = {
            let mut stream = stream.lock().await;
            stream.create_event_receiver()
        };
        
        // Store event receiver
        {
            let mut active_streams = self.active_streams.lock().await;
            active_streams.insert(stream_id, event_rx);
        }
        
        // Build request headers
        let mut request_headers = self.build_request_headers(method, path)?;
        if let Some(extra_headers) = headers {
            request_headers.extend(extra_headers);
        }
        
        // Send headers
        {
            let mut stream = stream.lock().await;
            stream.send_headers(request_headers).await?;
        }
        
        // Send body if provided
        if let Some(body) = body {
            let mut stream = stream.lock().await;
            stream.send_data(body).await?;
        }
        
        // Create response
        Ok(Response {
            stream,
            stream_id,
            active_streams: self.active_streams.clone(),
            headers_received: false,
            body_buffer: BytesMut::new(),
        })
    }

    /// Build request headers
    fn build_request_headers(&self, method: Method, path: &str) -> Result<Vec<HeaderField>> {
        let mut headers = Vec::new();
        
        // Required pseudo-headers
        headers.push(HeaderField::new(
            HeaderName::from(":method"),
            HeaderValue::from(method.as_str()),
        ));
        
        headers.push(HeaderField::new(
            HeaderName::from(":scheme"),
            HeaderValue::from(self.server_url.scheme()),
        ));
        
        headers.push(HeaderField::new(
            HeaderName::from(":authority"),
            HeaderValue::from(self.server_url.host_str().unwrap_or("localhost")),
        ));
        
        headers.push(HeaderField::new(
            HeaderName::from(":path"),
            HeaderValue::from(path),
        ));
        
        Ok(headers)
    }

    /// Send a GET request
    pub async fn get(&self, path: &str) -> Result<Response> {
        self.request(Method::Get, path, None, None).await
    }

    /// Send a POST request
    pub async fn post(&self, path: &str, body: Bytes) -> Result<Response> {
        self.request(Method::Post, path, None, Some(body)).await
    }

    /// Send a PUT request
    pub async fn put(&self, path: &str, body: Bytes) -> Result<Response> {
        self.request(Method::Put, path, None, Some(body)).await
    }

    /// Send a DELETE request
    pub async fn delete(&self, path: &str) -> Result<Response> {
        self.request(Method::Delete, path, None, None).await
    }

    /// Close the connection
    pub async fn close(&self) -> Result<()> {
        let mut h3_conn = self.h3_conn.lock().await;
        h3_conn.close(0, "Client closing connection".to_string()).await
    }

    /// Send an HTTP/3 request
    pub async fn send_request(&self, request: crate::http3::Request) -> Result<Response> {
        // Convert to internal method type
        let method = match request.method() {
            "GET" => Method::Get,
            "POST" => Method::Post,
            "PUT" => Method::Put,
            "DELETE" => Method::Delete,
            "HEAD" => Method::Head,
            "OPTIONS" => Method::Options,
            "CONNECT" => Method::Connect,
            "TRACE" => Method::Trace,
            "PATCH" => Method::Patch,
            _ => return Err(Error::ProtocolViolation(format!("Unsupported method: {}", request.method()))),
        };

        // Extract headers
        let mut headers = Vec::new();
        for (name, value) in request.headers() {
            headers.push(HeaderField::new(
                HeaderName::from(name.as_str()),
                HeaderValue::from(value.as_str()),
            ));
        }

        // Send request with body
        let body = if request.body().is_empty() {
            None
        } else {
            Some(Bytes::from(request.body().to_vec()))
        };

        self.request(method, request.uri(), Some(headers), body).await
    }
}

/// HTTP response
pub struct Response {
    /// Stream for this response
    stream: Arc<Mutex<Stream>>,
    /// Stream ID
    stream_id: u64,
    /// Active streams map
    active_streams: Arc<Mutex<HashMap<u64, mpsc::UnboundedReceiver<StreamEvent>>>>,
    /// Whether headers have been received
    headers_received: bool,
    /// Body buffer
    body_buffer: BytesMut,
}

impl Response {
    /// Get response headers
    pub async fn headers(&mut self) -> Result<Vec<HeaderField>> {
        if !self.headers_received {
            let mut event_rx = {
                let mut active_streams = self.active_streams.lock().await;
                active_streams.remove(&self.stream_id)
                    .ok_or_else(|| Error::StreamError {
                        code: crate::error::StreamErrorCode::IdError,
                        reason: "Stream not found".to_string()
                    })?
            };
            
            // Wait for headers event
            match event_rx.recv().await {
                Some(StreamEvent::Headers(headers)) => {
                    self.headers_received = true;
                    // Put receiver back
                    let mut active_streams = self.active_streams.lock().await;
                    active_streams.insert(self.stream_id, event_rx);
                    return Ok(headers);
                }
                _ => {
                    return Err(Error::StreamError {
                        code: crate::error::StreamErrorCode::FrameUnexpected,
                        reason: "Unexpected stream event".to_string()
                    });
                }
            }
        }
        
        Err(Error::StreamError {
            code: crate::error::StreamErrorCode::FrameUnexpected,
            reason: "Headers already received".to_string()
        })
    }

    /// Get response status code
    pub async fn status(&mut self) -> Result<u16> {
        let headers = self.headers().await?;
        
        for header in headers {
            if header.name.as_str() == ":status" {
                let status_str = header.value.as_str()
                    .map_err(|_| Error::ProtocolViolation("Invalid status header".to_string()))?;
                return status_str.parse()
                    .map_err(|_| Error::ProtocolViolation("Invalid status code".to_string()));
            }
        }
        
        Err(Error::ProtocolViolation("Missing status header".to_string()))
    }

    /// Read response body
    pub async fn body(&mut self) -> Result<Bytes> {
        let mut event_rx = {
            let mut active_streams = self.active_streams.lock().await;
            active_streams.remove(&self.stream_id)
                .ok_or_else(|| Error::StreamError {
                    code: crate::error::StreamErrorCode::IdError,
                    reason: "Stream not found".to_string()
                })?
        };
        
        // Collect all body data
        while let Some(event) = event_rx.recv().await {
            match event {
                StreamEvent::Data(data) => {
                    self.body_buffer.extend_from_slice(&data);
                }
                StreamEvent::Finished => {
                    break;
                }
                StreamEvent::Reset(error_code) => {
                    return Err(Error::StreamError {
                        code: crate::error::StreamErrorCode::RequestCancelled,
                        reason: format!("Stream reset with error {}", error_code)
                    });
                }
                _ => {}
            }
        }
        
        Ok(self.body_buffer.split().freeze())
    }

    /// Read response body as text
    pub async fn text(&mut self) -> Result<String> {
        let body = self.body().await?;
        String::from_utf8(body.to_vec())
            .map_err(|_| Error::ProtocolViolation("Invalid UTF-8 in response body".to_string()))
    }

    /// Read response body as JSON
    #[cfg(feature = "json")]
    pub async fn json<T: serde::de::DeserializeOwned>(&mut self) -> Result<T> {
        let body = self.body().await?;
        serde_json::from_slice(&body)
            .map_err(|e| Error::ProtocolViolation(format!("JSON parse error: {}", e)))
    }

    /// Read response body (alias for body())
    pub async fn read_body(&mut self) -> Result<Bytes> {
        self.body().await
    }
}