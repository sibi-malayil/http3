/// HTTP/3 message types (Request and Response)

use std::collections::HashMap;

/// HTTP/3 Request
#[derive(Debug, Clone)]
pub struct Request {
    method: String,
    uri: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl Request {
    /// Create a new request builder
    pub fn builder() -> RequestBuilder {
        RequestBuilder::new()
    }

    /// Get the request method
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Get the request URI
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Get the request headers
    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    /// Get the request body
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// HTTP/3 Response
#[derive(Debug, Clone)]
pub struct Response {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl Response {
    /// Create a new response builder
    pub fn builder() -> ResponseBuilder {
        ResponseBuilder::new()
    }

    /// Get the response status code
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Get the response headers
    pub fn headers(&self) -> &HashMap<String, String> {
        &self.headers
    }

    /// Get the response body
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Request builder
pub struct RequestBuilder {
    method: String,
    uri: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl RequestBuilder {
    /// Create a new request builder
    pub fn new() -> Self {
        Self {
            method: "GET".to_string(),
            uri: "/".to_string(),
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    /// Set the request method
    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.method = method.into();
        self
    }

    /// Set the request URI
    pub fn uri(mut self, uri: impl Into<String>) -> Self {
        self.uri = uri.into();
        self
    }

    /// Add a header
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Set the request body
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Build the request
    pub fn build(self) -> Result<Request, String> {
        Ok(Request {
            method: self.method,
            uri: self.uri,
            headers: self.headers,
            body: self.body,
        })
    }
}

impl Default for RequestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Response builder
pub struct ResponseBuilder {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl ResponseBuilder {
    /// Create a new response builder
    pub fn new() -> Self {
        Self {
            status: 200,
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    /// Set the response status code
    pub fn status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    /// Add a header
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Set the response body
    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    /// Build the response
    pub fn build(self) -> Result<Response, String> {
        Ok(Response {
            status: self.status,
            headers: self.headers,
            body: self.body,
        })
    }
}

impl Default for ResponseBuilder {
    fn default() -> Self {
        Self::new()
    }
}