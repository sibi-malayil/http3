//! Header field definitions and utilities for QPACK

use crate::error::{Error, Result};
use bytes::Bytes;
use std::fmt;
use std::str::FromStr;

/// HTTP header field name
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HeaderName {
    inner: Bytes,
}

impl HeaderName {
    /// Create a new header name
    /// 
    /// # Errors
    /// 
    /// Returns an error if the name is empty or contains invalid characters.
    pub fn new(name: impl Into<Bytes>) -> Result<Self> {
        let inner = name.into();
        
        // Validate header name according to RFC 7230
        if inner.is_empty() {
            return Err(Error::QpackInvalidHeaderName);
        }
        
        for &byte in &inner {
            if !is_valid_header_name_byte(byte) {
                return Err(Error::QpackInvalidHeaderName);
            }
        }
        
        Ok(Self { inner })
    }
    
    /// Get the header name as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }
    
    /// Get the header name as a string slice
    pub fn as_str(&self) -> &str {
        // Safety: We validated the bytes during construction
        std::str::from_utf8(&self.inner).unwrap()
    }
    
    /// Convert to lowercase (HTTP header names are case-insensitive)
    pub fn to_lowercase(&self) -> Self {
        let lower = self.inner.iter()
            .map(|&b| b.to_ascii_lowercase())
            .collect::<Vec<_>>();
        Self { inner: Bytes::from(lower) }
    }
}

impl fmt::Display for HeaderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for HeaderName {
    type Err = Error;
    
    fn from_str(s: &str) -> Result<Self> {
        Self::new(s.as_bytes().to_vec())
    }
}

impl From<&str> for HeaderName {
    fn from(s: &str) -> Self {
        Self::new(s.as_bytes().to_vec()).unwrap()
    }
}

impl From<String> for HeaderName {
    fn from(s: String) -> Self {
        Self::new(s.into_bytes()).unwrap()
    }
}

/// HTTP header field value
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HeaderValue {
    inner: Bytes,
}

impl HeaderValue {
    /// Create a new header value
    /// 
    /// # Errors
    /// 
    /// Returns an error if the value contains invalid characters.
    pub fn new(value: impl Into<Bytes>) -> Result<Self> {
        let inner = value.into();
        
        // Validate header value according to RFC 7230
        for &byte in &inner {
            if !is_valid_header_value_byte(byte) {
                return Err(Error::QpackInvalidHeaderValue);
            }
        }
        
        Ok(Self { inner })
    }
    
    /// Get the header value as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }
    
    /// Get the header value as a string slice
    /// 
    /// # Errors
    /// 
    /// Returns an error if the value contains invalid UTF-8.
    pub fn as_str(&self) -> Result<&str> {
        std::str::from_utf8(&self.inner)
            .map_err(|_| Error::QpackInvalidHeaderValue)
    }
    
    /// Get the length in bytes
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    
    /// Check if the value is empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Display for HeaderValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Ok(s) => write!(f, "{}", s),
            Err(_) => write!(f, "{:?}", self.inner),
        }
    }
}

impl FromStr for HeaderValue {
    type Err = Error;
    
    fn from_str(s: &str) -> Result<Self> {
        Self::new(s.as_bytes().to_vec())
    }
}

impl From<&str> for HeaderValue {
    fn from(s: &str) -> Self {
        Self::new(s.as_bytes().to_vec()).unwrap()
    }
}

impl From<String> for HeaderValue {
    fn from(s: String) -> Self {
        Self::new(s.into_bytes()).unwrap()
    }
}

impl From<i32> for HeaderValue {
    fn from(n: i32) -> Self {
        Self::new(n.to_string().into_bytes()).unwrap()
    }
}

impl From<u32> for HeaderValue {
    fn from(n: u32) -> Self {
        Self::new(n.to_string().into_bytes()).unwrap()
    }
}

/// HTTP header field (name-value pair)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HeaderField {
    /// Header field name
    pub name: HeaderName,
    /// Header field value
    pub value: HeaderValue,
}

impl HeaderField {
    /// Create a new header field
    pub fn new(name: HeaderName, value: HeaderValue) -> Self {
        Self { name, value }
    }
    
    /// Create a new header field that should never be indexed
    pub fn new_never_index(name: HeaderName, value: HeaderValue) -> Self {
        // For now, same as new() since never_index is determined by header name
        Self { name, value }
    }
    
    /// Calculate the size of this header field for QPACK table accounting
    /// Size = name_length + value_length + 32 (overhead)
    pub fn size(&self) -> usize {
        self.name.as_bytes().len() + self.value.as_bytes().len() + 32
    }
    
    /// Calculate the encoded size as u64 for compatibility
    pub fn encoded_size(&self) -> u64 {
        self.size() as u64
    }
    
    /// Check if this header field should never be indexed
    pub fn never_index(&self) -> bool {
        // Certain security-sensitive headers should never be indexed
        matches!(self.name.as_str(),
            "authorization" | "cookie" | "set-cookie" | 
            "proxy-authorization" | "www-authenticate" |
            "proxy-authenticate" | "x-forwarded-for"
        )
    }
}

impl fmt::Display for HeaderField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.name, self.value)
    }
}

/// Check if a byte is valid in an HTTP header name
fn is_valid_header_name_byte(byte: u8) -> bool {
    matches!(byte,
        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' |
        b'-' | b'_' | b'.' | b'~' | b'!' | b'#' |
        b'$' | b'&' | b'\'' | b'*' | b'+' | b'^' |
        b'`' | b'|' | b':' // Allow ':' for pseudo-headers
    )
}

/// Check if a byte is valid in an HTTP header value
fn is_valid_header_value_byte(byte: u8) -> bool {
    // Using Rust 1.80 exclusive range patterns
    // Allow visible ASCII characters plus space and tab
    matches!(byte, 0x09 | 0x20..0x7F)
}

/// Common HTTP header names as constants
pub mod names {
    use super::HeaderName;
    
    macro_rules! header_name {
        ($name:ident, $value:expr) => {
            #[doc = concat!("HTTP header name constant for `", $value, "`")]
            pub const $name: HeaderName = HeaderName {
                inner: bytes::Bytes::from_static($value.as_bytes()),
            };
        };
    }
    
    header_name!(ACCEPT, "accept");
    header_name!(ACCEPT_CHARSET, "accept-charset");
    header_name!(ACCEPT_ENCODING, "accept-encoding");
    header_name!(ACCEPT_LANGUAGE, "accept-language");
    header_name!(ACCEPT_RANGES, "accept-ranges");
    header_name!(ACCESS_CONTROL_ALLOW_ORIGIN, "access-control-allow-origin");
    header_name!(AGE, "age");
    header_name!(ALLOW, "allow");
    header_name!(AUTHORIZATION, "authorization");
    header_name!(CACHE_CONTROL, "cache-control");
    header_name!(CONTENT_DISPOSITION, "content-disposition");
    header_name!(CONTENT_ENCODING, "content-encoding");
    header_name!(CONTENT_LENGTH, "content-length");
    header_name!(CONTENT_LOCATION, "content-location");
    header_name!(CONTENT_RANGE, "content-range");
    header_name!(CONTENT_TYPE, "content-type");
    header_name!(COOKIE, "cookie");
    header_name!(DATE, "date");
    header_name!(ETAG, "etag");
    header_name!(EXPECT, "expect");
    header_name!(EXPIRES, "expires");
    header_name!(FROM, "from");
    header_name!(HOST, "host");
    header_name!(IF_MATCH, "if-match");
    header_name!(IF_MODIFIED_SINCE, "if-modified-since");
    header_name!(IF_NONE_MATCH, "if-none-match");
    header_name!(IF_RANGE, "if-range");
    header_name!(IF_UNMODIFIED_SINCE, "if-unmodified-since");
    header_name!(LAST_MODIFIED, "last-modified");
    header_name!(LINK, "link");
    header_name!(LOCATION, "location");
    header_name!(MAX_FORWARDS, "max-forwards");
    header_name!(PROXY_AUTHENTICATE, "proxy-authenticate");
    header_name!(PROXY_AUTHORIZATION, "proxy-authorization");
    header_name!(RANGE, "range");
    header_name!(REFERER, "referer");
    header_name!(REFRESH, "refresh");
    header_name!(RETRY_AFTER, "retry-after");
    header_name!(SERVER, "server");
    header_name!(SET_COOKIE, "set-cookie");
    header_name!(STRICT_TRANSPORT_SECURITY, "strict-transport-security");
    header_name!(TRANSFER_ENCODING, "transfer-encoding");
    header_name!(USER_AGENT, "user-agent");
    header_name!(VARY, "vary");
    header_name!(VIA, "via");
    header_name!(WWW_AUTHENTICATE, "www-authenticate");
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn header_name_validation() {
        assert!(HeaderName::new("content-type").is_ok());
        assert!(HeaderName::new("Content-Type").is_ok());
        assert!(HeaderName::new("x-custom-header").is_ok());
        assert!(HeaderName::new("").is_err());
        assert!(HeaderName::new("invalid\0name").is_err());
        assert!(HeaderName::new("invalid name").is_err());
    }
    
    #[test]
    fn header_value_validation() {
        assert!(HeaderValue::new("text/html").is_ok());
        assert!(HeaderValue::new("").is_ok());
        assert!(HeaderValue::new("value with spaces").is_ok());
        assert!(HeaderValue::new("value\twith\ttab").is_ok());
        assert!(HeaderValue::new("invalid\0value").is_err());
        assert!(HeaderValue::new("invalid\nvalue").is_err());
    }
    
    #[test]
    fn header_field_size() {
        let field = HeaderField::new(
            HeaderName::new("content-type").unwrap(),
            HeaderValue::new("text/html").unwrap(),
        );
        // "content-type" (12) + "text/html" (9) + 32 = 53
        assert_eq!(field.size(), 53);
    }
    
    #[test]
    fn never_index_headers() {
        let auth_field = HeaderField::new(
            HeaderName::new("authorization").unwrap(),
            HeaderValue::new("Bearer token").unwrap(),
        );
        assert!(auth_field.never_index());
        
        let normal_field = HeaderField::new(
            HeaderName::new("content-type").unwrap(),
            HeaderValue::new("text/html").unwrap(),
        );
        assert!(!normal_field.never_index());
    }
    
    #[test]
    fn header_name_case_conversion() {
        let name = HeaderName::new("Content-Type").unwrap();
        let lower = name.to_lowercase();
        assert_eq!(lower.as_str(), "content-type");
    }
}