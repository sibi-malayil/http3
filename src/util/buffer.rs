use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::VecDeque;

/// Extension trait for Buf to add HTTP/3 specific operations
pub trait BufExt: Buf {
    /// Decode a variable-length integer from the buffer
    /// 
    /// # Errors
    /// 
    /// Returns an error if the varint cannot be decoded.
    fn get_var(&mut self) -> Result<crate::util::VarInt, crate::util::varint::VarIntDecodeError> where Self: Sized {
        crate::util::VarInt::decode(self)
    }

    /// Peek at the first byte without consuming it
    fn peek_u8(&self) -> Option<u8> {
        if self.has_remaining() {
            Some(self.chunk()[0])
        } else {
            None
        }
    }

    /// Get bytes from buffer if available
    fn get_bytes(&mut self, len: usize) -> Option<Bytes> {
        if self.remaining() >= len {
            let mut buf = BytesMut::with_capacity(len);
            buf.put(self.take(len));
            Some(buf.freeze())
        } else {
            None
        }
    }
}

// Rust 1.85: Using #[diagnostic::do_not_recommend] to guide better error messages
#[diagnostic::do_not_recommend]
impl<T: Buf> BufExt for T {}

/// Extension trait for BufMut to add varint encoding
pub trait BufMutExt: BufMut {
    /// Put a varint into the buffer
    fn put_var(&mut self, value: crate::util::VarInt) where Self: Sized {
        let _ = value.encode(self);
    }
}

// Rust 1.85: Using #[diagnostic::do_not_recommend] to guide better error messages
#[diagnostic::do_not_recommend]
impl<T: BufMut> BufMutExt for T {}

#[derive(Debug, Clone)]
/// Buffer that stores data in chunks
pub struct ChunkedBuffer {
    chunks: VecDeque<Bytes>,
    total_len: usize,
    position: usize,
}

impl ChunkedBuffer {
    /// Create a new chunked buffer
    #[must_use]
    pub fn new() -> Self {
        Self {
            chunks: VecDeque::new(),
            total_len: 0,
            position: 0,
        }
    }

    /// Create a new chunked buffer with initial capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            chunks: VecDeque::with_capacity(capacity),
            total_len: 0,
            position: 0,
        }
    }

    /// Add a chunk of data to the buffer
    pub fn push(&mut self, chunk: Bytes) {
        if !chunk.is_empty() {
            self.total_len += chunk.len();
            self.chunks.push_back(chunk);
        }
    }

    /// Clear all data from the buffer
    pub fn clear(&mut self) {
        self.chunks.clear();
        self.total_len = 0;
        self.position = 0;
    }

    /// Get the total length of data in the buffer
    #[must_use]
    pub const fn len(&self) -> usize {
        self.total_len - self.position
    }

    /// Check if the buffer is empty
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Linearize the buffer into a single contiguous chunk
    pub fn linearize(&mut self) -> Bytes {
        if self.chunks.is_empty() {
            return Bytes::new();
        }

        if self.chunks.len() == 1 {
            let chunk = self.chunks.pop_front().unwrap();
            let result = chunk.slice(self.position..);
            self.position = 0;
            self.total_len = 0;
            return result;
        }

        let mut buf = BytesMut::with_capacity(self.len());
        while let Some(chunk) = self.chunks.pop_front() {
            let start = if self.position > 0 {
                let pos = std::cmp::min(self.position, chunk.len());
                self.position -= pos;
                pos
            } else {
                0
            };
            buf.put(chunk.slice(start..));
        }

        self.position = 0;
        self.total_len = 0;
        buf.freeze()
    }
}

impl Default for ChunkedBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl Buf for ChunkedBuffer {
    fn remaining(&self) -> usize {
        self.len()
    }

    fn chunk(&self) -> &[u8] {
        // Using Rust 2024 let chains feature
        if let Some(chunk) = self.chunks.front()
            && let start = std::cmp::min(self.position, chunk.len())
            && let slice = &chunk[start..]
            && !slice.is_empty()
        {
            return slice;
        }
        &[]
    }

    fn advance(&mut self, mut cnt: usize) {
        assert!(cnt <= self.remaining());

        while cnt > 0 && !self.chunks.is_empty() {
            let chunk_len = self.chunks.front().unwrap().len();
            let available = chunk_len - std::cmp::min(self.position, chunk_len);
            
            if cnt >= available {
                cnt -= available;
                self.position += available;
                self.chunks.pop_front();
                self.position = 0;
            } else {
                self.position += cnt;
                cnt = 0;
            }
        }
    }
}

#[derive(Debug)]
/// Buffer for framing data with size limits
pub struct FrameBuffer {
    inner: ChunkedBuffer,
    max_size: usize,
}

impl FrameBuffer {
    /// Create a new frame buffer with maximum size limit
    pub fn new(max_size: usize) -> Self {
        Self {
            inner: ChunkedBuffer::new(),
            max_size,
        }
    }

    /// Write data to the buffer
    /// 
    /// # Errors
    /// 
    /// Returns an error if the data would exceed the maximum buffer size.
    pub fn write(&mut self, data: Bytes) -> Result<(), BufferError> {
        if self.inner.len() + data.len() > self.max_size {
            return Err(BufferError::ExceedsMaxSize);
        }
        self.inner.push(data);
        Ok(())
    }

    /// Read data from the buffer
    pub fn read(&mut self, len: usize) -> Option<Bytes> {
        if self.inner.len() >= len {
            let mut buf = BytesMut::with_capacity(len);
            let mut remaining = len;
            while remaining > 0 && self.inner.has_remaining() {
                let chunk_len = std::cmp::min(remaining, self.inner.remaining());
                buf.put((&mut self.inner).take(chunk_len));
                remaining -= chunk_len;
            }
            Some(buf.freeze())
        } else {
            None
        }
    }

    /// Peek at data without consuming it
    pub fn peek(&self, len: usize) -> Option<Bytes> {
        if self.inner.len() >= len {
            let clone = self.inner.clone();
            let mut buf = BytesMut::with_capacity(len);
            let mut remaining = len;
            let mut clone_mut = clone;
            while remaining > 0 && clone_mut.has_remaining() {
                let chunk_len = std::cmp::min(remaining, clone_mut.remaining());
                buf.put((&mut clone_mut).take(chunk_len));
                remaining -= chunk_len;
            }
            Some(buf.freeze())
        } else {
            None
        }
    }

    /// Get the amount of data available to read
    pub fn available(&self) -> usize {
        self.inner.len()
    }

    /// Get the remaining capacity for writing
    pub fn capacity(&self) -> usize {
        self.max_size - self.inner.len()
    }

    /// Clear all data from the buffer
    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
/// Buffer operation errors
pub enum BufferError {
    #[error("buffer exceeds maximum size")]
    /// Buffer size would exceed the maximum allowed
    ExceedsMaxSize,
    #[error("insufficient data in buffer")]
    /// Not enough data available in buffer
    InsufficientData,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked_buffer_basic_ops() {
        let mut buffer = ChunkedBuffer::new();
        assert_eq!(buffer.len(), 0);
        assert!(buffer.is_empty());

        buffer.push(Bytes::from("hello"));
        buffer.push(Bytes::from(" world"));
        assert_eq!(buffer.len(), 11);

        let linearized = buffer.linearize();
        assert_eq!(linearized, Bytes::from("hello world"));
        assert!(buffer.is_empty());
    }

    #[test]
    fn chunked_buffer_advance() {
        let mut buffer = ChunkedBuffer::new();
        buffer.push(Bytes::from("hello"));
        buffer.push(Bytes::from(" world"));

        assert_eq!(buffer.chunk(), b"hello");
        buffer.advance(3);
        assert_eq!(buffer.chunk(), b"lo");
        buffer.advance(2);
        assert_eq!(buffer.chunk(), b" world");
        buffer.advance(6);
        assert!(buffer.is_empty());
    }

    #[test]
    fn frame_buffer_size_limits() {
        let mut buffer = FrameBuffer::new(10);
        
        assert!(buffer.write(Bytes::from("hello")).is_ok());
        assert!(buffer.write(Bytes::from("world")).is_ok());
        assert!(buffer.write(Bytes::from("!")).is_err());

        assert_eq!(buffer.available(), 10);
        let data = buffer.read(5).unwrap();
        assert_eq!(data, Bytes::from("hello"));
        assert_eq!(buffer.available(), 5);
    }
}