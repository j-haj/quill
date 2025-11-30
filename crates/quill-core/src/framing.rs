//! Stream framing for Quill RPC.
//!
//! Frame format: [length varint][flags byte][payload bytes]
//! Flags: DATA(bit 0), END_STREAM(bit 1), CANCEL(bit 2), CREDIT(bit 3)

use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Maximum frame size (4MB)
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024;

/// Frame flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameFlags(u8);

impl FrameFlags {
    pub const DATA: u8 = 0b0000_0001;
    pub const END_STREAM: u8 = 0b0000_0010;
    pub const CANCEL: u8 = 0b0000_0100;
    pub const CREDIT: u8 = 0b0000_1000;

    pub fn new(flags: u8) -> Self {
        Self(flags)
    }

    pub fn empty() -> Self {
        Self(0)
    }

    pub fn is_data(&self) -> bool {
        self.0 & Self::DATA != 0
    }

    pub fn is_end_stream(&self) -> bool {
        self.0 & Self::END_STREAM != 0
    }

    pub fn is_cancel(&self) -> bool {
        self.0 & Self::CANCEL != 0
    }

    pub fn is_credit(&self) -> bool {
        self.0 & Self::CREDIT != 0
    }

    pub fn as_u8(&self) -> u8 {
        self.0
    }
}

/// A frame in a Quill stream
#[derive(Debug, Clone)]
pub struct Frame {
    pub flags: FrameFlags,
    pub payload: Bytes,
}

impl Frame {
    /// Create a new data frame
    pub fn data(payload: Bytes) -> Self {
        Self {
            flags: FrameFlags::new(FrameFlags::DATA),
            payload,
        }
    }

    /// Create an end-of-stream frame
    pub fn end_stream() -> Self {
        Self {
            flags: FrameFlags::new(FrameFlags::END_STREAM),
            payload: Bytes::new(),
        }
    }

    /// Create a cancel frame
    pub fn cancel() -> Self {
        Self {
            flags: FrameFlags::new(FrameFlags::CANCEL),
            payload: Bytes::new(),
        }
    }

    /// Create a credit frame with the specified number of credits
    pub fn credit(credits: u32) -> Self {
        let mut buf = BytesMut::new();
        encode_varint(credits as u64, &mut buf);
        Self {
            flags: FrameFlags::new(FrameFlags::CREDIT),
            payload: buf.freeze(),
        }
    }

    /// Decode credit value from a credit frame
    pub fn decode_credit(&self) -> Option<u32> {
        if !self.flags.is_credit() {
            return None;
        }
        let mut cursor = std::io::Cursor::new(&self.payload[..]);
        decode_varint(&mut cursor).map(|v| v as u32)
    }

    /// Encode this frame to bytes
    pub fn encode(&self) -> Bytes {
        let payload_len = self.payload.len();
        let mut buf = BytesMut::new();

        // Encode length as varint
        encode_varint(payload_len as u64, &mut buf);

        // Encode flags
        buf.put_u8(self.flags.as_u8());

        // Encode payload
        buf.put_slice(&self.payload);

        buf.freeze()
    }
}

/// Frame parser for decoding frames from a byte stream
pub struct FrameParser {
    buffer: BytesMut,
}

impl FrameParser {
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::new(),
        }
    }

    /// Add data to the parser buffer
    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Try to parse a complete frame from the buffer
    pub fn parse_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        // Need at least 2 bytes (min varint + flags)
        if self.buffer.len() < 2 {
            return Ok(None);
        }

        let mut cursor = std::io::Cursor::new(&self.buffer[..]);

        // Decode length varint
        let payload_len = match decode_varint(&mut cursor) {
            Some(len) => len as usize,
            None => return Ok(None), // Need more data
        };

        if payload_len > MAX_FRAME_SIZE {
            return Err(FrameError::FrameTooLarge(payload_len));
        }

        let header_len = cursor.position() as usize;

        // Check if we have the full frame
        let total_len = header_len + 1 + payload_len; // +1 for flags byte
        if self.buffer.len() < total_len {
            return Ok(None); // Need more data
        }

        // Parse flags
        let flags = FrameFlags::new(self.buffer[header_len]);

        // Extract payload
        let payload_start = header_len + 1;
        let payload = self.buffer[payload_start..payload_start + payload_len].to_vec();

        // Advance buffer
        self.buffer.advance(total_len);

        Ok(Some(Frame {
            flags,
            payload: Bytes::from(payload),
        }))
    }
}

impl Default for FrameParser {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("Frame too large: {0} bytes (max {MAX_FRAME_SIZE})")]
    FrameTooLarge(usize),

    #[error("Invalid varint encoding")]
    InvalidVarint,
}

/// Encode a u64 as a protobuf varint
pub fn encode_varint(mut value: u64, buf: &mut BytesMut) {
    loop {
        if value < 0x80 {
            buf.put_u8(value as u8);
            break;
        } else {
            buf.put_u8(((value & 0x7F) | 0x80) as u8);
            value >>= 7;
        }
    }
}

/// Decode a protobuf varint from a cursor
pub fn decode_varint<B: Buf>(buf: &mut B) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0;

    loop {
        if !buf.has_remaining() {
            return None;
        }

        let byte = buf.get_u8();
        value |= ((byte & 0x7F) as u64) << shift;

        if byte < 0x80 {
            return Some(value);
        }

        shift += 7;
        if shift >= 64 {
            return None; // Overflow
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_roundtrip() {
        let mut buf = BytesMut::new();
        encode_varint(150, &mut buf);

        let mut cursor = std::io::Cursor::new(&buf[..]);
        let decoded = decode_varint(&mut cursor).unwrap();
        assert_eq!(decoded, 150);
    }

    #[test]
    fn test_frame_roundtrip() {
        let original = Frame::data(Bytes::from("hello"));
        let encoded = original.encode();

        let mut parser = FrameParser::new();
        parser.feed(&encoded);

        let decoded = parser.parse_frame().unwrap().unwrap();
        assert_eq!(decoded.payload, original.payload);
        assert_eq!(decoded.flags.as_u8(), original.flags.as_u8());
    }

    #[test]
    fn test_frame_flags() {
        let flags = FrameFlags::new(FrameFlags::DATA | FrameFlags::END_STREAM);
        assert!(flags.is_data());
        assert!(flags.is_end_stream());
        assert!(!flags.is_cancel());
        assert!(!flags.is_credit());
    }

    #[test]
    fn test_credit_frame() {
        let credits = 42u32;
        let frame = Frame::credit(credits);

        assert!(frame.flags.is_credit());
        assert!(!frame.flags.is_data());
        assert_eq!(frame.decode_credit(), Some(credits));
    }

    #[test]
    fn test_credit_frame_roundtrip() {
        let original = Frame::credit(100);
        let encoded = original.encode();

        let mut parser = FrameParser::new();
        parser.feed(&encoded);

        let decoded = parser.parse_frame().unwrap().unwrap();
        assert!(decoded.flags.is_credit());
        assert_eq!(decoded.decode_credit(), Some(100));
    }
}
