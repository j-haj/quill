//! WebTransport Example
//!
//! This example demonstrates WebTransport for browser and native client support.
//! WebTransport provides bidirectional communication over HTTP/3 with support for:
//! - Bidirectional streams
//! - Unidirectional streams
//! - Unreliable datagrams
//!
//! # Browser Client
//!
//! Browsers can connect using the native WebTransport API:
//!
//! ```javascript
//! const transport = new WebTransport('https://localhost:4433/webtransport');
//! await transport.ready;
//!
//! // Send datagram
//! const writer = transport.datagrams.writable.getWriter();
//! await writer.write(new TextEncoder().encode('Hello!'));
//!
//! // Read datagram
//! const reader = transport.datagrams.readable.getReader();
//! const { value } = await reader.read();
//! console.log(new TextDecoder().decode(value));
//!
//! // Use bidirectional stream
//! const stream = await transport.createBidirectionalStream();
//! const streamWriter = stream.writable.getWriter();
//! await streamWriter.write(new TextEncoder().encode('Stream data'));
//! ```
//!
//! # Native Rust Client
//!
//! Native clients use the WebTransportClient:
//!
//! ```ignore
//! use quill_transport::{WebTransportClientBuilder, WebTransportError};
//!
//! let client = WebTransportClientBuilder::new()
//!     .enable_datagrams(true)
//!     .build()?;
//!
//! let session = client.connect(addr, "localhost", "/webtransport").await?;
//!
//! // Send datagram
//! session.send_datagram(Bytes::from("Hello!"))?;
//!
//! // Use streams
//! let (send, recv) = session.open_bi().await?;
//! ```

use bytes::Bytes;
use quill_transport::{
    FnWebTransportHandler, Session, WebTransportClientBuilder, WebTransportError,
    WebTransportServer, WebTransportServerBuilder,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Statistics for WebTransport sessions
#[derive(Default)]
pub struct SessionStats {
    pub sessions_created: AtomicU64,
    pub datagrams_received: AtomicU64,
    pub streams_opened: AtomicU64,
}

impl SessionStats {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn record_session(&self) {
        self.sessions_created.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_datagram(&self) {
        self.datagrams_received.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_stream(&self) {
        self.streams_opened.fetch_add(1, Ordering::Relaxed);
    }
}

/// Default WebTransport path
pub const WEBTRANSPORT_PATH: &str = "/webtransport";

/// Default bind address
pub const DEFAULT_ADDR: &str = "127.0.0.1:4433";

/// Create a simple echo handler that logs session information
pub fn create_echo_handler(stats: Arc<SessionStats>) -> impl quill_transport::WebTransportHandler {
    FnWebTransportHandler::new(move |session: Session| {
        let stats = stats.clone();
        async move {
            stats.record_session();

            tracing::info!(
                "New WebTransport session: id={}, remote={}",
                session.session_id(),
                session.remote_addr()
            );

            // In a real implementation, you would:
            // 1. Accept incoming streams
            // 2. Process stream data
            // 3. Send responses
            // 4. Handle datagrams

            Ok(())
        }
    })
}

/// Build a WebTransport server with default configuration
pub fn build_server(addr: SocketAddr) -> Result<WebTransportServer, WebTransportError> {
    WebTransportServerBuilder::new(addr)
        .enable_datagrams(true)
        .max_datagram_size(65536)
        .max_sessions(100)
        .max_concurrent_streams(100)
        .session_timeout_ms(60000)
        .build()
}

/// Build a WebTransport client with default configuration
pub fn build_client() -> Result<quill_transport::WebTransportClient, WebTransportError> {
    // Install crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();

    WebTransportClientBuilder::new()
        .enable_datagrams(true)
        .max_datagram_size(65536)
        .build()
}

/// Example message types for the WebTransport protocol
#[derive(Debug, Clone)]
pub enum Message {
    /// Text message
    Text(String),
    /// Binary data
    Binary(Vec<u8>),
    /// Ping request
    Ping(u64),
    /// Pong response
    Pong(u64),
}

impl Message {
    /// Encode message to bytes
    pub fn encode(&self) -> Bytes {
        match self {
            Message::Text(text) => {
                let mut buf = vec![0x01]; // Type: Text
                buf.extend_from_slice(text.as_bytes());
                Bytes::from(buf)
            }
            Message::Binary(data) => {
                let mut buf = vec![0x02]; // Type: Binary
                buf.extend_from_slice(data);
                Bytes::from(buf)
            }
            Message::Ping(seq) => {
                let mut buf = vec![0x03]; // Type: Ping
                buf.extend_from_slice(&seq.to_le_bytes());
                Bytes::from(buf)
            }
            Message::Pong(seq) => {
                let mut buf = vec![0x04]; // Type: Pong
                buf.extend_from_slice(&seq.to_le_bytes());
                Bytes::from(buf)
            }
        }
    }

    /// Decode message from bytes
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        match data[0] {
            0x01 => {
                // Text
                let text = String::from_utf8(data[1..].to_vec()).ok()?;
                Some(Message::Text(text))
            }
            0x02 => {
                // Binary
                Some(Message::Binary(data[1..].to_vec()))
            }
            0x03 => {
                // Ping
                if data.len() < 9 {
                    return None;
                }
                let seq = u64::from_le_bytes([
                    data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
                ]);
                Some(Message::Ping(seq))
            }
            0x04 => {
                // Pong
                if data.len() < 9 {
                    return None;
                }
                let seq = u64::from_le_bytes([
                    data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
                ]);
                Some(Message::Pong(seq))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_stats() {
        let stats = SessionStats::new();

        stats.record_session();
        stats.record_session();
        stats.record_datagram();
        stats.record_stream();

        assert_eq!(stats.sessions_created.load(Ordering::Relaxed), 2);
        assert_eq!(stats.datagrams_received.load(Ordering::Relaxed), 1);
        assert_eq!(stats.streams_opened.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_message_text_encode_decode() {
        let msg = Message::Text("Hello, WebTransport!".to_string());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();

        match decoded {
            Message::Text(text) => assert_eq!(text, "Hello, WebTransport!"),
            _ => panic!("Expected Text message"),
        }
    }

    #[test]
    fn test_message_binary_encode_decode() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let msg = Message::Binary(data.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();

        match decoded {
            Message::Binary(decoded_data) => assert_eq!(decoded_data, data),
            _ => panic!("Expected Binary message"),
        }
    }

    #[test]
    fn test_message_ping_pong() {
        let ping = Message::Ping(12345);
        let encoded = ping.encode();
        let decoded = Message::decode(&encoded).unwrap();

        match decoded {
            Message::Ping(seq) => assert_eq!(seq, 12345),
            _ => panic!("Expected Ping message"),
        }

        let pong = Message::Pong(12345);
        let encoded = pong.encode();
        let decoded = Message::decode(&encoded).unwrap();

        match decoded {
            Message::Pong(seq) => assert_eq!(seq, 12345),
            _ => panic!("Expected Pong message"),
        }
    }

    #[test]
    fn test_build_server() {
        let addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let server = build_server(addr);
        assert!(server.is_ok());

        let server = server.unwrap();
        assert_eq!(server.bind_addr(), addr);
        assert!(server.config().enable_datagrams);
    }

    #[tokio::test]
    async fn test_build_client() {
        let client = build_client();
        assert!(client.is_ok());

        let client = client.unwrap();
        assert!(client.config().enable_datagrams);
    }

    #[test]
    fn test_echo_handler_creation() {
        let stats = SessionStats::new();
        let _handler = create_echo_handler(stats);
        // Handler creation should succeed
    }

    #[test]
    fn test_constants() {
        assert_eq!(WEBTRANSPORT_PATH, "/webtransport");
        assert_eq!(DEFAULT_ADDR, "127.0.0.1:4433");
    }

    #[test]
    fn test_message_decode_empty() {
        assert!(Message::decode(&[]).is_none());
    }

    #[test]
    fn test_message_decode_invalid_type() {
        assert!(Message::decode(&[0xFF]).is_none());
    }

    #[test]
    fn test_message_ping_too_short() {
        // Ping needs 9 bytes (1 type + 8 seq)
        assert!(Message::decode(&[0x03, 0x01, 0x02]).is_none());
    }
}
