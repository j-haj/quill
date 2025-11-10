//! Chat service example demonstrating bidirectional streaming
//!
//! This example shows how to implement a simple chat service where:
//! - Clients send messages via a stream
//! - Server broadcasts messages to all connected clients
//! - Uses bidirectional streaming

use bytes::Bytes;
use quill_core::QuillError;
use quill_server::streaming::RpcResponse;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio_stream::{wrappers::BroadcastStream, Stream, StreamExt};

/// Maximum number of messages to buffer
const CHANNEL_CAPACITY: usize = 100;

/// Chat message structure (simplified - in real app would use protobuf)
#[derive(Debug, Clone)]
pub struct ChatMessage {
    pub user: String,
    pub message: String,
    pub timestamp: u64,
}

impl ChatMessage {
    pub fn encode(&self) -> Bytes {
        let json = format!(
            r#"{{"user":"{}","message":"{}","timestamp":{}}}"#,
            self.user, self.message, self.timestamp
        );
        Bytes::from(json)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, QuillError> {
        // Simplified parsing - in real app would use protobuf
        let json = String::from_utf8_lossy(bytes);

        // Very basic JSON parsing (in production use serde_json)
        let user = json
            .split(r#""user":""#)
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap_or("unknown")
            .to_string();

        let message = json
            .split(r#""message":""#)
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap_or("")
            .to_string();

        let timestamp = json
            .split(r#""timestamp":"#)
            .nth(1)
            .and_then(|s| s.split('}').next())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        Ok(ChatMessage {
            user,
            message,
            timestamp,
        })
    }
}

/// Chat room that manages message broadcasting
pub struct ChatRoom {
    tx: broadcast::Sender<ChatMessage>,
}

impl ChatRoom {
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(CHANNEL_CAPACITY);
        Self { tx }
    }

    /// Subscribe to the chat room
    pub fn subscribe(&self) -> broadcast::Receiver<ChatMessage> {
        self.tx.subscribe()
    }

    /// Broadcast a message to all subscribers
    pub fn broadcast(&self, message: ChatMessage) -> Result<(), QuillError> {
        self.tx
            .send(message)
            .map_err(|e| QuillError::Rpc(format!("Failed to broadcast: {}", e)))?;
        Ok(())
    }
}

impl Default for ChatRoom {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle a chat stream (bidirectional streaming)
///
/// This processes incoming messages from the client and streams back
/// all messages in the chat room
pub async fn handle_chat(
    chat_room: Arc<ChatRoom>,
    request_stream: Pin<Box<dyn Stream<Item = Result<Bytes, QuillError>> + Send>>,
) -> Result<RpcResponse, QuillError> {
    // Subscribe to chat room before processing client messages
    let rx = chat_room.subscribe();

    // Spawn a task to process incoming messages from client
    let chat_room_clone = chat_room.clone();
    tokio::spawn(async move {
        let mut stream = request_stream;
        while let Some(result) = stream.next().await {
            match result {
                Ok(bytes) => {
                    if let Ok(msg) = ChatMessage::decode(&bytes) {
                        tracing::info!("Received message from {}: {}", msg.user, msg.message);
                        let _ = chat_room_clone.broadcast(msg);
                    }
                }
                Err(e) => {
                    tracing::error!("Error reading message: {}", e);
                    break;
                }
            }
        }
    });

    // Create response stream from broadcast receiver
    let response_stream = BroadcastStream::new(rx)
        .filter_map(|result| match result {
            Ok(msg) => Some(Ok(msg.encode())),
            Err(e) => {
                tracing::warn!("Broadcast error: {}", e);
                None
            }
        });

    Ok(RpcResponse::streaming(response_stream))
}

/// Generate a welcome message for new users
pub fn create_welcome_message(user: &str) -> ChatMessage {
    ChatMessage {
        user: "System".to_string(),
        message: format!("Welcome to the chat, {}!", user),
        timestamp: current_timestamp(),
    }
}

/// Get current timestamp in milliseconds
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_encode_decode() {
        let msg = ChatMessage {
            user: "Alice".to_string(),
            message: "Hello, world!".to_string(),
            timestamp: 1234567890,
        };

        let encoded = msg.encode();
        let decoded = ChatMessage::decode(&encoded).unwrap();

        assert_eq!(decoded.user, msg.user);
        assert_eq!(decoded.message, msg.message);
        assert_eq!(decoded.timestamp, msg.timestamp);
    }

    #[test]
    fn test_chat_room_broadcast() {
        let room = ChatRoom::new();
        let mut rx = room.subscribe();

        let msg = ChatMessage {
            user: "Bob".to_string(),
            message: "Test message".to_string(),
            timestamp: current_timestamp(),
        };

        room.broadcast(msg.clone()).unwrap();

        let received = rx.try_recv().unwrap();
        assert_eq!(received.user, msg.user);
        assert_eq!(received.message, msg.message);
    }

    #[test]
    fn test_welcome_message() {
        let msg = create_welcome_message("Charlie");
        assert_eq!(msg.user, "System");
        assert!(msg.message.contains("Charlie"));
    }
}
