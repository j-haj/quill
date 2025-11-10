# Quill Examples

This directory contains example implementations demonstrating different RPC patterns in Quill.

## Examples

### 1. Echo Service (`examples/echo`)

**Pattern**: Unary RPC (request → response)

A simple echo service that demonstrates the basic unary RPC pattern.

**Features**:
- Simple request/response
- Basic server setup
- Client usage example

**Use Case**: Simple API calls, health checks, basic CRUD operations

---

### 2. Log Tailing Service (`examples/streaming`)

**Pattern**: Server Streaming (request → stream of responses)

A log-tailing service that demonstrates server-side streaming where the server sends multiple messages to the client.

**Features**:
- Server-side streaming
- Continuous data delivery
- Frame-based streaming protocol

**Use Case**:
- Log tailing
- Real-time notifications
- Live data feeds
- Event streams

**Code Highlights**:

```rust
use quill_server::streaming::RpcResponse;
use tokio_stream::{iter, StreamExt};

pub async fn handle_tail(request: Bytes) -> Result<RpcResponse, QuillError> {
    // Generate stream of log entries
    let entries = generate_log_entries(max_entries);

    // Convert to byte stream
    let byte_stream = entries.map(|entry| Ok(entry.encode()));

    // Return as streaming response
    Ok(RpcResponse::streaming(byte_stream))
}
```

---

### 3. File Upload Service (`examples/upload`)

**Pattern**: Client Streaming (stream of requests → response)

A file upload service that demonstrates client-side streaming where the client sends chunks and the server receives them.

**Features**:
- Client-side streaming
- Chunked file uploads
- SHA-256 checksum verification
- Size validation
- Progress tracking

**Use Case**:
- File uploads
- Large data transfers
- Batch data imports
- Streaming aggregation

**Key Concepts**:

```rust
// Client splits file into chunks
let chunks = create_chunks(&file_data, CHUNK_SIZE);

// Server receives and validates chunks
pub async fn handle_upload(
    mut chunk_stream: Pin<Box<dyn Stream<Item = Result<Bytes, QuillError>> + Send>>,
) -> Result<Bytes, QuillError> {
    let mut hasher = Sha256::new();

    while let Some(chunk_bytes) = chunk_stream.next().await {
        let chunk = FileChunk::decode(&chunk_bytes?)?;
        hasher.update(&chunk.data);
        // ... process chunk
    }

    // Return result with checksum
    Ok(UploadResult { checksum, ... }.encode())
}
```

**Configuration**:
- `CHUNK_SIZE`: 1MB per chunk
- `MAX_FILE_SIZE`: 100MB maximum

---

### 4. Chat Service (`examples/chat`)

**Pattern**: Bidirectional Streaming (stream of requests ↔ stream of responses)

A simple chat room that demonstrates bidirectional streaming where both client and server can send messages concurrently.

**Features**:
- Bidirectional streaming
- Real-time message broadcasting
- Broadcast channels for pub/sub
- Concurrent send/receive

**Use Case**:
- Chat applications
- Real-time collaboration
- Live updates with user input
- Interactive streaming

**Architecture**:

```rust
pub struct ChatRoom {
    tx: broadcast::Sender<ChatMessage>,
}

pub async fn handle_chat(
    chat_room: Arc<ChatRoom>,
    request_stream: Pin<Box<dyn Stream<Item = Result<Bytes, QuillError>> + Send>>,
) -> Result<RpcResponse, QuillError> {
    // Subscribe to room for receiving messages
    let rx = chat_room.subscribe();

    // Spawn task to handle incoming client messages
    tokio::spawn(async move {
        while let Some(msg) = request_stream.next().await {
            chat_room.broadcast(msg).await;
        }
    });

    // Return stream of chat messages
    let response_stream = BroadcastStream::new(rx);
    Ok(RpcResponse::streaming(response_stream))
}
```

---

## Running the Examples

### Build All Examples

```bash
cargo build --examples
```

### Test All Examples

```bash
cargo test -p echo-example
cargo test -p streaming-example
cargo test -p upload-example
cargo test -p chat-example
```

### Run Individual Examples

Each example includes tests that demonstrate the functionality. Check the test section in each `src/lib.rs` file.

## Streaming Patterns Comparison

| Pattern | Client Sends | Server Sends | Use Case |
|---------|-------------|--------------|----------|
| **Unary** | 1 message | 1 message | Simple API calls |
| **Server Streaming** | 1 message | N messages | Live feeds, notifications |
| **Client Streaming** | N messages | 1 message | File upload, batch import |
| **Bidirectional** | N messages | N messages | Chat, collaboration |

## Implementation Notes

### Frame Protocol

All streaming examples use Quill's frame protocol:
```
[length varint][flags byte][payload bytes]
```

**Flags**:
- `DATA` (0x01): Frame contains data
- `END_STREAM` (0x02): Stream has ended
- `CANCEL` (0x04): Stream was cancelled
- `CREDIT` (0x08): Flow control credit grant

### Flow Control

Streaming uses credit-based flow control to prevent buffer overflow:
- Default initial credits: 16
- Credit refill: 8 messages
- Tracked automatically by `ResponseFrameStream` and `RequestFrameStream`

### Compression

All examples can optionally use zstd compression:

```rust
let client = QuillClient::builder()
    .base_url("http://localhost:8080")
    .enable_compression(true)
    .build()?;
```

### Tracing

All RPC calls are automatically instrumented with OpenTelemetry:

```rust
// Initialize tracing
tracing_subscriber::fmt::init();

// Calls are automatically traced
client.call_server_streaming("log.v1.LogService", "Tail", request).await?;
```

## Production Considerations

### Error Handling

Always handle stream errors:

```rust
while let Some(result) = stream.next().await {
    match result {
        Ok(data) => process(data),
        Err(e) => {
            tracing::error!("Stream error: {}", e);
            break;
        }
    }
}
```

### Backpressure

Use flow control to prevent overwhelming slow clients:

```rust
// Server automatically tracks credits
// Client grants credits as it processes messages
```

### Resource Cleanup

Ensure streams are properly cleaned up:

```rust
// Streams are automatically cleaned up when dropped
// For early termination, drop the stream explicitly
drop(stream);
```

### Timeouts

Add timeouts for long-running streams:

```rust
use tokio::time::timeout;

let result = timeout(
    Duration::from_secs(30),
    client.call_server_streaming(service, method, request)
).await??;
```

## Next Steps

1. **Integration Tests**: See the integration test suite for end-to-end examples
2. **Code Generation**: Future protoc plugin will generate typed clients/servers
3. **Middleware**: Add compression, tracing, and custom middleware
4. **Production Deploy**: Configure OTLP tracing, metrics, and monitoring

## See Also

- [Flow Control Documentation](../docs/flow-control.md)
- [Compression Guide](../docs/compression.md)
- [Tracing Guide](../docs/tracing.md)
- [CLAUDE.md](../CLAUDE.md) - Implementation status and architecture
