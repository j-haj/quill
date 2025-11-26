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

### 4. HTTP/3 Echo Service (`examples/h3-echo`)

**Pattern**: Unary RPC over HTTP/3 (QUIC)

An echo service demonstrating Quill RPC over HTTP/3 using the Hyper profile.

**Features**:
- HTTP/3 transport over QUIC
- 0-RTT configuration for idempotent requests
- TLS 1.3 with self-signed certificates
- QuillH3Client and QuillH3Server setup

**Use Case**:
- Mobile applications (connection migration)
- Browser clients (native HTTP/3 support)
- Lossy networks (better packet loss handling)
- Edge-to-client communication

**Code Highlights**:

```rust
use quill_client::QuillH3Client;
use quill_server::QuillH3Server;

// HTTP/3 Server
let server = QuillH3Server::builder(addr)
    .enable_zero_rtt(true)
    .enable_datagrams(false)
    .max_concurrent_streams(100)
    .register("echo.v1.EchoService/Echo", handle_echo)
    .build();

server.serve().await?;

// HTTP/3 Client
let client = QuillH3Client::builder(addr)
    .enable_zero_rtt(true)
    .enable_compression(true)
    .build()?;

let response = client.call("echo.v1.EchoService", "Echo", request).await?;
```

**Requirements**:
- Enable the `http3` feature in `quill-client` and `quill-server`
- Uses rustls with ring crypto provider for TLS

---

### 5. HTTP/3 Streaming Service (`examples/h3-streaming`)

**Pattern**: Server Streaming over HTTP/3 (QUIC)

A log-tailing service demonstrating server-side streaming over HTTP/3 using the Quill frame protocol.

**Features**:
- Server-side streaming over HTTP/3
- Quill frame protocol encoding/decoding
- Multiple DATA frames with END_STREAM signaling
- Large stream support (100+ messages)

**Use Case**:
- Real-time log tailing over lossy networks
- Live event feeds on mobile
- Streaming metrics/telemetry
- Large data transfers with frame-level control

**Code Highlights**:

```rust
use quill_core::{Frame, FrameParser};

/// Generate log entries as Quill frames
pub fn generate_log_stream(max_entries: usize) -> Bytes {
    let mut buf = Vec::new();

    for i in 0..max_entries {
        let entry = LogEntry {
            timestamp: format!("2025-11-25T12:00:{:02}Z", i),
            level: "INFO".to_string(),
            message: format!("HTTP/3 log message #{}", i),
        };

        // Encode protobuf and wrap in Quill DATA frame
        let mut entry_buf = Vec::new();
        entry.encode(&mut entry_buf)?;
        let frame = Frame::data(Bytes::from(entry_buf));
        buf.extend_from_slice(&frame.encode());
    }

    // Add END_STREAM frame to signal completion
    let end_frame = Frame::end_stream();
    buf.extend_from_slice(&end_frame.encode());

    Bytes::from(buf)
}

/// Parse streaming response
pub fn parse_log_stream(data: Bytes) -> Result<Vec<LogEntry>, QuillError> {
    let mut parser = FrameParser::new();
    parser.feed(&data);

    let mut entries = Vec::new();
    loop {
        match parser.parse_frame()? {
            Some(frame) if frame.flags.is_end_stream() => break,
            Some(frame) if frame.flags.is_data() => {
                entries.push(LogEntry::decode(frame.payload)?);
            }
            _ => break,
        }
    }
    Ok(entries)
}
```

**Requirements**:
- Enable the `http3` feature in `quill-transport`, `quill-client`, and `quill-server`
- Uses rustls with ring crypto provider for TLS

---

### 6. Chat Service (`examples/chat`)

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

### 7. gRPC Bridge (`examples/grpc-bridge`)

**Pattern**: Protocol Bridge (gRPC → Quill)

Demonstrates interoperability between gRPC clients and Quill services using the gRPC bridge.

**Features**:
- gRPC to Quill unary call bridging
- Status code translation (gRPC ↔ HTTP)
- Metadata/header forwarding
- Problem Details error mapping

**Use Case**:
- Gradual migration from gRPC to Quill
- Protocol gateway for gRPC-only clients
- Hybrid architectures with both protocols

**Architecture**:

```
┌─────────────┐         ┌─────────────┐         ┌──────────────┐
│ gRPC Client │────────▶│ gRPC Bridge │────────▶│ Quill Server │
└─────────────┘         └─────────────┘         └──────────────┘
```

**Code Highlights**:

```rust
use quill_grpc_bridge::{GrpcBridge, GrpcBridgeConfig};

// Create bridge configuration
let config = GrpcBridgeConfig {
    quill_base_url: "http://localhost:8080".to_string(),
    enable_logging: true,
    forward_metadata: true,
};

let bridge = GrpcBridge::new(config)?;

// Implement gRPC service that bridges to Quill
#[tonic::async_trait]
impl EchoService for EchoServiceBridge {
    async fn echo(
        &self,
        request: tonic::Request<EchoRequest>,
    ) -> Result<tonic::Response<EchoResponse>, tonic::Status> {
        // Bridge the call to Quill
        self.bridge
            .call_unary("echo.v1.EchoService", "Echo", request)
            .await
    }
}
```

**Requirements**:
- `quill-grpc-bridge` crate
- `tonic` for gRPC server implementation
- Quill server running on backend

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
cargo test -p h3-echo-example
cargo test -p h3-streaming-example
cargo test -p grpc-bridge-example
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
