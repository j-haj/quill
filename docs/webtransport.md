# WebTransport Support

This guide covers WebTransport support in Quill, enabling bidirectional communication over HTTP/3 with support for streams and unreliable datagrams.

## Table of Contents

- [Overview](#overview)
- [Enabling WebTransport](#enabling-webtransport)
- [Server Setup](#server-setup)
- [Client Setup](#client-setup)
- [Browser Integration](#browser-integration)
- [Sessions](#sessions)
- [Streams](#streams)
- [Datagrams](#datagrams)
- [Use Cases](#use-cases)
- [Configuration](#configuration)
- [Error Handling](#error-handling)
- [Best Practices](#best-practices)

## Overview

WebTransport is a protocol for bidirectional communication between a browser and server, built on HTTP/3. It provides:

- **Bidirectional Streams**: Full-duplex communication channels
- **Unidirectional Streams**: One-way communication channels
- **Unreliable Datagrams**: Low-latency, unordered message delivery
- **Browser Native Support**: Direct WebTransport API in modern browsers
- **Multiplexing**: Multiple streams over a single connection

### Why WebTransport?

WebTransport is ideal for:
- **Real-Time Applications**: Gaming, collaborative editing, live streaming
- **Browser Games**: Low-latency bidirectional communication
- **IoT Dashboards**: Streaming sensor data to browsers
- **Video Conferencing**: Media streaming with unreliable datagrams
- **Live Updates**: Push-based real-time notifications

### WebTransport vs WebSockets

| Feature | WebTransport | WebSockets |
|---------|-------------|------------|
| Protocol | HTTP/3 (QUIC) | HTTP/1.1 |
| Streams | Multiple concurrent | Single stream |
| Unreliable delivery | Yes (datagrams) | No |
| Head-of-line blocking | No | Yes |
| Connection migration | Yes | No |

## Enabling WebTransport

Enable the `webtransport` feature in your `Cargo.toml`:

```toml
[dependencies]
quill-transport = { version = "0.1", features = ["webtransport"] }
```

### Dependencies

The WebTransport implementation uses:
- **h3-webtransport**: WebTransport over HTTP/3 (v0.1)
- **h3-datagram**: HTTP/3 datagram support (v0.0.2)
- **quinn**: QUIC implementation (via http3 feature)
- **rustls**: TLS 1.3 encryption

## Server Setup

### Basic WebTransport Server

```rust
use quill_transport::{
    WebTransportServerBuilder, WebTransportServer, Session,
    FnWebTransportHandler, WebTransportError,
};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), WebTransportError> {
    let addr: SocketAddr = "0.0.0.0:4433".parse().unwrap();

    // Build server with configuration
    let server = WebTransportServerBuilder::new(addr)
        .enable_datagrams(true)
        .max_datagram_size(65536)
        .max_sessions(100)
        .max_concurrent_streams(100)
        .session_timeout_ms(60000)
        .build()?;

    // Create a session handler
    let handler = FnWebTransportHandler::new(|session: Session| async move {
        println!(
            "New session: id={}, remote={}",
            session.session_id(),
            session.remote_addr()
        );

        // Handle session...
        Ok(())
    });

    println!("WebTransport server listening on {}", server.bind_addr());

    // Start serving (full implementation pending)
    // server.serve(handler).await?;

    Ok(())
}
```

### Server Builder Options

```rust
let server = WebTransportServerBuilder::new(addr)
    // Enable HTTP/3 datagrams
    .enable_datagrams(true)

    // Maximum datagram payload size
    .max_datagram_size(65536)

    // Maximum concurrent sessions
    .max_sessions(100)

    // Maximum concurrent streams per session
    .max_concurrent_streams(100)

    // Session idle timeout in milliseconds
    .session_timeout_ms(60000)

    // HTTP/3 idle timeout
    .idle_timeout_ms(120000)

    // HTTP/3 keep-alive interval
    .keep_alive_interval_ms(30000)

    .build()?;
```

### Custom Session Handler

Implement the `WebTransportHandler` trait for more complex logic:

```rust
use quill_transport::{WebTransportHandler, Session, WebTransportError};
use std::future::Future;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
struct GameSessionHandler {
    active_games: Arc<Mutex<HashMap<u64, GameState>>>,
}

impl WebTransportHandler for GameSessionHandler {
    type Future = impl Future<Output = Result<(), WebTransportError>> + Send;

    fn handle(&self, session: Session) -> Self::Future {
        let games = self.active_games.clone();
        async move {
            // Create a new game state for this session
            let game_state = GameState::new();
            games.lock().await.insert(session.session_id(), game_state);

            // Handle game logic...

            // Clean up on disconnect
            games.lock().await.remove(&session.session_id());
            Ok(())
        }
    }
}
```

## Client Setup

### Native Rust Client

```rust
use quill_transport::{WebTransportClientBuilder, WebTransportError};
use bytes::Bytes;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), WebTransportError> {
    // Install crypto provider
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Build client
    let client = WebTransportClientBuilder::new()
        .enable_datagrams(true)
        .max_datagram_size(65536)
        .build()?;

    // Connect to server
    let addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    let session = client.connect(addr, "localhost", "/webtransport").await?;

    // Send a datagram
    session.send_datagram(Bytes::from("Hello!"))?;

    // Open a bidirectional stream
    let (mut send, mut recv) = session.open_bi().await?;
    // Use send/recv for streaming data...

    // Open a unidirectional stream
    let mut send_uni = session.open_uni().await?;
    // Use send_uni for one-way data...

    // Accept incoming streams
    if let Some((send, recv)) = session.accept_bi().await? {
        // Handle incoming bidirectional stream
    }

    Ok(())
}
```

### Client Builder Options

```rust
let client = WebTransportClientBuilder::new()
    // Enable HTTP/3 datagrams
    .enable_datagrams(true)

    // Maximum datagram payload size
    .max_datagram_size(65536)

    // Enable 0-RTT for fast resumption (idempotent only)
    .enable_zero_rtt(false)

    // Connection idle timeout
    .idle_timeout_ms(60000)

    // Keep-alive interval
    .keep_alive_interval_ms(30000)

    .build()?;
```

## Browser Integration

### JavaScript WebTransport API

Modern browsers support WebTransport natively:

```javascript
// Connect to WebTransport server
const transport = new WebTransport('https://localhost:4433/webtransport');
await transport.ready;

console.log('Connected!');

// Handle connection close
transport.closed.then(() => {
    console.log('Connection closed gracefully');
}).catch(error => {
    console.error('Connection closed with error:', error);
});
```

### Sending Datagrams

```javascript
// Send a datagram
const writer = transport.datagrams.writable.getWriter();
await writer.write(new TextEncoder().encode('Hello from browser!'));
writer.releaseLock();

// Read datagrams
const reader = transport.datagrams.readable.getReader();
while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    console.log('Received:', new TextDecoder().decode(value));
}
```

### Using Bidirectional Streams

```javascript
// Create a bidirectional stream
const stream = await transport.createBidirectionalStream();

// Write to stream
const writer = stream.writable.getWriter();
await writer.write(new TextEncoder().encode('Stream message'));
writer.releaseLock();

// Read from stream
const reader = stream.readable.getReader();
const { value } = await reader.read();
console.log('Response:', new TextDecoder().decode(value));
reader.releaseLock();
```

### Using Unidirectional Streams

```javascript
// Create outgoing unidirectional stream
const outgoingStream = await transport.createUnidirectionalStream();
const writer = outgoingStream.getWriter();
await writer.write(new TextEncoder().encode('One-way message'));
await writer.close();

// Accept incoming unidirectional streams
const reader = transport.incomingUnidirectionalStreams.getReader();
while (true) {
    const { value: stream, done } = await reader.read();
    if (done) break;

    // Read from incoming stream
    const streamReader = stream.getReader();
    const { value } = await streamReader.read();
    console.log('Incoming:', new TextDecoder().decode(value));
}
```

## Sessions

### Session Object

The `Session` represents an active WebTransport connection:

```rust
use quill_transport::Session;

fn handle_session(session: Session) {
    // Get session ID (unique per connection)
    let id = session.session_id();

    // Get remote address
    let addr = session.remote_addr();

    // Get session configuration
    let config = session.config();
    println!("Max datagram size: {}", config.max_datagram_size);
}
```

### Client Session

The `ClientSession` provides client-side session operations:

```rust
use quill_transport::ClientSession;
use bytes::Bytes;

async fn use_session(session: ClientSession) -> Result<(), WebTransportError> {
    // Send datagram
    session.send_datagram(Bytes::from("data"))?;

    // Receive datagram
    if let Some(data) = session.recv_datagram().await? {
        println!("Received: {:?}", data);
    }

    // Open bidirectional stream
    let (send, recv) = session.open_bi().await?;

    // Open unidirectional stream
    let send = session.open_uni().await?;

    // Accept incoming bidirectional stream
    if let Some((send, recv)) = session.accept_bi().await? {
        // Handle incoming stream
    }

    // Accept incoming unidirectional stream
    if let Some(recv) = session.accept_uni().await? {
        // Handle incoming stream
    }

    Ok(())
}
```

## Streams

### Bidirectional Streams (BiStream)

Full-duplex communication channels:

```rust
use quill_transport::BiStream;
use bytes::Bytes;

async fn handle_bi_stream(stream: BiStream) -> Result<(), WebTransportError> {
    let (mut send, mut recv) = stream;

    // Read data
    let mut buf = vec![0u8; 1024];
    let n = recv.read(&mut buf).await?;

    // Write response
    send.write_all(&buf[..n]).await?;
    send.finish().await?;

    Ok(())
}
```

### Unidirectional Streams (UniStream)

One-way communication channels:

```rust
use quill_transport::UniStream;

// Send-only stream (client opens, server receives)
async fn send_data(mut stream: UniStream) -> Result<(), WebTransportError> {
    stream.write_all(b"Hello, server!").await?;
    stream.finish().await?;
    Ok(())
}

// Receive-only stream (server accepts)
async fn recv_data(mut stream: RecvStream) -> Result<Vec<u8>, WebTransportError> {
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    Ok(buf)
}
```

## Datagrams

### Sending Datagrams

```rust
use bytes::Bytes;

// Simple datagram
session.send_datagram(Bytes::from("sensor:temp=72.5"))?;

// Binary datagram
let data = [0x01, 0x02, 0x03, 0x04];
session.send_datagram(Bytes::copy_from_slice(&data))?;
```

### Receiving Datagrams

```rust
// Receive single datagram
if let Some(data) = session.recv_datagram().await? {
    println!("Received {} bytes", data.len());
}

// Receive datagrams in a loop
loop {
    match session.recv_datagram().await? {
        Some(data) => process_datagram(data),
        None => break, // Connection closed
    }
}
```

### Datagram Best Practices

- **Size**: Keep datagrams < 1200 bytes to avoid fragmentation
- **Loss**: Design for datagram loss (no delivery guarantee)
- **Ordering**: Handle out-of-order delivery
- **Rate**: Implement application-level flow control
- **FEC**: Consider Forward Error Correction for important data

## Use Cases

### Real-Time Game Example

```rust
use quill_transport::{
    WebTransportServerBuilder, FnWebTransportHandler, Session,
};
use bytes::Bytes;

// Game update packet
#[derive(Debug)]
struct GameUpdate {
    player_id: u64,
    x: f32,
    y: f32,
    action: u8,
}

impl GameUpdate {
    fn encode(&self) -> Bytes {
        let mut buf = Vec::with_capacity(25);
        buf.extend_from_slice(&self.player_id.to_le_bytes());
        buf.extend_from_slice(&self.x.to_le_bytes());
        buf.extend_from_slice(&self.y.to_le_bytes());
        buf.push(self.action);
        Bytes::from(buf)
    }

    fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 21 { return None; }
        Some(GameUpdate {
            player_id: u64::from_le_bytes(data[0..8].try_into().ok()?),
            x: f32::from_le_bytes(data[8..12].try_into().ok()?),
            y: f32::from_le_bytes(data[12..16].try_into().ok()?),
            action: data[20],
        })
    }
}

// Server handler
let handler = FnWebTransportHandler::new(|session: Session| async move {
    println!("Player connected: {}", session.session_id());

    // Use datagrams for position updates (tolerate loss)
    // Use streams for chat messages (reliable)

    Ok(())
});
```

### IoT Sensor Dashboard

```rust
// Sensor reading
struct SensorReading {
    sensor_id: u32,
    timestamp: u64,
    value: f64,
    unit: &'static str,
}

// Browser connects and receives sensor updates via datagrams
let handler = FnWebTransportHandler::new(|session: Session| async move {
    let session_id = session.session_id();

    // Stream sensor data to browser
    loop {
        let reading = get_sensor_reading().await;

        // Send via datagram (low latency, tolerate loss)
        if let Err(e) = session.send_datagram(reading.encode()) {
            tracing::warn!("Failed to send reading: {}", e);
            break;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Ok(())
});
```

### Chat Application

```rust
// Chat message
enum ChatMessage {
    Text(String),
    Typing { user_id: u64 },
    Read { message_id: u64 },
}

let handler = FnWebTransportHandler::new(|session: Session| async move {
    // Use bidirectional stream for reliable chat messages
    let (mut send, mut recv) = session.open_bi().await?;

    // Use datagrams for ephemeral updates (typing indicators)
    loop {
        tokio::select! {
            // Receive chat message (reliable stream)
            msg = recv_message(&mut recv) => {
                broadcast_message(msg).await;
            }

            // Send typing indicator (unreliable datagram)
            _ = typing_indicator_timer.tick() => {
                let _ = session.send_datagram(typing_packet());
            }
        }
    }

    Ok(())
});
```

## Configuration

### WebTransportConfig

```rust
use quill_transport::WebTransportConfig;

let config = WebTransportConfig {
    // HTTP/3 base configuration
    http3: HyperConfig {
        enable_zero_rtt: false,
        enable_datagrams: true,
        enable_connection_migration: true,
        max_concurrent_streams: 100,
        max_datagram_size: 65536,
        keep_alive_interval_ms: 30000,
        idle_timeout_ms: 60000,
    },

    // WebTransport-specific settings
    max_sessions: 1000,           // Maximum concurrent sessions
    session_timeout_ms: 300000,   // 5-minute session timeout
    enable_datagrams: true,       // Enable datagram support
    max_datagram_size: 65536,     // Maximum datagram size
};
```

### Configuration Best Practices

| Setting | Development | Production |
|---------|-------------|------------|
| `max_sessions` | 100 | 10,000+ |
| `session_timeout_ms` | 60,000 | 300,000 |
| `max_datagram_size` | 65,536 | 1,200 |
| `max_concurrent_streams` | 100 | 1,000 |
| `idle_timeout_ms` | 30,000 | 120,000 |

## Error Handling

### WebTransportError

```rust
use quill_transport::WebTransportError;

fn handle_error(error: WebTransportError) {
    match error {
        WebTransportError::ConnectionError(msg) => {
            eprintln!("Connection failed: {}", msg);
        }
        WebTransportError::SessionError(msg) => {
            eprintln!("Session error: {}", msg);
        }
        WebTransportError::StreamError(msg) => {
            eprintln!("Stream error: {}", msg);
        }
        WebTransportError::DatagramError(msg) => {
            eprintln!("Datagram error: {}", msg);
        }
        WebTransportError::ConfigError(msg) => {
            eprintln!("Configuration error: {}", msg);
        }
        WebTransportError::TlsError(msg) => {
            eprintln!("TLS error: {}", msg);
        }
    }
}
```

### Graceful Shutdown

```rust
// Server shutdown
async fn shutdown_server(server: WebTransportServer) {
    // Signal shutdown to all sessions
    server.shutdown().await;
}

// Client session close
async fn close_session(session: ClientSession) {
    // Close all streams gracefully
    session.close(0, b"goodbye").await;
}
```

## Best Practices

### 1. Choose the Right Transport

- **Streams**: Reliable, ordered data (chat messages, file transfers)
- **Datagrams**: Real-time, loss-tolerant data (game state, sensor readings)

### 2. Handle Connection Lifecycle

```rust
let handler = FnWebTransportHandler::new(|session: Session| async move {
    // 1. Initialize session state
    let state = SessionState::new(session.session_id());

    // 2. Main session loop
    loop {
        tokio::select! {
            result = session.recv_datagram() => {
                match result {
                    Ok(Some(data)) => state.process_datagram(data),
                    Ok(None) => break, // Connection closed
                    Err(e) => {
                        tracing::error!("Error: {}", e);
                        break;
                    }
                }
            }
            // Handle other events...
        }
    }

    // 3. Clean up session state
    state.cleanup();

    Ok(())
});
```

### 3. Implement Backpressure

```rust
// Track outstanding datagrams
let outstanding = Arc::new(AtomicU32::new(0));

// Send with backpressure
if outstanding.load(Ordering::Relaxed) < MAX_OUTSTANDING {
    session.send_datagram(data)?;
    outstanding.fetch_add(1, Ordering::Relaxed);
} else {
    tracing::warn!("Dropping datagram due to backpressure");
}
```

### 4. Use Appropriate Timeouts

```rust
use tokio::time::{timeout, Duration};

// Timeout for stream operations
let result = timeout(
    Duration::from_secs(5),
    session.open_bi()
).await??;

// Timeout for datagram receive
match timeout(Duration::from_millis(100), session.recv_datagram()).await {
    Ok(Ok(Some(data))) => process(data),
    Ok(Ok(None)) => return Ok(()), // Closed
    Ok(Err(e)) => return Err(e),
    Err(_) => {} // Timeout, continue
}
```

### 5. Monitor Session Health

```rust
// Send periodic pings
let ping_interval = tokio::time::interval(Duration::from_secs(10));

loop {
    tokio::select! {
        _ = ping_interval.tick() => {
            let ping = Message::Ping(sequence.fetch_add(1, Ordering::Relaxed));
            if session.send_datagram(ping.encode()).is_err() {
                break; // Connection lost
            }
        }
        // Handle other events...
    }
}
```

## Browser Compatibility

| Browser | WebTransport Support |
|---------|---------------------|
| Chrome | 97+ (stable) |
| Edge | 97+ (stable) |
| Firefox | 114+ (enabled by default) |
| Safari | Not yet supported |
| Opera | 83+ (stable) |

### Feature Detection

```javascript
if (typeof WebTransport === 'undefined') {
    console.log('WebTransport not supported, falling back to WebSocket');
    // Use WebSocket fallback
} else {
    // Use WebTransport
    const transport = new WebTransport(url);
}
```

## See Also

- [HTTP/3 Configuration](http3.md) - Hyper profile documentation
- [Performance Guide](performance.md) - Performance optimization
- [Examples](../examples/webtransport/) - WebTransport example code

## References

- [WebTransport Specification](https://www.w3.org/TR/webtransport/)
- [MDN WebTransport](https://developer.mozilla.org/en-US/docs/Web/API/WebTransport)
- [h3-webtransport Crate](https://docs.rs/h3-webtransport/latest/h3_webtransport/)
