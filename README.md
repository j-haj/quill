# Quill

![CI](https://github.com/your-org/quill/workflows/CI/badge.svg)
![Documentation](https://github.com/your-org/quill/workflows/Documentation/badge.svg)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A modern, protobuf-first RPC framework with adaptive HTTP/1–3 transport (Prism), real HTTP errors, streaming that just works, and a single CLI for gen, call, and bench.

**[Documentation](https://your-org.github.io/quill/)** | **[API Reference](https://your-org.github.io/quill/quill_core/)** | **[Examples](examples/)**

## Overview

Quill is a Rust implementation of a next-generation RPC framework featuring:

- **Prism Transport Profiles**: Adaptive HTTP/1.1, HTTP/2 (Turbo), and HTTP/3 (Hyper) support
- **Protobuf-First**: `.proto` as the single source of truth
- **Real HTTP Errors**: Problem Details (RFC 7807) instead of 200-with-error-envelope
- **Stream Framing**: Custom framing with flow control for efficient streaming
- **Zero Trailers**: No trailers required for correctness

## Architecture

### Crates

- **quill-core**: Core types (framing, Problem Details, flow control)
- **quill-proto**: Protobuf integration and Quill annotations
- **quill-transport**: Transport layer implementations (Classic/Turbo/Hyper)
- **quill-server**: Server SDK with routing, middleware, and streaming
- **quill-client**: Client SDK with streaming, compression, and tracing
- **quill-codegen**: Code generation (protoc plugin)
- **quill-cli**: CLI tool for gen/call/bench
- **quill-tensor**: Tensor types and streaming for ML inference

### Prism Transport Profiles

1. **Classic** (HTTP/1.1 + basic HTTP/2): Legacy/enterprise proxies
2. **Turbo** (HTTP/2 end-to-end): Cluster-internal traffic
3. **Hyper** (HTTP/3 over QUIC): Browser/mobile, lossy networks - *coming soon*

Profile negotiation via `Prefer: prism=hyper,turbo,classic` header.

## Quick Start

See the [Examples directory](examples/) for complete working examples of all streaming patterns.

### Installation

Add Quill to your `Cargo.toml`:

```toml
[dependencies]
quill-server = "0.1"
quill-client = "0.1"
quill-core = "0.1"

[build-dependencies]
quill-codegen = "0.1"
```

### CLI Tool

Install the Quill CLI for code generation and RPC calls:

```bash
cargo install --path crates/quill-cli

# Generate code from .proto files
quill gen proto/service.proto -I proto

# Make RPC calls (curl-for-proto)
quill call http://localhost:8080/greeter.v1.Greeter/SayHello \
  --input '{"name":"World"}' \
  --pretty
```

### Server

```rust
use quill_server::QuillServer;
use bytes::Bytes;
use quill_core::QuillError;

async fn handle_echo(request: Bytes) -> Result<Bytes, QuillError> {
    // Decode request, process, encode response
    Ok(request) // Echo back
}

#[tokio::main]
async fn main() {
    let server = QuillServer::builder()
        .register("echo.v1.EchoService/Echo", handle_echo)
        .build();

    server.serve("127.0.0.1:8080".parse().unwrap()).await.unwrap();
}
```

### Client

```rust
use quill_client::QuillClient;
use bytes::Bytes;

#[tokio::main]
async fn main() {
    let client = QuillClient::builder()
        .base_url("http://127.0.0.1:8080")
        .build()
        .unwrap();

    let response = client
        .call("echo.v1.EchoService", "Echo", Bytes::from("Hello"))
        .await
        .unwrap();

    println!("Response: {:?}", response);
}
```

## Development

### Build

```bash
cargo build --workspace
```

### Test

```bash
cargo test --workspace
```

### Run Echo Example

```bash
cargo test --package echo-example
```

## Features

- **HTTP/2 Support**: Full HTTP/2 with multiplexing, connection pooling, and flow control
- **Streaming**: Unary, server streaming, client streaming, and bidirectional streaming
- **Code Generation**: Automatic client and server stub generation from `.proto` files
- **Production Middleware**:
  - Authentication (Bearer, API keys, Basic, custom)
  - Rate limiting (token bucket algorithm)
  - Request logging (with header sanitization)
  - Metrics collection (requests, success/failure rates, bytes)
  - Compression (zstd)
  - OpenTelemetry tracing
- **CLI Tooling**: `quill` command for gen, call, bench, compat, and explain
- **Type Safety**: Full Rust type safety with prost integration
- **Error Handling**: Problem Details (RFC 7807) for structured errors
- **Frame Protocol**: Custom framing with credit-based flow control

## Project Status

### Phase 1: Foundation
- [x] Core types (framing, Problem Details, Prism profiles)
- [x] HTTP/1.1 transport layer
- [x] Server routing and handlers
- [x] Client implementation

### Phase 2: Transport Layer
- [x] HTTP/1.1 Classic profile
- [x] HTTP/2 preparation
- [x] Router infrastructure

### Phase 3: Streaming & Middleware
- [x] Server streaming
- [x] Client streaming
- [x] Bidirectional streaming
- [x] Credit-based flow control
- [x] zstd compression
- [x] OpenTelemetry tracing
- [x] Examples for all patterns
- [x] Integration tests (158 tests passing)

### Phase 4: Code Generation
- [x] Protoc plugin infrastructure
- [x] Client stub generation
- [x] Server trait generation
- [x] Greeter example

### Phase 5: CLI Tooling
- [x] `quill gen` - Code generation
- [x] `quill call` - RPC client
- [x] `quill bench` - Benchmarking (structured)
- [x] `quill compat` - Compatibility checking (structured)
- [x] `quill explain` - Payload decoding (structured)

### Phase 6: Production Middleware
- [x] Authentication middleware (Bearer, API keys, Basic auth)
- [x] Rate limiting (token bucket algorithm)
- [x] Request logging (with sanitization)
- [x] Metrics collection

### Phase 7: Performance & Benchmarking
- [x] Full `quill bench` implementation
- [x] Criterion-based microbenchmarks
- [x] Performance documentation
- [x] Performance budget verification

### Phase 8: HTTP/2 Full Support
- [x] HTTP/2 server with multiplexing
- [x] HTTP/2 client with connection pooling
- [x] Turbo profile (HTTP/2 end-to-end)
- [x] Flow control and keep-alive
- [x] HTTP/2 documentation

### Phase 9: Retry Policies and Circuit Breakers
- [x] Retry policy with exponential backoff and jitter
- [x] Circuit breaker state machine
- [x] Client builder integration
- [x] Comprehensive test suite (14 tests)
- [x] Resilience documentation

### Phase 10: Production Deployment & Operations
- [x] Comprehensive deployment guide
- [x] Docker and Kubernetes examples
- [x] Monitoring setup (Prometheus/Grafana)
- [x] Security hardening best practices
- [x] Complete deployment examples

### Phase 11: Enhanced Observability
- [x] Comprehensive metrics collection
- [x] Prometheus-compatible metrics endpoint
- [x] Detailed health checks with dependencies
- [x] Production Grafana dashboard
- [x] Prometheus alerting rules (15+ alerts)
- [x] Complete observability documentation

### Phase 12: gRPC Bridge
- [x] Status code mapping (gRPC ↔ HTTP)
- [x] Problem Details conversion
- [x] Metadata translation (binary and ASCII headers)
- [x] Bridge configuration and unary call support
- [x] Server streaming bridging
- [x] Client streaming bridging
- [x] Bidirectional streaming bridging
- [x] Comprehensive test suite (17 tests)
- [x] Complete documentation with streaming examples

### Phase 13: HTTP/3 Hyper Profile (Full Implementation)
- [x] QUIC/HTTP/3 dependencies (quinn, h3, h3-quinn, rustls)
- [x] Hyper profile transport layer implementation
- [x] HTTP/3 configuration (0-RTT, datagrams, connection migration)
- [x] Feature flag for optional HTTP/3 support
- [x] HyperTransport with builder pattern
- [x] HTTP/3 server with quinn Endpoint and h3 connection handling
- [x] HTTP/3 client with quinn Connection and request/response
- [x] TLS configuration with ring crypto provider
- [x] RequestResolver API integration for h3 0.0.8
- [x] QuillH3Client for RPC calls over HTTP/3 with Quill framing
- [x] QuillH3Server for serving RPCs over HTTP/3
- [x] Streaming support (server, client, bidirectional) over HTTP/3
- [x] Test suite (17 client tests, 24 server tests, 5 transport tests)
- [x] Comprehensive HTTP/3 documentation with Quill integration examples

### Phase 14: REST Gateway with OpenAPI
- [x] Gateway architecture and URL template mapping
- [x] HTTP method routing (GET/POST/PUT/PATCH/DELETE)
- [x] RouteMapping with path parameter extraction
- [x] OpenAPI 3.0 specification generation
- [x] Problem Details error mapping (RFC 7807)
- [x] Axum router integration
- [x] Authentication middleware (Bearer, API key, Basic, Custom)
- [x] CORS middleware with origin control
- [x] Rate limiting middleware (token bucket)
- [x] Test suite (30 tests)
- [x] Comprehensive REST gateway documentation

### Phase 15: Tensor Support for ML Inference
- [x] Proto definitions (tensor.proto, inference.proto, agent.proto)
- [x] Zero-copy frame protocol with 9-byte header (TensorFrame, FrameType enum)
- [x] quill-tensor crate with DType, Tensor, TensorMeta types
- [x] Tensor streaming with TensorStream, TensorSender, TensorReceiver
- [x] Token streaming for LLM inference (Token, TokenBatch, TokenStream)
- [x] Agent-to-agent communication protocol (AgentMessage, AgentResponse)
- [x] Byte-based flow control (TensorCreditTracker with high/low water marks)
- [x] Half-precision float support (f16, bf16 via half crate)
- [x] Tensor chunking and reassembly for large tensors
- [x] Test suite (28 quill-tensor tests, 6 new flow control tests)

### Phase 16: HTTP/3 Datagrams
- [x] Datagram type with payload and optional flow ID
- [x] QUIC varint encoding/decoding for flow IDs
- [x] DatagramSender and DatagramReceiver for async datagram I/O
- [x] H3Connection for persistent connections with datagram support
- [x] DatagramHandler trait for server-side datagram processing
- [x] H3Server.serve_with_datagrams() for serving with datagram support
- [x] Comprehensive datagram documentation

### Phase 17: WebTransport Support
- [x] WebTransport module with `webtransport` feature flag
- [x] WebTransportConfig with HTTP/3 base and session settings
- [x] Session and ClientSession types for session management
- [x] BiStream and UniStream types for stream handling
- [x] WebTransportHandler trait with FnWebTransportHandler helper
- [x] WebTransportServerBuilder and WebTransportClientBuilder
- [x] Datagram send/receive on sessions
- [x] Browser JavaScript API documentation
- [x] WebTransport example with Message protocol
- [x] Comprehensive WebTransport documentation (docs/webtransport.md)

### Next Steps

- [ ] Python bindings via PyO3 + rust-numpy (Phase 2 tensor support)
- [x] LLM inference example with token streaming
- [x] gRPC bridge production examples and integration tests
- [x] HTTP/3 examples (h3-echo, h3-streaming)
- [x] WebTransport support for browser clients
- [x] HTTP/3 datagrams for unreliable messaging

## Documentation

- **[Architecture Guide](https://your-org.github.io/quill/guide/architecture.md)** - System design and implementation
- **[API Reference](https://your-org.github.io/quill/)** - Complete API documentation
- **[Flow Control](https://your-org.github.io/quill/guide/flow-control.md)** - Credit-based flow control
- **[Compression](https://your-org.github.io/quill/guide/compression.md)** - zstd compression guide
- **[Tracing](https://your-org.github.io/quill/guide/tracing.md)** - OpenTelemetry integration
- **[Middleware](docs/middleware.md)** - Authentication, rate limiting, logging, metrics
- **[Performance](docs/performance.md)** - Benchmarks, optimization guide, performance budgets
- **[HTTP/2](docs/http2.md)** - HTTP/2 configuration, Turbo profile, connection pooling
- **[HTTP/3](docs/http3.md)** - HTTP/3 over QUIC, Hyper profile, 0-RTT, datagrams, connection migration
- **[WebTransport](docs/webtransport.md)** - WebTransport for browser clients, streams, and datagrams
- **[Resilience](docs/resilience.md)** - Retry policies and circuit breakers
- **[Deployment](docs/deployment.md)** - Production deployment, Docker, Kubernetes, monitoring
- **[Deployment Examples](deployment/examples/README.md)** - Ready-to-use Docker and K8s configs
- **[Observability](docs/observability.md)** - Metrics, health checks, Grafana dashboards, alerting
- **[gRPC Bridge](docs/grpc-bridge.md)** - gRPC interoperability, status mapping, metadata translation
- **[REST Gateway](docs/rest-gateway.md)** - RESTful HTTP access, OpenAPI 3.0, URL mapping
- **[CLI Tool](crates/quill-cli/README.md)** - CLI usage and examples

## Examples

- **[echo](examples/echo/)** - Unary RPC
- **[streaming](examples/streaming/)** - Server streaming (log tailing)
- **[upload](examples/upload/)** - Client streaming (file upload)
- **[chat](examples/chat/)** - Bidirectional streaming (chat room)
- **[greeter](examples/greeter/)** - Code generation example
- **[h3-echo](examples/h3-echo/)** - HTTP/3 unary RPC
- **[h3-streaming](examples/h3-streaming/)** - HTTP/3 server streaming
- **[h3-datagram](examples/h3-datagram/)** - HTTP/3 datagrams
- **[webtransport](examples/webtransport/)** - WebTransport with browser support

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/your-org/quill.git
cd quill

# Build the project
cargo build --workspace

# Run tests
cargo test --workspace

# Build documentation
cargo doc --no-deps --workspace --open
```

### Running Examples

```bash
# Run echo example tests
cargo test -p echo-example

# Run all example tests
cargo test --workspace

# Build the CLI
cargo build -p quill-cli
```

## License

MIT

