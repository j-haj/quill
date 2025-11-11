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
- [x] Integration tests (112 tests passing)

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

### Next Steps

- [ ] Add HTTP/3 Hyper profile (QUIC support)
- [ ] Enhanced observability (custom metrics, dashboards)
- [ ] gRPC bridge implementation

## Documentation

- **[Architecture Guide](https://your-org.github.io/quill/guide/architecture.md)** - System design and implementation
- **[API Reference](https://your-org.github.io/quill/)** - Complete API documentation
- **[Flow Control](https://your-org.github.io/quill/guide/flow-control.md)** - Credit-based flow control
- **[Compression](https://your-org.github.io/quill/guide/compression.md)** - zstd compression guide
- **[Tracing](https://your-org.github.io/quill/guide/tracing.md)** - OpenTelemetry integration
- **[Middleware](docs/middleware.md)** - Authentication, rate limiting, logging, metrics
- **[Performance](docs/performance.md)** - Benchmarks, optimization guide, performance budgets
- **[HTTP/2](docs/http2.md)** - HTTP/2 configuration, Turbo profile, connection pooling
- **[Resilience](docs/resilience.md)** - Retry policies and circuit breakers
- **[Deployment](docs/deployment.md)** - Production deployment, Docker, Kubernetes, monitoring
- **[Deployment Examples](deployment/examples/README.md)** - Ready-to-use Docker and K8s configs
- **[CLI Tool](crates/quill-cli/README.md)** - CLI usage and examples

## Examples

- **[echo](examples/echo/)** - Unary RPC
- **[streaming](examples/streaming/)** - Server streaming (log tailing)
- **[upload](examples/upload/)** - Client streaming (file upload)
- **[chat](examples/chat/)** - Bidirectional streaming (chat room)
- **[greeter](examples/greeter/)** - Code generation example

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

