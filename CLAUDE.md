# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Quill is a modern, protobuf-first RPC framework with adaptive HTTP/1-3 transport (Prism), real HTTP errors, streaming, and a unified CLI for gen/call/bench. The framework includes:

- **Quill**: Protobuf-first RPC layer
- **Prism**: Transport profiles (Classic/H1-H2, Turbo/H2, Hyper/H3) that negotiate per-hop
- **CLI**: Single tool for code generation, making calls, benchmarking, compatibility checks, and payload decoding

### Core Design Principles

1. Keep `.proto` as the single source of truth
2. H3/QUIC is a progressive enhancement, not a requirement
3. No trailers required for correctness
4. Use HTTP status codes + typed Problem Details for errors (never 200-with-error-envelope)
5. DX first: gen/call/bench/compat/explain in one CLI

## Architecture

### Components

- **sdk-go**: Client (Prism negotiation, streaming, retries, backpressure, zstd) and Server (HTTP router, stream framing, Problem Details, OTel)
- **sdk-ts**: Browser (streaming over fetch/H2, H3/WebTransport when available) and Node.js (same API, H2/H3 clients)
- **runtime**: Server-side request lifecycle, auth, flow control, error mapping, transport profile selection
- **cli** (`tools/quill/`): Code generation, RPC testing, benchmarking, compatibility checking, payload decoding
- **bridges**: gRPC bridge (H2) and REST gateway with clean URLs and Problem Details

### Transport Profiles (Prism)

1. **Classic** (HTTP/1.1 + H2 without advanced features): For enterprise proxies and legacy networks. Datagrams emulated on a stream.
2. **Turbo** (HTTP/2 end-to-end): For cluster-internal traffic with native H2 streams and per-stream flow control.
3. **Hyper** (HTTP/3 over QUIC): For browser/mobile and lossy networks. Supports HTTP/3 Datagrams, WebTransport, 0-RTT for idempotent RPCs, and connection migration.

**Negotiation**: Client sends `Prefer: prism=hyper,turbo,classic` header; server responds with `Selected-Prism: <profile>`. Servers pick the highest mutually supported profile; routes may pin a minimum profile.

### API Surface

- **URL Template**: `/{package}.{service}/{method}`
- **HTTP Method**: POST for unary/streaming; GET allowed for cacheable idempotent reads
- **Content-Type**: `application/proto` (default) or `application/quill-tao`
- **Accept**: `application/proto, application/quill-tao;q=0.9`
- **Tracing**: `traceparent`, `tracestate` headers

### Stream Framing

Layout: `[length varint][flags byte][payload bytes]`

Flags:
- Bit 0: DATA
- Bit 1: END_STREAM
- Bit 2: CANCEL

Flow control: Credit-based at app layer + transport flow control

### Error Model (Problem Details)

- **Media Type**: `application/problem+json`
- **Required Fields**: `type`, `title`, `status`
- **Typed Extensions**: `quill_proto_type`, `quill_proto_detail_base64`
- **Always map to real HTTP status codes** (400, 401, 403, 404, 409, 422, 429, 499, 500, 501, 503, 504)
- Include trace IDs when safe; never leak secrets in Problem Details

### Resource Limits

- `max_frame_bytes`: 4,194,304 (4 MB)
- `max_streams_per_connection`: 100
- `zstd_threshold_bytes`: 1024

## Repository Structure

```
quill/
├── docs/           # Generated from YAML (architecture.md, api.md, cli.md)
├── proto/          # Protobuf definitions
├── sdk/
│   ├── go/         # Go SDK (client + server)
│   └── ts/         # TypeScript SDK (browser + node)
├── runtime/
│   └── go/         # Server runtime
├── tools/
│   └── quill/      # CLI tool
├── examples/       # Example services (media_service, chat_stream)
├── benches/        # Benchmarking scenarios
├── scripts/        # Build and development scripts
└── context/        # YAML specifications (architecture, design, etc.)
```

## CLI Commands

The `quill` CLI provides all tooling:

### Code Generation
```bash
quill gen --lang go,ts --out ./gen
```
Runs protoc plugins for Go/TS code generation.

### Making RPC Calls (curl-for-proto)
```bash
# Unary call
quill call https://api.example.com/media.v1.ImageService/GetMetadata \
  --in '{"id":"abc123"}' \
  --prism hyper

# Streaming call
quill call https://api.example.com/media.v1.ImageService/Thumbnails --stream
```

Flags: `--in <json|path>`, `--headers key:value`, `--stream`, `--accept`, `--prism`

### Benchmarking
```bash
quill bench
```
Input: `benchmarks.yaml` format. Measures tail latency and throughput.

### Compatibility Checks
```bash
quill compat --against <ref|registry>
```
Uses Buf for breaking-change detection.

### Payload Decoding
```bash
quill explain --descriptor_set path/to.pb --payload HEX|BASE64|FILE
```
Decodes arbitrary payloads using descriptors.

### Exit Codes
- 0: OK
- 2: Invalid input
- 3: Network/protocol error
- 4: Server-side error (non-2xx)

## Development Workflow

### Initial Setup
1. Review `context/architecture.yaml` and `context/design.yaml` for system overview
2. Check `context/reference_impl.yaml` and `context/repo_structure.yaml` for implementation guidance
3. Use `context/examples.yaml` for server/client/CLI behavior patterns

### Testing Strategy

**Unit Tests**:
- Frame encoder/decoder
- Problem Details mapper
- Negotiation headers

**Integration Tests**:
- Streaming with credit flow control
- Datagram fallback to stream
- zstd thresholds and content-encoding correctness

**E2E Tests**:
- Browser client -> edge H3 -> interior H2
- H2-only path through an ALB/Envoy

**Fuzz Tests**:
- Frame parser
- Problem Details JSON

**Chaos/Network Tests**:
- Loss, reordering, latency spikes (use netem)

**Security Tests**:
- 0-RTT replay attempts rejected for non-idempotent methods
- Compression side-channel exclusions enforced

**Acceptance Criteria**:
- All e2e tests pass across Classic/Turbo/Hyper profiles
- Benchmarks meet performance budgets (browser stream p99 < 250ms, service internal p99 < 40ms)

### Proto Annotations

Use `option (quill.rpc)` to declare method semantics:

```protobuf
service ImageService {
  rpc GetMetadata(GetRequest) returns (ImageMetadata) {
    option (quill.rpc) = { idempotent: true, cache_ttl_ms: 60000 };
  }
  rpc Upload(stream ImageChunk) returns (UploadAck) {
    option (quill.rpc) = { throws: ["QuotaExceeded"], throughput_hint: "high" };
  }
  rpc Thumbnails(stream Frame) returns (stream Thumb) {
    option (quill.rpc) = { real_time: true };
  }
}
```

- `idempotent: true` - Eligible for 0-RTT on Hyper profile
- `real_time: true` - Prefer datagrams if available; disable Nagle-like batching
- `throws: [...]` - Declares typed error details

## Performance Budgets

- **Browser stream p99**: 250ms
- **Service internal p99**: 40ms
- **Availability target**: 99.9%
- **Error budget policy**: SLO-based rollback on breach

## Security Baseline

- TLS 1.3 required
- mTLS for service-to-service
- JWT/OIDC for end-users
- 0-RTT only enabled for `idempotent: true` methods (return 425 Too Early on replay attempts)

## Reference Implementation

**Languages**: Go, TypeScript

**Server (Go)**:
- Router: `net/http` + `http2` + `quic-go` for H3
- Handlers: Generated from `.proto`
- Middlewares: OTel, auth, zstd, Problem Details

**Client (Go)**:
- Transport: `http2` with fallback to `http1`; `http3` when enabled

**Client (TypeScript)**:
- Browser: `fetch`/`EventSource`; `WebTransport` when available
- Node: `http2`/`http3`

**Artifacts**:
- Go module: `quillprism.dev/server`
- npm package: `@quill/prism`

## Deployment Topologies

1. **Edge H3 -> Interior H2**: H3 at CDN/edge terminates to H2 within the cluster
2. **H2 Everywhere**: Mature baseline; Prism Classic/Turbo only
3. **Browser Clients**: TS SDK prefers fetch/H2, upshifts to H3/WebTransport when available

## Interoperability

- Bridge to gRPC services (H2 transport)
- REST gateway with clean URLs and Problem Details error format
- Share protobuf types across messaging systems (NATS/Kafka)

## Implementation Status (Rust SDK)

### Phase 1: Foundation ✅
- [x] Core types and error handling (Problem Details)
- [x] Prism transport profile negotiation
- [x] Frame protocol (varint encoding, frame parsing)
- [x] Basic HTTP client and server
- [x] Unary RPC calls

### Phase 2: Transport Layer ✅
- [x] HTTP/1.1 support (Classic profile)
- [x] HTTP/2 support preparation (Turbo profile)
- [x] Router and handler infrastructure

### Phase 3: Streaming & Middleware ✅
- [x] Server-side streaming (server sends multiple responses)
- [x] Client-side streaming (client sends multiple requests)
- [x] Bidirectional streaming (both sides stream)
- [x] Credit-based flow control (CREDIT frames)
- [x] Frame protocol enhancements (DATA, END_STREAM, CANCEL, CREDIT flags)
- [x] zstd compression middleware (request/response compression)
- [x] OpenTelemetry tracing middleware (automatic instrumentation, distributed tracing)
- [x] Streaming examples: echo (unary), log tailing (server), file upload (client), chat (bidi)
- [x] Integration tests for all streaming modes (64 tests across all examples)

### Phase 4: Code Generation ✅
- [x] protoc plugin for service stubs (QuillServiceGenerator)
- [x] Client stub generation (generates type-safe client modules)
- [x] Server stub generation (generates async trait and route handlers)
- [x] Type-safe request/response handling (prost integration)
- [x] Greeter example demonstrating generated code
- [x] Support for unary and server-streaming RPCs

### Phase 5: CLI Tooling ✅
- [x] `quill gen` - Code generation command (via build.rs integration)
- [x] `quill call` - Make RPC calls (curl-for-proto) with streaming support
- [x] `quill bench` - Benchmarking framework (structured, implementation pending)
- [x] `quill compat` - Compatibility checking (structured, implementation pending)
- [x] `quill explain` - Payload decoding (structured, implementation pending)
- [x] Exit code handling and error reporting (0/2/3/4 codes)
- [x] CLI documentation and examples

### Phase 6: Production Middleware & Performance ✅
- [x] Authentication middleware (Bearer, API keys, Basic auth, custom)
- [x] Rate limiting middleware (token bucket algorithm)
- [x] Request/response logging middleware (with header sanitization)
- [x] Metrics middleware (requests, success/failure rates, bytes)
- [x] Comprehensive middleware documentation
- [x] 10 new middleware tests (98 total tests passing)
- [ ] Retry policies with exponential backoff (future)
- [ ] Circuit breaker pattern (future)
- [ ] Connection pooling (future)

### Phase 7: Performance Benchmarking & Profiling ✅
- [x] Full `quill bench` command with benchmarks.yaml support
- [x] Criterion-based microbenchmarks for frame operations (encoding, decoding, roundtrip)
- [x] Middleware overhead benchmarks (auth, rate limiting, metrics, compression)
- [x] Compression level benchmarks (levels 1-22)
- [x] Performance documentation with real benchmark results
- [x] Performance budget verification (all targets met)
- [x] Optimization guide and best practices
- [x] 3 new CLI tests for benchmarking (100 total tests passing)

### Phase 8: HTTP/2 Full Support ✅
- [x] HTTP/2 server implementation with full configuration
- [x] HTTP version selection (Auto/Http1Only/Http2Only)
- [x] HTTP/2 flow control settings (window sizes, max streams)
- [x] HTTP/2 keep-alive configuration
- [x] HTTP/2 client with connection pooling
- [x] Client connection pool configuration (idle timeout, max connections)
- [x] HTTP/2 adaptive windows
- [x] Turbo profile support (HTTP/2 end-to-end)
- [x] Comprehensive HTTP/2 documentation with examples
- [x] All tests passing (100 total tests)

### Phase 9: Retry Policies and Circuit Breakers ✅
- [x] Retry policy implementation with exponential backoff
- [x] Configurable backoff parameters (initial, max, multiplier)
- [x] Jitter support to prevent thundering herd
- [x] Selective retries based on error type
- [x] Circuit breaker state machine (Closed/Open/HalfOpen)
- [x] Configurable circuit breaker thresholds
- [x] Rolling window for failure tracking
- [x] Client builder integration for retry and circuit breaker
- [x] Comprehensive test suite (14 tests for retry/circuit breaker)
- [x] Complete resilience documentation with examples

### Phase 10: Production Deployment & Operations ✅
- [x] Comprehensive deployment guide (Docker, Kubernetes, monitoring)
- [x] Multi-stage Dockerfile with security hardening
- [x] Docker Compose stack with Prometheus, Grafana, Jaeger
- [x] Kubernetes manifests (Deployment, Service, ConfigMap, HPA)
- [x] Security-hardened pod specifications
- [x] Health check and readiness probe implementation
- [x] Prometheus scrape configuration
- [x] Configuration management best practices
- [x] Load balancing and scaling strategies
- [x] Complete deployment examples with README

### Phase 11: Enhanced Observability ✅
- [x] Comprehensive metrics collection system (ObservabilityCollector)
- [x] Prometheus-compatible metrics endpoint
- [x] JSON metrics export
- [x] Detailed health check with dependency status
- [x] Production-ready Grafana dashboard
- [x] Prometheus alerting rules (15+ alerts)
- [x] SLO monitoring (availability, latency)
- [x] Complete observability documentation
- [x] 4 new observability tests (116 total tests passing)

### Phase 12: gRPC Bridge ✅
- [x] gRPC status code to HTTP/Problem Details mapping (bidirectional)
- [x] HTTP status to gRPC status conversion
- [x] Metadata/header translation (binary and ASCII headers)
- [x] Base64 encoding for binary metadata
- [x] Header filtering (gRPC-internal and HTTP-specific)
- [x] Bridge configuration and client integration
- [x] Unary call bridging implementation
- [x] Comprehensive test suite (12 tests)
- [x] Complete bridge documentation (use cases, architecture, implementation guide)
- [x] All compilation errors resolved

### Phase 13: HTTP/3 Hyper Profile (Full Implementation) ✅
- [x] QUIC/HTTP/3 dependency integration (quinn 0.11, h3 0.0.8, h3-quinn 0.0.10, rustls 0.23)
- [x] Hyper profile transport layer implementation
- [x] HTTP/3 configuration structure (HyperConfig)
- [x] 0-RTT support configuration for idempotent requests
- [x] HTTP/3 datagrams configuration
- [x] Connection migration support configuration
- [x] Feature flag for optional HTTP/3 support
- [x] H3ServerBuilder and H3ClientBuilder with fluent API
- [x] HyperTransport implementation
- [x] HyperError type for HTTP/3-specific errors
- [x] Full HTTP/3 server with quinn::Endpoint
- [x] Full HTTP/3 client with quinn::Connection
- [x] RequestResolver API integration for h3 0.0.8
- [x] TLS configuration with ring crypto provider
- [x] QuillH3Client with Quill framing protocol integration
- [x] QuillH3Server for serving RPCs over HTTP/3
- [x] Streaming support over HTTP/3 (server, client, bidirectional)
- [x] H3ResponseFrameStream for parsing framed responses
- [x] Comprehensive test suite (17 client tests, 24 server tests, 5 transport tests)
- [x] Complete HTTP/3 documentation with Quill RPC examples

### Phase 14: REST Gateway with OpenAPI ✅
- [x] Gateway architecture and URL template mapping
- [x] HTTP method routing (GET, POST, PUT, PATCH, DELETE)
- [x] RouteMapping with path parameter extraction
- [x] URL template parsing and matching
- [x] OpenAPI 3.0 specification generation
- [x] OpenAPI spec builder with metadata
- [x] Problem Details error mapping (RFC 7807)
- [x] GatewayError types with HTTP status codes
- [x] Axum router integration
- [x] RestGatewayBuilder with fluent API
- [x] Authentication middleware (Bearer, API key, Basic, Custom)
- [x] CORS middleware with origin validation and preflight handling
- [x] Rate limiting middleware with token bucket algorithm
- [x] Middleware composition and ordering
- [x] MessageConverter for JSON ↔ Protobuf conversion (prost-reflect)
- [x] Full RPC invocation via handle_request
- [x] Path parameter and query parameter merging
- [x] Comprehensive test suite (41 tests)
- [x] Complete REST gateway documentation (900+ lines)

### Phase 15: Tensor Support for ML Inference ✅
- [x] Proto definitions (tensor.proto, inference.proto, agent.proto)
- [x] Zero-copy frame protocol with 9-byte header (TensorFrame, FrameType enum)
- [x] quill-tensor crate with DType, Tensor, TensorMeta types
- [x] Half-precision float support (f16, bf16 via half crate)
- [x] Element trait for type-safe tensor data access
- [x] Tensor streaming with TensorStream, TensorSender, TensorReceiver
- [x] TensorFrameParser for parsing streaming tensor frames
- [x] Token streaming for LLM inference (Token, TokenBatch, TokenStream)
- [x] TokenBatchBuilder for efficient token batching
- [x] Agent-to-agent communication protocol (AgentMessage, AgentResponse, AgentContext)
- [x] Tool definitions and tool calls for agent capabilities
- [x] Byte-based flow control (TensorCreditTracker with high/low water marks)
- [x] Hysteresis-based pause/resume for preventing oscillation
- [x] Tensor chunking and reassembly for large tensors
- [x] Test suite (28 quill-tensor tests, 6 new flow control tests)

### Phase 16: HTTP/3 Datagrams ✅
- [x] Datagram type with payload and optional flow ID
- [x] QUIC varint encoding/decoding for flow IDs
- [x] DatagramSender for sending datagrams on connections
- [x] DatagramReceiver for async datagram reception
- [x] H3Connection for persistent connections with datagram support
- [x] H3Client.connect() method for establishing datagram-enabled connections
- [x] H3Client.send_datagram_oneshot() for fire-and-forget datagrams
- [x] DatagramHandler trait for server-side datagram processing
- [x] FnDatagramHandler for closure-based datagram handling
- [x] H3Server.serve_with_datagrams() for serving with datagram support
- [x] Size validation and max_datagram_size enforcement
- [x] Connection statistics via H3Connection.stats()
- [x] Comprehensive test suite (9 new datagram tests)
- [x] Complete datagram documentation in docs/http3.md

### Phase 17: WebTransport Support ✅
- [x] WebTransport module with `webtransport` feature flag
- [x] WebTransportConfig with HTTP/3 base and session settings
- [x] WebTransportError type for WebTransport-specific errors
- [x] Session type for server-side session handling
- [x] ClientSession type for client-side session operations
- [x] BiStream and UniStream types for stream handling
- [x] WebTransportHandler trait for session handling
- [x] FnWebTransportHandler for closure-based session handling
- [x] WebTransportServerBuilder with fluent API
- [x] WebTransportServer for accepting WebTransport connections
- [x] WebTransportClientBuilder with fluent API
- [x] WebTransportClient for connecting to WebTransport servers
- [x] Session management (session_id, remote_addr, config access)
- [x] Datagram send/receive on sessions
- [x] Bidirectional and unidirectional stream support
- [x] Browser JavaScript API documentation
- [x] WebTransport example with Message protocol (Text, Binary, Ping, Pong)
- [x] Comprehensive test suite (7 transport tests + 11 example tests)
- [x] Complete WebTransport documentation (docs/webtransport.md)

### Phase 18: Python Bindings via PyO3 ✅
- [x] quill-python crate with PyO3 0.22 and numpy 0.22 dependencies
- [x] PyDType bindings for all ML data types (float32, float64, float16, bfloat16, int8, int32, int64, uint8, bool)
- [x] PyTensor with NumPy integration (from_numpy, to_numpy, zeros, from_bytes)
- [x] PyTensorMeta for tensor metadata without data
- [x] PyToken for LLM token representation with logprob support
- [x] PyTokenBatch for efficient token streaming with iteration
- [x] PyQuillClient for RPC calls (call, call_json, headers, auth)
- [x] PyStreamResponse and iterator for streaming responses
- [x] pyproject.toml for maturin wheel building
- [x] Feature-flagged tests (`python-tests` feature for Rust tests)
- [x] Comprehensive README with API reference
- [x] Complete Python bindings documentation (docs/python-bindings.md)

### Phase 19: Zero-Copy GPU Tensor Streaming (Phase 19.4 ✅)
**Goal**: Enable direct network-to-GPU tensor transfers, bypassing CPU serialization for massive ML inference workloads.

**Phase 19.1: Foundation** (cudarc integration) ✅:
- [x] Add `cudarc` dependency with optional `cuda` feature flag
- [x] Create `CudaBuffer` type for GPU memory management
- [x] Add `TensorBuffer` enum (Cpu/Cuda variants)
- [x] Implement `GpuStatus` for GPU availability detection
- [x] Add `Device.is_gpu()`, `Device.is_cpu()`, `Device.allocate_buffer()` helpers
- [x] Add `TensorMeta.allocate_buffer()` for device-aware allocation
- [x] Graceful fallback to CPU when GPU unavailable
- [x] Comprehensive GPU streaming documentation (docs/gpu-streaming.md)
- [x] Context documentation (context/gpu_streaming.yaml)
- [x] 41 tests passing including GPU buffer tests

**Phase 19.2: Streaming Integration** ✅:
- [x] Create `GpuTensorReceiver` for device-aware tensor streaming
- [x] Implement device allocation based on `TensorMeta.device`
- [x] Add `GpuReceiverEvent` for streaming progress events
- [x] Implement data staging and device transfer at stream end
- [x] Add progress tracking (`received_bytes()`, `expected_bytes()`, `is_complete()`)
- [x] Add `take()` method returning `(TensorMeta, TensorBuffer)`
- [x] Add `take_tensor()` convenience method for CPU compatibility
- [x] 5 new streaming tests (46 total quill-tensor tests)
- [ ] GPU memory pressure signaling via flow control (future)

**Phase 19.3: Performance Optimization** ✅:
- [x] `PinnedMemoryPool` for page-locked host memory with size-class bucketing
- [x] `GpuMemoryPool` for GPU buffer reuse to avoid allocation latency
- [x] `PoolConfig` with default, high_throughput, and low_memory presets
- [x] `PoolStats` for monitoring hits/misses/returns/drops with hit_rate()
- [x] `PooledGpuReceiver` with integrated memory pool support
- [x] `PooledTensorBuffer` RAII wrapper for automatic pool returns
- [x] 60 quill-tensor tests (14 new pool tests)
- [x] Comprehensive memory pools documentation in docs/gpu-streaming.md
- [ ] Async DMA transfers with CUDA streams (future)
- [ ] Multi-GPU device routing (future)

**Phase 19.4: ML Framework Integration** ✅:
- [x] DLPack protocol implementation (DLTensor, DLManagedTensor, DLPackCapsule)
- [x] Device/dtype conversion between DLPack and Quill formats
- [x] CUDA Array Interface (CudaArrayInterface struct)
- [x] Python bindings for GPU (PyGpuStatus, PyTensorBuffer, PyDLPackCapsule)
- [x] `Tensor.to_dlpack()` method for ML framework interop
- [x] 68 quill-tensor tests (8 new DLPack tests)
- [x] Comprehensive ML framework integration documentation

### Phase 20: REST Gateway RPC Integration ✅
- [x] Implement actual RPC call logic in REST gateway router
- [x] JSON-to-Protobuf request body conversion (MessageConverter)
- [x] Protobuf-to-JSON response conversion
- [x] Path parameter injection into RPC payloads
- [x] Query parameter merging for GET requests

### Phase 21: CLI Completion ✅
- [x] `quill compat` - Full breaking change detection with Buf integration
- [x] `quill explain` - Payload decoding with file descriptor sets
- [x] Multiple output formats (JSON, text, debug)
- [x] Auto-detection of hex/base64/file input

### Phase 22: REST Gateway Streaming ✅
- [x] Server-Sent Events (SSE) for server-streaming RPCs
- [x] NDJSON (Newline-Delimited JSON) streaming format
- [x] EventSource-compatible SSE response format
- [x] Chunked transfer encoding for client streaming
- [x] Multipart request parsing for file uploads
- [x] ChunkedRequestReader for NDJSON/multipart parsing
- [x] StreamingConfig for route-level streaming configuration
- [x] StreamingMode enum (Unary, ServerStreaming, ClientStreaming, Bidirectional)
- [x] StreamingResponse builder for programmatic stream construction
- [x] Content-Type negotiation (SSE vs NDJSON vs JSON)
- [x] 63 REST gateway tests (7 new streaming tests)
- [x] Comprehensive streaming documentation in rest-gateway.md

### Phase 23: Codegen Client/Bidi Streaming Support ✅
- [x] `register_client_streaming` method on RpcRouter for client streaming handlers
- [x] `register_bidi_streaming` method on RpcRouter for bidirectional streaming handlers
- [x] Handler enum (Unary, ClientStreaming, Bidi) for type-safe handler dispatch
- [x] RequestStream type alias for client streaming input (`Pin<Box<dyn Stream<Item = Result<Bytes, QuillError>> + Send>>`)
- [x] ServerBuilder methods for client and bidi streaming registration
- [x] Code generation for client streaming route handlers (request stream → unary response)
- [x] Code generation for bidirectional streaming route handlers (request stream → response stream)
- [x] Byte stream to typed message mapping in generated code
- [x] Typed response to byte stream mapping for bidi streaming
- [x] 16 server codegen tests (3 new streaming tests)

### Phase 24: Client Codegen Streaming Fix ✅
- [x] Fixed `client_streaming` → `call_client_streaming` method name in client codegen
- [x] Fixed `bidirectional_streaming` → `call_bidi_streaming` method name in client codegen
- [x] Added 4 new client codegen streaming tests:
  - `test_generate_client_with_server_streaming`
  - `test_generate_client_with_client_streaming`
  - `test_generate_client_with_bidi_streaming`
  - `test_generate_client_all_streaming_types`
- [x] 20 codegen tests total (4 new client streaming tests)
- [x] All 363+ tests passing

### Phase 25: Fuzzing & Security Hardening ✅
- [x] cargo-fuzz infrastructure setup (`fuzz/` directory)
- [x] Frame parser fuzz target (`fuzz_frame_parser`)
- [x] Problem Details JSON fuzz target (`fuzz_problem_details`)
- [x] Varint encoding/decoding fuzz target (`fuzz_varint`)
- [x] 0-RTT replay protection (`IdempotencyChecker`)
- [x] HTTP 425 "Too Early" response for non-idempotent methods
- [x] Early-Data header detection (`is_early_data_request`)
- [x] Compression side-channel protection (`CompressionExclusions`)
- [x] Security module with 5 tests (`quill-server/src/security.rs`)
- [x] Public varint functions (`encode_varint`, `decode_varint`)
- [x] Security documentation (`docs/security.md`)
- [x] Fuzz testing documentation (`fuzz/README.md`)
- [x] 377 total tests passing (14 new security tests)

### Current Implementation Notes

**Streaming Architecture**: Implemented using chunked transfer encoding over HTTP/1.1 and native HTTP/2 streams. Response streams use `UnsyncBoxBody` for efficient frame streaming. Request streams are currently buffered before transmission. HTTP/2 multiplexing enables concurrent streams over a single connection.

**Flow Control**: Credit-based flow control is implemented with `CreditTracker` for atomic credit management. CREDIT frames can be sent to grant send permissions. Current implementation tracks credits and logs when they would be granted; full bidirectional credit exchange will be enabled with HTTP/2.

**Compression**: zstd compression is supported for both requests and responses. The client can enable compression via the builder pattern (`enable_compression(true)`). The server provides utilities for decompressing requests and compressing responses. Compression uses `Content-Encoding` and `Accept-Encoding` headers for negotiation.

**Tracing**: OpenTelemetry tracing is built-in with automatic instrumentation for all RPC calls. The client automatically creates spans with the `#[instrument]` attribute. The server provides utilities for creating spans (`create_rpc_span`), extracting trace context from headers (`extract_trace_context`), and recording RPC results. Follows OpenTelemetry semantic conventions for RPC systems with support for W3C Trace Context propagation.

**Frame Protocol**:
```
[length varint][flags byte][payload bytes]
```
Flags: DATA (0x01), END_STREAM (0x02), CANCEL (0x04), CREDIT (0x08)

**Files of Interest**:
- `crates/quill-core/src/framing.rs` - Frame protocol and parsing
- `crates/quill-core/src/flow_control.rs` - Credit tracking and TensorCreditTracker
- `crates/quill-core/src/profile.rs` - Prism profiles (Classic, Turbo, Hyper)
- `crates/quill-client/src/client.rs` - Client with streaming, compression, and tracing
- `crates/quill-client/src/h3_client.rs` - HTTP/3 client with Quill framing integration
- `crates/quill-server/src/streaming.rs` - Server streaming response
- `crates/quill-server/src/request_stream.rs` - Server request streaming
- `crates/quill-server/src/middleware.rs` - Compression and tracing utilities
- `crates/quill-server/src/observability.rs` - Metrics collection and health checks
- `crates/quill-server/src/security.rs` - 0-RTT protection and compression side-channel mitigation
- `crates/quill-server/src/h3_server.rs` - HTTP/3 server with RPC routing
- `crates/quill-transport/src/classic.rs` - HTTP/1.1 transport (Classic profile)
- `crates/quill-transport/src/turbo.rs` - HTTP/2 transport (Turbo profile)
- `crates/quill-transport/src/hyper.rs` - HTTP/3 transport (Hyper profile)
- `crates/quill-transport/src/webtransport.rs` - WebTransport server and client
- `crates/quill-grpc-bridge/src/status.rs` - gRPC/HTTP status code mapping
- `crates/quill-grpc-bridge/src/metadata.rs` - Metadata/header translation
- `crates/quill-grpc-bridge/src/bridge.rs` - gRPC bridge implementation
- `crates/quill-rest-gateway/src/mapping.rs` - URL templates and HTTP method routing
- `crates/quill-rest-gateway/src/openapi.rs` - OpenAPI 3.0 spec generation
- `crates/quill-rest-gateway/src/router.rs` - REST gateway router and RPC handler
- `crates/quill-rest-gateway/src/converter.rs` - JSON ↔ Protobuf conversion (MessageConverter)
- `crates/quill-rest-gateway/src/error.rs` - Problem Details error mapping
- `crates/quill-rest-gateway/src/streaming.rs` - SSE, NDJSON, and chunked request streaming
- `crates/quill-tensor/src/dtype.rs` - ML data types (f32, f16, bf16, etc.)
- `crates/quill-tensor/src/tensor.rs` - Tensor, TensorMeta, TensorView types
- `crates/quill-tensor/src/buffer.rs` - TensorBuffer, CudaBuffer, GpuStatus for GPU support
- `crates/quill-tensor/src/pool.rs` - PinnedMemoryPool, GpuMemoryPool for efficient buffer reuse
- `crates/quill-tensor/src/dlpack.rs` - DLPack protocol for ML framework interop
- `crates/quill-tensor/src/frame.rs` - Zero-copy TensorFrame protocol
- `crates/quill-tensor/src/stream.rs` - TensorStream, TensorSender, TensorReceiver, PooledGpuReceiver
- `crates/quill-tensor/src/token.rs` - Token, TokenBatch, TokenStream for LLM
- `proto/quill/tensor.proto` - Tensor protobuf definitions
- `proto/quill/inference.proto` - LLM inference service definitions
- `proto/quill/agent.proto` - Agent-to-agent communication definitions
- `examples/echo/` - Unary RPC example
- `examples/streaming/` - Server streaming (log tailing) example
- `examples/upload/` - Client streaming (file upload) example
- `examples/chat/` - Bidirectional streaming (chat room) example
- `examples/h3-echo/` - HTTP/3 unary RPC example
- `examples/h3-streaming/` - HTTP/3 server streaming example
- `examples/h3-datagram/` - HTTP/3 datagram example
- `examples/webtransport/` - WebTransport example with browser support
- `examples/grpc-bridge/` - gRPC to Quill bridge example
- `crates/quill-python/src/lib.rs` - Python module entry point
- `crates/quill-python/src/dtype.rs` - PyDType bindings
- `crates/quill-python/src/tensor.rs` - PyTensor, PyTensorMeta bindings
- `crates/quill-python/src/token.rs` - PyToken, PyTokenBatch bindings
- `crates/quill-python/src/client.rs` - PyQuillClient bindings
- `crates/quill-python/src/gpu.rs` - PyGpuStatus, PyTensorBuffer, PyDLPackCapsule bindings
- `docs/flow-control.md` - Detailed flow control documentation
- `docs/compression.md` - Compression usage and guidelines
- `docs/tracing.md` - OpenTelemetry tracing guide
- `docs/http2.md` - HTTP/2 configuration guide
- `docs/http3.md` - HTTP/3 over QUIC guide with Quill RPC examples
- `docs/webtransport.md` - WebTransport guide with browser integration
- `docs/observability.md` - Comprehensive observability guide
- `docs/grpc-bridge.md` - gRPC bridge architecture and usage
- `docs/rest-gateway.md` - REST gateway with OpenAPI guide
- `docs/python-bindings.md` - Python bindings guide with API reference
- `docs/gpu-streaming.md` - GPU tensor streaming guide with CUDA integration
- `docs/security.md` - Security guide (0-RTT protection, fuzzing, TLS)
- `fuzz/` - Fuzz testing infrastructure and targets
- `examples/README.md` - Comprehensive examples guide

**CLI**: `quill` binary provides code generation, RPC calls, benchmarking, compatibility checking, and payload decoding. See `crates/quill-cli/README.md` for usage.

**Middleware**: Production-ready authentication, rate limiting, request logging, and metrics collection. See `docs/middleware.md` for comprehensive guide.

**Performance**: Comprehensive benchmarking with Criterion.rs. Framework overhead < 20 µs for typical requests. All performance budgets met. HTTP/2 provides 3.8x higher throughput vs HTTP/1.1 for concurrent requests. See `docs/performance.md` for detailed results and optimization guide.

**Resilience**: Retry policies support exponential backoff with jitter to handle transient failures. Circuit breakers implement the state machine pattern (Closed/Open/HalfOpen) to fail fast and prevent cascading failures. Both patterns are configurable via the client builder. See `docs/resilience.md` for comprehensive guide.

**HTTP/2**: Full HTTP/2 support with multiplexing, connection pooling, and flow control. Server supports HTTP/1.1, HTTP/2, or auto-negotiation. Client supports connection pooling and HTTP/2 keep-alive. Turbo profile enables HTTP/2 end-to-end. See `docs/http2.md` for configuration guide.

**Observability**: Comprehensive metrics collection with Prometheus export, detailed health checks with dependency monitoring, Grafana dashboards, and production-ready alerting rules. See `docs/observability.md` for complete guide.

**gRPC Bridge**: Protocol bridge enabling full interoperability between gRPC and Quill services. Includes bidirectional status code mapping, metadata/header translation with binary encoding support, unary call bridging, and complete streaming support (server streaming, client streaming, and bidirectional streaming). All streaming patterns use async_stream for efficient stream translation. See `docs/grpc-bridge.md` for architecture and usage guide.

**HTTP/3**: Full Hyper profile transport implementation using quinn (QUIC) and h3 (HTTP/3). Server implementation uses quinn::Endpoint with h3::server::Connection for accepting requests via RequestResolver. Client implementation uses quinn::Connection with h3::client for sending requests and receiving responses. Supports 0-RTT for fast connection resumption, HTTP/3 datagrams for unreliable messaging, and connection migration for network changes. Uses ring crypto provider for TLS 1.3 with self-signed certificates for development. Feature-flagged via `http3` feature. **QuillH3Client** provides the same API as QuillClient (call, call_server_streaming, call_client_streaming, call_bidi_streaming) but uses HTTP/3 transport with Quill frame encoding/decoding. **QuillH3Server** serves RPC methods over HTTP/3 with the same handler registration pattern as QuillServer. See `docs/http3.md` for comprehensive guide with examples.

**REST Gateway**: RESTful HTTP gateway for Quill RPC services with OpenAPI 3.0 support, production middleware, and full RPC integration. Provides clean URL templates with path parameter extraction, HTTP method routing (GET/POST/PUT/PATCH/DELETE), automatic OpenAPI spec generation, and Problem Details (RFC 7807) error responses. The MessageConverter enables automatic JSON ↔ Protobuf conversion using prost-reflect for dynamic message reflection. Path and query parameters are merged into requests automatically. Includes authentication middleware (Bearer/API key/Basic/Custom), CORS middleware with origin validation, and token bucket rate limiting. Built on Axum with RestGatewayBuilder for easy setup. See `docs/rest-gateway.md` for complete guide.

**Tensor Support**: First-class tensor and token streaming for LLM inference and agent-to-agent communication. The quill-tensor crate provides:
- **Data Types**: Full ML data type support including f32, f64, f16 (IEEE), bf16 (bfloat16), i8, i32, i64, u8, and bool via the `half` crate
- **Zero-Copy Frame Protocol**: 9-byte header format `[FrameType (1B)][Reserved (4B)][Length (4B)]` with frame types: PROTO_MSG (0x01), END_STREAM (0x02), CANCEL (0x04), CREDIT (0x08), TENSOR_META (0x10), TENSOR_PAYLOAD (0x11), TOKEN_BATCH (0x20)
- **Tensor Streaming**: TensorSender encodes tensors as TENSOR_META + TENSOR_PAYLOAD frames; TensorReceiver pre-allocates buffers based on metadata for zero-copy writes
- **Token Streaming**: Token and TokenBatch types for efficient LLM token generation with logprobs, sequence IDs, and batching via TokenBatchBuilder
- **Agent Protocol**: AgentMessage, AgentResponse, AgentContext with tool definitions and calls for agent-to-agent communication
- **Byte-Based Flow Control**: TensorCreditTracker with high/low water marks and hysteresis to prevent oscillation
- Proto definitions in `proto/quill/tensor.proto`, `proto/quill/inference.proto`, and `proto/quill/agent.proto`

**WebTransport**: Browser-compatible bidirectional communication over HTTP/3 with streams and datagrams. Built on h3-webtransport for the WebTransport protocol and h3-datagram for datagram support. Provides WebTransportServer and WebTransportClient with builder patterns, Session and ClientSession for session management, BiStream and UniStream for stream handling. The `webtransport` feature flag enables the module. Native Rust clients can connect with datagram and stream support. Browser clients use the native WebTransport API with JavaScript examples provided. See `docs/webtransport.md` for complete guide.

**Python Bindings**: PyO3-based Python package (`quill`) for ML inference and tensor streaming. Provides PyDType (ML data types), PyTensor/PyTensorMeta (NumPy integration), PyToken/PyTokenBatch (LLM token streaming), and PyQuillClient (RPC calls). Build with maturin: `cd crates/quill-python && maturin develop`. Tests require `python-tests` feature flag. See `docs/python-bindings.md` for comprehensive guide.

**Tests**: 377 tests passing across all crates and examples (unit tests, integration tests, middleware tests, CLI tests, retry/circuit breaker tests, observability tests, gRPC bridge tests with streaming, gRPC bridge example tests, HTTP/3 transport tests, HTTP/3 datagram tests, HTTP/3 datagram example tests, HTTP/3 example tests (h3-echo, h3-streaming), WebTransport transport tests, WebTransport example tests, REST gateway tests, REST gateway streaming tests (SSE, NDJSON, chunked), authentication tests, CORS tests, rate limit tests, tensor tests, GPU buffer tests, GPU streaming tests, DLPack tests, LLM inference example tests, Python binding tests, security tests (0-RTT, compression exclusions), and benchmark tests)
