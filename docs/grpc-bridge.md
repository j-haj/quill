# gRPC Bridge

This guide covers the gRPC to Quill protocol bridge, enabling interoperability with existing gRPC services.

## Table of Contents

- [Overview](#overview)
- [Status Code Mapping](#status-code-mapping)
- [Metadata Translation](#metadata-translation)
- [Bridge Architecture](#bridge-architecture)
- [Use Cases](#use-cases)
- [Implementation Guide](#implementation-guide)
- [Limitations](#limitations)

## Overview

The Quill gRPC bridge enables bidirectional communication between gRPC and Quill services:

- **gRPC → Quill**: Call Quill services from gRPC clients
- **Quill → gRPC**: Call gRPC services from Quill clients
- **Protocol Translation**: Automatic mapping between gRPC and HTTP/2 semantics
- **Error Mapping**: Convert between gRPC Status and HTTP Problem Details

## Status Code Mapping

### gRPC to HTTP Status Codes

The bridge maps gRPC canonical error codes to HTTP status codes:

| gRPC Code | HTTP Status | Description |
|-----------|-------------|-------------|
| OK | 200 | Success |
| CANCELLED | 499 | Client Closed Request |
| UNKNOWN | 500 | Internal Server Error |
| INVALID_ARGUMENT | 400 | Bad Request |
| DEADLINE_EXCEEDED | 504 | Gateway Timeout |
| NOT_FOUND | 404 | Not Found |
| ALREADY_EXISTS | 409 | Conflict |
| PERMISSION_DENIED | 403 | Forbidden |
| RESOURCE_EXHAUSTED | 429 | Too Many Requests |
| FAILED_PRECONDITION | 400 | Bad Request |
| ABORTED | 409 | Conflict |
| OUT_OF_RANGE | 400 | Bad Request |
| UNIMPLEMENTED | 501 | Not Implemented |
| INTERNAL | 500 | Internal Server Error |
| UNAVAILABLE | 503 | Service Unavailable |
| DATA_LOSS | 500 | Internal Server Error |
| UNAUTHENTICATED | 401 | Unauthorized |

### gRPC Status to Problem Details

gRPC status codes are converted to RFC 7807 Problem Details:

```rust
use quill_grpc_bridge::grpc_to_problem_details;
use tonic::Code;

let details = grpc_to_problem_details(
    Code::NotFound,
    "User not found".to_string()
);

assert_eq!(details.status, 404);
assert_eq!(details.title, "Not Found");
assert_eq!(details.type_uri, "urn:grpc:status:NOT_FOUND");
```

### HTTP Status to gRPC Code

```rust
use quill_grpc_bridge::http_to_grpc_status;
use http::StatusCode;

let grpc_code = http_to_grpc_status(StatusCode::NOT_FOUND);
assert_eq!(grpc_code, Code::NotFound);
```

## Metadata Translation

### gRPC Metadata to HTTP Headers

gRPC metadata is translated to HTTP headers:

```rust
use quill_grpc_bridge::grpc_metadata_to_http_headers;
use tonic::metadata::MetadataMap;

let mut metadata = MetadataMap::new();
metadata.insert("authorization", "Bearer token123".parse().unwrap());
metadata.insert("custom-header", "value".parse().unwrap());

let headers = grpc_metadata_to_http_headers(&metadata);
// headers now contains HTTP-compatible headers
```

**Header Filtering:**
- gRPC-internal headers (`grpc-*`) are filtered out
- HTTP/2 pseudo-headers (`:authority`, `:path`) are filtered out
- Custom application headers are forwarded

### HTTP Headers to gRPC Metadata

```rust
use quill_grpc_bridge::http_headers_to_grpc_metadata;
use http::HeaderMap;

let mut headers = HeaderMap::new();
headers.insert(http::header::AUTHORIZATION, "Bearer token123".parse().unwrap());

let metadata = http_headers_to_grpc_metadata(&headers);
// metadata now contains gRPC-compatible metadata
```

**Header Filtering:**
- HTTP-specific headers (`Host`, `Connection`) are filtered out
- Custom application headers are forwarded
- Binary headers (ending in `-bin`) are base64-encoded

## Bridge Architecture

### Components

```
┌──────────────┐         ┌─────────────┐         ┌──────────────┐
│              │         │             │         │              │
│ gRPC Client  │────────▶│  GrpcBridge │────────▶│ Quill Server │
│              │         │             │         │              │
└──────────────┘         └─────────────┘         └──────────────┘
                               │
                               │ Translates:
                               │ • Status codes
                               │ • Metadata/headers
                               │ • Protobuf messages
                               │
```

### Bridge Configuration

```rust
use quill_grpc_bridge::{GrpcBridge, GrpcBridgeConfig};

let config = GrpcBridgeConfig {
    quill_base_url: "http://localhost:8080".to_string(),
    enable_logging: true,
    forward_metadata: true,
};

let bridge = GrpcBridge::new(config)?;
```

### Unary Call Bridging

```rust
// Bridge a gRPC unary call to Quill
let response = bridge.call_unary(
    "echo.v1.EchoService",  // Service
    "Echo",                  // Method
    request,                 // gRPC Request<T>
).await?;
```

### Streaming Support

The bridge supports all gRPC streaming patterns:

#### Server Streaming

Server sends multiple responses to client:

```rust
use tokio_stream::StreamExt;

// Bridge server streaming call
let mut stream = bridge.call_server_streaming::<MyRequest, MyResponse>(
    "my.service.MyService",
    "StreamResults",
    request,
).await?;

// Process responses as they arrive
while let Some(result) = stream.get_mut().next().await {
    match result {
        Ok(response) => {
            // Handle response
            println!("Received: {:?}", response);
        }
        Err(status) => {
            eprintln!("Stream error: {}", status);
            break;
        }
    }
}
```

#### Client Streaming

Client sends multiple requests, receives single response:

```rust
use tokio_stream::iter;

// Create a stream of requests
let requests = vec![req1, req2, req3];
let request_stream = iter(requests);

// Convert to gRPC Streaming
let grpc_stream = tokio_stream::StreamExt::map(request_stream, Ok);

// Bridge client streaming call
let response = bridge.call_client_streaming::<MyRequest, MyResponse>(
    "my.service.MyService",
    "AggregateData",
    Request::new(grpc_stream),
).await?;
```

#### Bidirectional Streaming

Both client and server stream:

```rust
use tokio_stream::StreamExt;

// Create request stream
let request_stream = /* your stream */;

// Bridge bidirectional streaming call
let mut response_stream = bridge.call_bidi_streaming::<MyRequest, MyResponse>(
    "my.service.MyService",
    "Chat",
    Request::new(request_stream),
).await?;

// Process responses as they arrive
while let Some(result) = response_stream.get_mut().next().await {
    match result {
        Ok(response) => {
            // Handle response
            println!("Received: {:?}", response);
        }
        Err(status) => {
            eprintln!("Stream error: {}", status);
            break;
        }
    }
}
```

## Use Cases

### 1. Gradual Migration from gRPC to Quill

**Scenario:** Organization has existing gRPC services and wants to adopt Quill gradually.

**Solution:** Use bridge to allow gRPC clients to call new Quill services:

```
┌─────────────┐
│ gRPC Client │ (existing)
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ gRPC Bridge │
└──────┬──────┘
       │
       ├──────▶ Quill Service A (new)
       │
       └──────▶ Quill Service B (new)
```

### 2. Protocol Gateway

**Scenario:** Expose Quill services to gRPC-only clients.

**Solution:** Deploy bridge as a gateway:

```
Internet           Internal Network
    │
    ▼
┌─────────────┐     ┌──────────────┐
│ gRPC Bridge │────▶│ Quill Service│
│  (Gateway)  │     │   Cluster    │
└─────────────┘     └──────────────┘
```

### 3. Hybrid Architecture

**Scenario:** Run both gRPC and Quill services in same infrastructure.

**Solution:** Use bridge for cross-protocol communication:

```
┌─────────────┐         ┌─────────────┐
│ gRPC Service│◀───────▶│ Bridge      │◀───────▶┌──────────────┐
└─────────────┘         └─────────────┘         │ Quill Service│
                                                 └──────────────┘
```

## Implementation Guide

### Step 1: Status Code Mapping

Implement status code conversion:

```rust
use quill_grpc_bridge::{grpc_to_http_status, grpc_to_problem_details};
use tonic::Code;

// Convert gRPC status to HTTP
let http_status = grpc_to_http_status(Code::NotFound);

// Convert to Problem Details
let details = grpc_to_problem_details(
    Code::Internal,
    "Database connection failed".to_string()
);
```

### Step 2: Create Bridge Instance

```rust
use quill_grpc_bridge::{GrpcBridge, GrpcBridgeConfig};

let bridge = GrpcBridge::new(GrpcBridgeConfig {
    quill_base_url: "http://quill-service:8080".to_string(),
    enable_logging: true,
    forward_metadata: true,
})?;
```

### Step 3: Bridge gRPC Service

```rust
// Define your gRPC service
#[tonic::async_trait]
impl MyService for MyServiceBridge {
    async fn my_method(
        &self,
        request: Request<MyRequest>,
    ) -> Result<Response<MyResponse>, Status> {
        // Bridge to Quill
        self.bridge.call_unary(
            "my.package.MyService",
            "MyMethod",
            request,
        ).await
    }
}
```

### Step 4: Deploy

Deploy the bridge as a sidecar or gateway:

```yaml
# Kubernetes sidecar
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: grpc-bridge
      image: quill-grpc-bridge:latest
      ports:
        - containerPort: 50051  # gRPC
      env:
        - name: QUILL_BASE_URL
          value: "http://localhost:8080"

    - name: quill-service
      image: my-quill-service:latest
      ports:
        - containerPort: 8080  # HTTP/2
```

## Limitations

### Current Implementation

The bridge implementation in `crates/quill-grpc-bridge` provides comprehensive gRPC-Quill interoperability:

**Completed:**
- ✅ Status code mapping (gRPC ↔ HTTP)
- ✅ Problem Details conversion
- ✅ Metadata translation with binary encoding
- ✅ Bridge configuration structure
- ✅ Unary call bridging
- ✅ Server streaming bridging
- ✅ Client streaming bridging
- ✅ Bidirectional streaming bridging
- ✅ Comprehensive test suite (17 tests)

**Requires Development:**
- ⚠️ Production testing and error handling
- ⚠️ Performance optimization
- ⚠️ Complete example services

### Protocol Differences

Some differences between gRPC and Quill require careful handling:

1. **Timeouts**: gRPC uses deadline, Quill uses HTTP timeouts
2. **Cancellation**: Different cancellation semantics
3. **Backpressure**: gRPC flow control vs Quill credit system
4. **Error Details**: gRPC Status vs Problem Details structure

### Performance Considerations

- **Additional Hop**: Bridge adds latency
- **Serialization**: Double encoding/decoding overhead
- **Connection Pooling**: Maintain connections to both sides
- **Header Translation**: Some overhead in conversion

### Recommendations

For production use:

1. **Direct Integration**: Prefer native Quill or gRPC where possible
2. **Bridge as Gateway**: Use bridge at edge, not between every service
3. **Monitor Performance**: Track bridge latency and throughput
4. **Gradual Migration**: Use bridge during transition period only

## Future Development

Areas for enhancement:

1. **Advanced Error Mapping**:
   - Custom error detail translation
   - Preserve error metadata
   - Stack trace forwarding

2. **Performance Optimization**:
   - Connection pooling
   - Header caching
   - Zero-copy where possible
   - Stream buffer optimization

3. **Observability**:
   - Bridge-specific metrics
   - Tracing correlation
   - Error tracking
   - Streaming backpressure metrics

4. **Production Features**:
   - Complete example services
   - Integration tests with real gRPC services
   - Load testing and benchmarks
   - Best practices documentation

## See Also

- [Resilience Guide](resilience.md) - Retry and circuit breaker for bridge calls
- [HTTP/2 Configuration](http2.md) - Optimize HTTP/2 for bridge
- [Performance Guide](performance.md) - Bridge performance optimization

## References

- [gRPC Status Codes](https://grpc.io/docs/guides/error/)
- [RFC 7807 Problem Details](https://tools.ietf.org/html/rfc7807)
- [HTTP/2 Specification](https://httpwg.org/specs/rfc7540.html)
