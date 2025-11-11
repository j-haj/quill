# Middleware Guide

Quill provides a comprehensive suite of middleware for production-ready RPC services. This guide covers authentication, rate limiting, logging, metrics, and more.

## Table of Contents

- [Authentication](#authentication)
- [Rate Limiting](#rate-limiting)
- [Request Logging](#request-logging)
- [Metrics Collection](#metrics-collection)
- [Compression](#compression)
- [Tracing](#tracing)

## Authentication

Quill supports multiple authentication schemes: Bearer tokens, API keys, and Basic auth.

### API Key Authentication

```rust
use quill_server::middleware::{ApiKeyValidator, AuthLayer, AuthScheme, AuthResult};
use std::sync::Arc;

// Create an API key validator
let mut validator = ApiKeyValidator::new();
validator.add_key("key123".to_string(), "user1".to_string());
validator.add_key("key456".to_string(), "service1".to_string());

// Create auth layer
let auth = AuthLayer::new(
    AuthScheme::ApiKey {
        header_name: "X-API-Key".to_string(),
    },
    Arc::new(validator),
);

// Use in request handling
let result = auth.authenticate(&request);
match result {
    AuthResult::Authenticated(identity) => {
        println!("Authenticated as: {}", identity);
        // Process request
    }
    AuthResult::Failed(msg) => {
        // Return 401 Unauthorized
        eprintln!("Auth failed: {}", msg);
    }
    AuthResult::None => {
        // No auth provided (if optional)
    }
}
```

### Bearer Token Authentication

```rust
use quill_server::middleware::{AuthLayer, AuthScheme, AuthValidator};

// Implement custom validator (e.g., JWT validation)
struct JwtValidator {
    secret: String,
}

impl AuthValidator for JwtValidator {
    fn validate(&self, token: &str) -> Result<String, String> {
        // Decode and validate JWT
        // Return user ID/email on success
        Ok("user@example.com".to_string())
    }
}

// Create auth layer
let auth = AuthLayer::new(
    AuthScheme::Bearer,
    Arc::new(JwtValidator {
        secret: "your-secret".to_string(),
    }),
);
```

### Optional Authentication

Make authentication optional for public endpoints:

```rust
let auth = AuthLayer::new(scheme, validator).optional();

match auth.authenticate(&request) {
    AuthResult::Authenticated(identity) => {
        // Process as authenticated request
    }
    AuthResult::None => {
        // Process as anonymous request
    }
    AuthResult::Failed(_) => {
        // Return 401 even for optional auth if credentials were provided but invalid
    }
}
```

### Custom Authentication Schemes

```rust
use quill_server::middleware::{AuthValidator, AuthScheme};

// Implement your own validator
struct CustomValidator;

impl AuthValidator for CustomValidator {
    fn validate(&self, token: &str) -> Result<String, String> {
        // Custom validation logic
        if token.starts_with("custom-") {
            Ok(token[7..].to_string())
        } else {
            Err("Invalid custom token".to_string())
        }
    }
}

let auth = AuthLayer::new(
    AuthScheme::Custom("MyScheme".to_string()),
    Arc::new(CustomValidator),
);
```

## Rate Limiting

Prevent abuse with token bucket rate limiting.

### Basic Rate Limiting

```rust
use quill_server::middleware::RateLimitLayer;

// 100 requests per second with burst of 200
let rate_limiter = RateLimitLayer::new(100.0, 200.0);

// Check before processing request
if !rate_limiter.check_rate_limit() {
    // Return 429 Too Many Requests
    return Err(QuillError::Rpc("Rate limit exceeded".to_string()));
}

// Process request...
```

### Custom Rate Limiter

```rust
use quill_server::middleware::RateLimiter;
use std::sync::Arc;

// Create custom rate limiter
let limiter = Arc::new(RateLimiter::new(
    50.0,  // capacity (burst size)
    10.0,  // refill rate (tokens per second)
));

// Use in handler
if !limiter.try_acquire() {
    // Rate limited
}

// Can also acquire multiple tokens
if !limiter.try_acquire_n(5.0) {
    // Not enough tokens
}

// Check available tokens
let available = limiter.available();
```

### Per-User Rate Limiting

```rust
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use quill_server::middleware::RateLimiter;

struct PerUserRateLimiter {
    limiters: Arc<Mutex<HashMap<String, Arc<RateLimiter>>>>,
    default_rate: f64,
    default_burst: f64,
}

impl PerUserRateLimiter {
    pub fn new(rate: f64, burst: f64) -> Self {
        Self {
            limiters: Arc::new(Mutex::new(HashMap::new())),
            default_rate: rate,
            default_burst: burst,
        }
    }

    pub fn check(&self, user_id: &str) -> bool {
        let mut limiters = self.limiters.lock().unwrap();
        let limiter = limiters.entry(user_id.to_string()).or_insert_with(|| {
            Arc::new(RateLimiter::new(self.default_burst, self.default_rate))
        });
        limiter.try_acquire()
    }
}
```

## Request Logging

Log incoming requests and responses with automatic header sanitization.

### Basic Logging

```rust
use quill_server::middleware::RequestLogger;

let logger = RequestLogger::new();

// Log incoming request
logger.log_request(&request);

// Process request...
let start = std::time::Instant::now();

// Log response
logger.log_response(http::StatusCode::OK, start.elapsed());
```

Output:
```
INFO Incoming request method=POST uri=/service/Method version=HTTP/1.1
DEBUG header=content-type value=application/proto
DEBUG header=authorization value=[REDACTED]
INFO Response sent status=200 OK duration_ms=42
```

### Disable Logging

```rust
let logger = RequestLogger::disabled();
```

### Structured Logging

The request logger uses `tracing` for structured logs:

```rust
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Initialize tracing
tracing_subscriber::registry()
    .with(tracing_subscriber::fmt::layer().json())
    .init();

// All request logs will now be in JSON format
```

## Metrics Collection

Collect request/response metrics with atomic counters.

### Basic Metrics

```rust
use quill_server::middleware::MetricsCollector;
use std::sync::Arc;

let metrics = Arc::new(MetricsCollector::new());

// In request handler
let metrics_clone = metrics.clone();

// Record request
metrics_clone.record_request();
metrics_clone.record_bytes_received(request.len() as u64);

// Process request...
match process_request().await {
    Ok(response) => {
        metrics_clone.record_success();
        metrics_clone.record_bytes_sent(response.len() as u64);
    }
    Err(_) => {
        metrics_clone.record_failure();
    }
}

// Get metrics snapshot
let snapshot = metrics.get_metrics();
println!("Total requests: {}", snapshot.requests_total);
println!("Success rate: {:.2}%", snapshot.success_rate() * 100.0);
println!("Error rate: {:.2}%", snapshot.error_rate() * 100.0);
println!("Bytes sent: {}", snapshot.bytes_sent);
println!("Bytes received: {}", snapshot.bytes_received);
```

### Expose Metrics Endpoint

```rust
use quill_server::{QuillServer, ServerBuilder};
use quill_server::middleware::MetricsCollector;

let metrics = Arc::new(MetricsCollector::new());

let server = QuillServer::builder()
    .register("metrics/Get", move |_| {
        let metrics = metrics.clone();
        async move {
            let snapshot = metrics.get_metrics();
            let json = serde_json::json!({
                "requests_total": snapshot.requests_total,
                "requests_success": snapshot.requests_success,
                "requests_failed": snapshot.requests_failed,
                "success_rate": snapshot.success_rate(),
                "error_rate": snapshot.error_rate(),
                "bytes_sent": snapshot.bytes_sent,
                "bytes_received": snapshot.bytes_received,
            });
            Ok(Bytes::from(json.to_string()))
        }
    })
    .build();
```

### Prometheus Integration

For Prometheus metrics, use the `prometheus` crate:

```rust
use prometheus::{Counter, Encoder, Histogram, Registry, TextEncoder};

lazy_static! {
    static ref REGISTRY: Registry = Registry::new();

    static ref REQUESTS_TOTAL: Counter = Counter::new(
        "quill_requests_total",
        "Total number of RPC requests"
    ).unwrap();

    static ref REQUEST_DURATION: Histogram = Histogram::new(
        "quill_request_duration_seconds",
        "Request duration in seconds"
    ).unwrap();
}

// Register metrics
REGISTRY.register(Box::new(REQUESTS_TOTAL.clone())).unwrap();
REGISTRY.register(Box::new(REQUEST_DURATION.clone())).unwrap();

// In handler
REQUESTS_TOTAL.inc();
let timer = REQUEST_DURATION.start_timer();
// ... process request ...
timer.observe_duration();

// Expose metrics endpoint
let encoder = TextEncoder::new();
let metric_families = REGISTRY.gather();
let mut buffer = vec![];
encoder.encode(&metric_families, &mut buffer).unwrap();
```

## Compression

See [Compression Guide](compression.md) for detailed compression documentation.

```rust
use quill_server::middleware::{compress_zstd, decompress_zstd};

// Compress response
let compressed = compress_zstd(&data, 3)?;

// Decompress request
let decompressed = decompress_zstd(&compressed_data)?;
```

## Tracing

See [Tracing Guide](tracing.md) for detailed OpenTelemetry documentation.

```rust
use quill_server::middleware::create_rpc_span;
use tracing::instrument;

#[instrument]
async fn handle_request() {
    let span = create_rpc_span("service.v1.Service", "Method");
    let _enter = span.enter();

    // Request processing happens within span
}
```

## Complete Example

Combining all middleware:

```rust
use quill_server::{QuillServer, ServerBuilder};
use quill_server::middleware::*;
use std::sync::Arc;
use std::time::Instant;

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Setup middleware
    let validator = Arc::new(ApiKeyValidator::new()
        .with_key("key123".to_string(), "user1".to_string()));

    let auth = Arc::new(AuthLayer::new(
        AuthScheme::ApiKey {
            header_name: "X-API-Key".to_string(),
        },
        validator,
    ));

    let rate_limiter = Arc::new(RateLimitLayer::new(100.0, 200.0));
    let logger = Arc::new(RequestLogger::new());
    let metrics = Arc::new(MetricsCollector::new());

    // Build server with middleware
    let server = QuillServer::builder()
        .register("service/Method", move |request| {
            let auth = auth.clone();
            let rate_limiter = rate_limiter.clone();
            let logger = logger.clone();
            let metrics = metrics.clone();

            async move {
                let start = Instant::now();

                // Record request
                metrics.record_request();

                // Check rate limit
                if !rate_limiter.check_rate_limit() {
                    metrics.record_failure();
                    return Err(QuillError::Rpc("Rate limit exceeded".to_string()));
                }

                // Authenticate
                // (In real code, you'd extract request to get headers)
                // match auth.authenticate(&http_request) { ... }

                // Process request
                let response = process(request).await?;

                // Record success
                metrics.record_success();
                logger.log_response(http::StatusCode::OK, start.elapsed());

                Ok(response)
            }
        })
        .build();

    server.serve("127.0.0.1:8080".parse().unwrap()).await.unwrap();
}
```

## Best Practices

1. **Layer Order**: Apply middleware in this order:
   - Logging (first, to log everything)
   - Metrics (early, to track all requests)
   - Rate limiting (before auth, to prevent auth brute force)
   - Authentication
   - Compression
   - Tracing (spans around business logic)

2. **Security**:
   - Never log sensitive data (tokens, passwords)
   - Use HTTPS/TLS in production
   - Validate all tokens properly
   - Set appropriate rate limits

3. **Performance**:
   - Use Arc for shared middleware
   - Compression only for large payloads (>1KB)
   - Sample traces in high-traffic services
   - Aggregate metrics periodically

4. **Error Handling**:
   - Return appropriate HTTP status codes
   - Log errors with context
   - Track error rates in metrics
   - Include trace IDs in errors

## See Also

- [Flow Control](flow-control.md) - Credit-based flow control
- [Compression](compression.md) - zstd compression
- [Tracing](tracing.md) - OpenTelemetry tracing
- [Architecture](architecture.md) - System design
