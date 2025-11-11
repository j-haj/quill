//! Middleware implementations for Quill server
//!
//! This module provides middleware for:
//! - Compression (zstd)
//! - Decompression of incoming requests
//! - Content negotiation
//! - OpenTelemetry tracing
//! - Authentication (JWT, API keys)
//! - Rate limiting
//! - Request logging
//! - Metrics collection

use bytes::Bytes;
use http::{header, Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use quill_core::QuillError;
use tracing::{span, Level, Span};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Compression level for zstd
pub const DEFAULT_COMPRESSION_LEVEL: i32 = 3;

/// Minimum body size to compress (in bytes)
pub const MIN_COMPRESS_SIZE: usize = 1024; // 1KB

/// Check if the client accepts zstd compression
pub fn accepts_zstd(req: &Request<Incoming>) -> bool {
    req.headers()
        .get(header::ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("zstd"))
        .unwrap_or(false)
}

/// Compress bytes using zstd
pub fn compress_zstd(data: &[u8], level: i32) -> Result<Bytes, QuillError> {
    zstd::encode_all(data, level)
        .map(Bytes::from)
        .map_err(|e| QuillError::Transport(format!("Compression failed: {}", e)))
}

/// Decompress bytes using zstd
pub fn decompress_zstd(data: &[u8]) -> Result<Bytes, QuillError> {
    zstd::decode_all(data)
        .map(Bytes::from)
        .map_err(|e| QuillError::Transport(format!("Decompression failed: {}", e)))
}

/// Decompress request body if it's compressed
///
/// Returns the request parts and the decompressed body bytes
pub async fn decompress_request_body(
    req: Request<Incoming>,
) -> Result<(http::request::Parts, Bytes), QuillError> {
    let (parts, body) = req.into_parts();

    // Read body
    let body_bytes = body
        .collect()
        .await
        .map_err(|e| QuillError::Transport(format!("Failed to read request body: {}", e)))?
        .to_bytes();

    // Check if compressed
    let decompressed = if let Some(encoding) = parts.headers.get(header::CONTENT_ENCODING) {
        if encoding == "zstd" {
            decompress_zstd(&body_bytes)?
        } else {
            body_bytes
        }
    } else {
        body_bytes
    };

    Ok((parts, decompressed))
}

/// Compress response body if appropriate
///
/// Note: This is a placeholder for future implementation.
/// Compressing streaming responses requires a compression stream adapter.
pub fn compress_response<B>(
    response: Response<B>,
    _accept_zstd: bool,
) -> Response<B>
where
    B: http_body::Body<Data = Bytes, Error = QuillError> + Send + 'static,
{
    // For now, we'll return the response as-is
    // In a real implementation, we would:
    // 1. Check if body is large enough to compress
    // 2. Compress the body
    // 3. Add Content-Encoding header
    // 4. Return compressed response
    //
    // This is tricky because we need to consume the body to compress it,
    // but we want to stream responses. For streaming responses, we'd need
    // a compression stream adapter.
    response
}

/// Middleware layer for compression
pub struct CompressionLayer {
    level: i32,
}

impl CompressionLayer {
    pub fn new() -> Self {
        Self {
            level: DEFAULT_COMPRESSION_LEVEL,
        }
    }

    pub fn with_level(level: i32) -> Self {
        Self { level }
    }

    pub fn level(&self) -> i32 {
        self.level
    }
}

impl Default for CompressionLayer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// OpenTelemetry Tracing
// ============================================================================

/// Create a tracing span for an RPC request
///
/// This creates a span with the RPC service and method as attributes,
/// following OpenTelemetry semantic conventions for RPC systems.
pub fn create_rpc_span(service: &str, method: &str) -> Span {
    span!(
        Level::INFO,
        "rpc.request",
        rpc.service = service,
        rpc.method = method,
        rpc.system = "quill",
        otel.kind = "server",
    )
}

/// Extract trace context from HTTP headers
///
/// This extracts distributed tracing context (traceparent, tracestate)
/// from HTTP headers following W3C Trace Context specification.
pub fn extract_trace_context(req: &Request<Incoming>) -> HashMap<String, String> {
    let mut context = HashMap::new();

    // Extract traceparent header (W3C Trace Context)
    if let Some(traceparent) = req.headers().get("traceparent") {
        if let Ok(value) = traceparent.to_str() {
            context.insert("traceparent".to_string(), value.to_string());
        }
    }

    // Extract tracestate header
    if let Some(tracestate) = req.headers().get("tracestate") {
        if let Ok(value) = tracestate.to_str() {
            context.insert("tracestate".to_string(), value.to_string());
        }
    }

    // Extract baggage header (for cross-cutting concerns)
    if let Some(baggage) = req.headers().get("baggage") {
        if let Ok(value) = baggage.to_str() {
            context.insert("baggage".to_string(), value.to_string());
        }
    }

    context
}

/// Record common RPC attributes on a span
pub fn record_rpc_attributes(span: &Span, service: &str, method: &str, compressed: bool) {
    span.record("rpc.service", service);
    span.record("rpc.method", method);
    span.record("rpc.system", "quill");
    if compressed {
        span.record("rpc.compression", "zstd");
    }
}

/// Record the RPC result on a span
pub fn record_rpc_result(span: &Span, success: bool, error: Option<&str>) {
    if success {
        span.record("rpc.status", "ok");
    } else {
        span.record("rpc.status", "error");
        if let Some(err) = error {
            span.record("rpc.error", err);
        }
    }
}

/// Tracing middleware layer
pub struct TracingLayer {
    enabled: bool,
}

impl TracingLayer {
    pub fn new() -> Self {
        Self { enabled: true }
    }

    pub fn disabled() -> Self {
        Self { enabled: false }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl Default for TracingLayer {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Authentication
// ============================================================================

/// Authentication result
#[derive(Debug, Clone, PartialEq)]
pub enum AuthResult {
    /// Authentication succeeded with user/service identity
    Authenticated(String),
    /// Authentication failed
    Failed(String),
    /// No authentication provided (may be acceptable for public endpoints)
    None,
}

/// Authentication scheme
#[derive(Debug, Clone)]
pub enum AuthScheme {
    /// Bearer token (JWT or opaque token)
    Bearer,
    /// API key authentication
    ApiKey { header_name: String },
    /// Basic authentication
    Basic,
    /// Custom authentication scheme
    Custom(String),
}

/// Extract bearer token from Authorization header
pub fn extract_bearer_token(req: &Request<Incoming>) -> Option<String> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            if s.starts_with("Bearer ") {
                Some(s[7..].to_string())
            } else {
                None
            }
        })
}

/// Extract API key from header
pub fn extract_api_key(req: &Request<Incoming>, header_name: &str) -> Option<String> {
    req.headers()
        .get(header_name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Extract basic auth credentials
pub fn extract_basic_auth(req: &Request<Incoming>) -> Option<(String, String)> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| {
            if s.starts_with("Basic ") {
                let encoded = &s[6..];
                // In production, use base64 decoding
                // For now, this is a placeholder
                Some(("user".to_string(), "password".to_string()))
            } else {
                None
            }
        })
}

/// Authentication validator trait
///
/// Implement this trait to provide custom authentication logic.
pub trait AuthValidator: Send + Sync {
    /// Validate a token/credential and return the authenticated identity
    fn validate(&self, token: &str) -> Result<String, String>;
}

/// Simple API key validator (for demonstration)
pub struct ApiKeyValidator {
    valid_keys: HashMap<String, String>, // key -> identity
}

impl ApiKeyValidator {
    pub fn new() -> Self {
        Self {
            valid_keys: HashMap::new(),
        }
    }

    pub fn add_key(&mut self, key: String, identity: String) {
        self.valid_keys.insert(key, identity);
    }

    pub fn with_key(mut self, key: String, identity: String) -> Self {
        self.add_key(key, identity);
        self
    }
}

impl AuthValidator for ApiKeyValidator {
    fn validate(&self, token: &str) -> Result<String, String> {
        self.valid_keys
            .get(token)
            .cloned()
            .ok_or_else(|| "Invalid API key".to_string())
    }
}

/// Authentication middleware layer
pub struct AuthLayer {
    scheme: AuthScheme,
    validator: Arc<dyn AuthValidator>,
    required: bool,
}

impl AuthLayer {
    pub fn new(scheme: AuthScheme, validator: Arc<dyn AuthValidator>) -> Self {
        Self {
            scheme,
            validator,
            required: true,
        }
    }

    pub fn optional(mut self) -> Self {
        self.required = false;
        self
    }

    pub fn is_required(&self) -> bool {
        self.required
    }

    /// Authenticate a request
    pub fn authenticate(&self, req: &Request<Incoming>) -> AuthResult {
        match &self.scheme {
            AuthScheme::Bearer => {
                if let Some(token) = extract_bearer_token(req) {
                    match self.validator.validate(&token) {
                        Ok(identity) => AuthResult::Authenticated(identity),
                        Err(msg) => AuthResult::Failed(msg),
                    }
                } else if self.required {
                    AuthResult::Failed("Missing bearer token".to_string())
                } else {
                    AuthResult::None
                }
            }
            AuthScheme::ApiKey { header_name } => {
                if let Some(key) = extract_api_key(req, header_name) {
                    match self.validator.validate(&key) {
                        Ok(identity) => AuthResult::Authenticated(identity),
                        Err(msg) => AuthResult::Failed(msg),
                    }
                } else if self.required {
                    AuthResult::Failed("Missing API key".to_string())
                } else {
                    AuthResult::None
                }
            }
            AuthScheme::Basic => {
                if let Some((user, pass)) = extract_basic_auth(req) {
                    // Combine user:pass for validation
                    let credentials = format!("{}:{}", user, pass);
                    match self.validator.validate(&credentials) {
                        Ok(identity) => AuthResult::Authenticated(identity),
                        Err(msg) => AuthResult::Failed(msg),
                    }
                } else if self.required {
                    AuthResult::Failed("Missing basic auth".to_string())
                } else {
                    AuthResult::None
                }
            }
            AuthScheme::Custom(_name) => {
                // Custom schemes would extract and validate tokens differently
                AuthResult::Failed("Custom auth not implemented".to_string())
            }
        }
    }
}

// ============================================================================
// Rate Limiting
// ============================================================================

use std::sync::Mutex;

/// Rate limiter using token bucket algorithm
pub struct RateLimiter {
    tokens: Arc<Mutex<f64>>,
    capacity: f64,
    refill_rate: f64, // tokens per second
    last_refill: Arc<Mutex<Instant>>,
}

impl RateLimiter {
    /// Create a new rate limiter
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of tokens (burst size)
    /// * `refill_rate` - Tokens added per second
    pub fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: Arc::new(Mutex::new(capacity)),
            capacity,
            refill_rate,
            last_refill: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Try to consume a token
    ///
    /// Returns true if successful, false if rate limited
    pub fn try_acquire(&self) -> bool {
        self.try_acquire_n(1.0)
    }

    /// Try to consume n tokens
    pub fn try_acquire_n(&self, n: f64) -> bool {
        let mut tokens = self.tokens.lock().unwrap();
        let mut last_refill = self.last_refill.lock().unwrap();

        // Refill tokens based on elapsed time
        let now = Instant::now();
        let elapsed = now.duration_since(*last_refill).as_secs_f64();
        let refill = elapsed * self.refill_rate;

        *tokens = (*tokens + refill).min(self.capacity);
        *last_refill = now;

        // Try to consume tokens
        if *tokens >= n {
            *tokens -= n;
            true
        } else {
            false
        }
    }

    /// Get current token count
    pub fn available(&self) -> f64 {
        *self.tokens.lock().unwrap()
    }
}

/// Rate limiting middleware layer
pub struct RateLimitLayer {
    limiter: Arc<RateLimiter>,
}

impl RateLimitLayer {
    pub fn new(requests_per_second: f64, burst_size: f64) -> Self {
        Self {
            limiter: Arc::new(RateLimiter::new(burst_size, requests_per_second)),
        }
    }

    pub fn check_rate_limit(&self) -> bool {
        self.limiter.try_acquire()
    }
}

// ============================================================================
// Request Logging
// ============================================================================

/// Request logger for detailed request/response logging
pub struct RequestLogger {
    enabled: bool,
}

impl RequestLogger {
    pub fn new() -> Self {
        Self { enabled: true }
    }

    pub fn disabled() -> Self {
        Self { enabled: false }
    }

    pub fn log_request(&self, req: &Request<Incoming>) {
        if !self.enabled {
            return;
        }

        tracing::info!(
            method = %req.method(),
            uri = %req.uri(),
            version = ?req.version(),
            "Incoming request"
        );

        // Log headers (sanitized)
        for (name, value) in req.headers() {
            if name == "authorization" || name == "cookie" {
                tracing::debug!(header = %name, value = "[REDACTED]");
            } else if let Ok(v) = value.to_str() {
                tracing::debug!(header = %name, value = %v);
            }
        }
    }

    pub fn log_response(&self, status: StatusCode, duration: Duration) {
        if !self.enabled {
            return;
        }

        tracing::info!(
            status = %status,
            duration_ms = duration.as_millis(),
            "Response sent"
        );
    }
}

impl Default for RequestLogger {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Metrics
// ============================================================================

use std::sync::atomic::{AtomicU64, Ordering};

/// Simple metrics collector
pub struct MetricsCollector {
    requests_total: AtomicU64,
    requests_success: AtomicU64,
    requests_failed: AtomicU64,
    bytes_sent: AtomicU64,
    bytes_received: AtomicU64,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            requests_success: AtomicU64::new(0),
            requests_failed: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        }
    }

    pub fn record_request(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_success(&self) {
        self.requests_success.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.requests_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_bytes_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_bytes_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn get_metrics(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            requests_success: self.requests_success.load(Ordering::Relaxed),
            requests_failed: self.requests_failed.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of metrics at a point in time
#[derive(Debug, Clone, Copy)]
pub struct MetricsSnapshot {
    pub requests_total: u64,
    pub requests_success: u64,
    pub requests_failed: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl MetricsSnapshot {
    pub fn success_rate(&self) -> f64 {
        if self.requests_total == 0 {
            0.0
        } else {
            self.requests_success as f64 / self.requests_total as f64
        }
    }

    pub fn error_rate(&self) -> f64 {
        if self.requests_total == 0 {
            0.0
        } else {
            self.requests_failed as f64 / self.requests_total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zstd_roundtrip() {
        // Use a larger message with repetition for good compression
        let original = b"Hello, world! This is a test message. ".repeat(10);
        let compressed = compress_zstd(&original, 3).unwrap();
        let decompressed = decompress_zstd(&compressed).unwrap();

        assert_eq!(original, &decompressed[..]);
        // With repetition, compression should be effective
        assert!(compressed.len() < original.len());
    }

    #[test]
    fn test_compress_empty() {
        let original = b"";
        let compressed = compress_zstd(original, 3).unwrap();
        let decompressed = decompress_zstd(&compressed).unwrap();

        assert_eq!(original, &decompressed[..]);
    }

    #[test]
    fn test_compress_large() {
        // Create a large repeating pattern (should compress well)
        let original = vec![b'a'; 10000];
        let compressed = compress_zstd(&original, 3).unwrap();
        let decompressed = decompress_zstd(&compressed).unwrap();

        assert_eq!(original, &decompressed[..]);
        // Should achieve good compression on repeating data
        assert!(compressed.len() < original.len() / 10);
    }

    #[test]
    fn test_create_rpc_span() {
        // Create a span - just verify it doesn't panic
        let _span = create_rpc_span("echo.v1.EchoService", "Echo");
        // Metadata might not be available without an active subscriber
        // The important part is that the span is created successfully
    }

    #[test]
    fn test_tracing_layer() {
        let layer = TracingLayer::new();
        assert!(layer.is_enabled());

        let disabled = TracingLayer::disabled();
        assert!(!disabled.is_enabled());
    }

    #[test]
    fn test_api_key_validator() {
        let mut validator = ApiKeyValidator::new();
        validator.add_key("key123".to_string(), "user1".to_string());
        validator.add_key("key456".to_string(), "user2".to_string());

        assert_eq!(validator.validate("key123"), Ok("user1".to_string()));
        assert_eq!(validator.validate("key456"), Ok("user2".to_string()));
        assert!(validator.validate("invalid").is_err());
    }

    #[test]
    fn test_api_key_validator_builder() {
        let validator = ApiKeyValidator::new()
            .with_key("key1".to_string(), "user1".to_string())
            .with_key("key2".to_string(), "user2".to_string());

        assert_eq!(validator.validate("key1"), Ok("user1".to_string()));
        assert_eq!(validator.validate("key2"), Ok("user2".to_string()));
    }

    #[test]
    fn test_auth_result() {
        let authenticated = AuthResult::Authenticated("user1".to_string());
        assert_eq!(authenticated, AuthResult::Authenticated("user1".to_string()));

        let failed = AuthResult::Failed("Invalid token".to_string());
        assert_eq!(failed, AuthResult::Failed("Invalid token".to_string()));

        let none = AuthResult::None;
        assert_eq!(none, AuthResult::None);
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = RateLimiter::new(10.0, 5.0);

        // Should be able to consume 10 tokens
        for _ in 0..10 {
            assert!(limiter.try_acquire());
        }

        // Should be rate limited now
        assert!(!limiter.try_acquire());

        // Wait for refill
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Should have ~2.5 tokens now (5 tokens/sec * 0.5 sec)
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        // Third attempt might fail depending on timing
    }

    #[test]
    fn test_rate_limiter_burst() {
        let limiter = RateLimiter::new(5.0, 1.0);

        // Can consume burst
        assert!(limiter.try_acquire_n(5.0));

        // No more capacity
        assert!(!limiter.try_acquire());
    }

    #[test]
    fn test_rate_limit_layer() {
        let layer = RateLimitLayer::new(10.0, 5.0);

        // Should allow first few requests
        assert!(layer.check_rate_limit());
        assert!(layer.check_rate_limit());
    }

    #[test]
    fn test_request_logger() {
        let logger = RequestLogger::new();
        assert!(logger.enabled);

        let disabled = RequestLogger::disabled();
        assert!(!disabled.enabled);
    }

    #[test]
    fn test_metrics_collector() {
        let metrics = MetricsCollector::new();

        metrics.record_request();
        metrics.record_request();
        metrics.record_success();
        metrics.record_failure();
        metrics.record_bytes_sent(100);
        metrics.record_bytes_received(200);

        let snapshot = metrics.get_metrics();
        assert_eq!(snapshot.requests_total, 2);
        assert_eq!(snapshot.requests_success, 1);
        assert_eq!(snapshot.requests_failed, 1);
        assert_eq!(snapshot.bytes_sent, 100);
        assert_eq!(snapshot.bytes_received, 200);
    }

    #[test]
    fn test_metrics_snapshot_rates() {
        let snapshot = MetricsSnapshot {
            requests_total: 100,
            requests_success: 95,
            requests_failed: 5,
            bytes_sent: 1000,
            bytes_received: 2000,
        };

        assert_eq!(snapshot.success_rate(), 0.95);
        assert_eq!(snapshot.error_rate(), 0.05);
    }

    #[test]
    fn test_metrics_snapshot_empty() {
        let snapshot = MetricsSnapshot {
            requests_total: 0,
            requests_success: 0,
            requests_failed: 0,
            bytes_sent: 0,
            bytes_received: 0,
        };

        assert_eq!(snapshot.success_rate(), 0.0);
        assert_eq!(snapshot.error_rate(), 0.0);
    }
}
