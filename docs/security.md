# Security Guide

This document covers security features and testing in Quill.

## Overview

Quill implements security measures to protect against common attacks in RPC systems:

1. **0-RTT Replay Protection** - Prevents replay attacks on non-idempotent methods
2. **Compression Side-Channel Mitigation** - Protects secrets from CRIME/BREACH-style attacks
3. **Fuzz Testing** - Validates robustness of parsers against malformed input
4. **TLS Requirements** - Enforces TLS 1.3 for all connections

## 0-RTT Security

### Background

HTTP/3 (QUIC) supports 0-RTT connection resumption for reduced latency. However, 0-RTT data can be replayed by an attacker, making it unsafe for non-idempotent operations.

### Quill's Approach

Quill provides the `IdempotencyChecker` to control which methods can use 0-RTT:

```rust
use quill_server::{IdempotencyChecker, is_early_data_request};

// Create checker and register idempotent methods
let mut checker = IdempotencyChecker::new();
checker.register_idempotent("image.v1.ImageService/GetMetadata");
checker.register_idempotent("image.v1.ImageService/GetThumbnail");

// In request handler
fn handle_request(req: &http::Request<()>, checker: &IdempotencyChecker) {
    let path = req.uri().path();
    let is_early = is_early_data_request(req.headers());

    if let Err(problem) = checker.validate_early_data(path, is_early) {
        // Return HTTP 425 Too Early
        return Err(problem);
    }

    // Process request...
}
```

### HTTP 425 Too Early

When a non-idempotent method is called with 0-RTT data, Quill returns:

```http
HTTP/3 425 Too Early
Content-Type: application/problem+json

{
  "type": "urn:quill:error:425",
  "title": "Request rejected due to early data",
  "status": 425,
  "detail": "Method 'image.v1.ImageService/Upload' is not idempotent and cannot be sent with 0-RTT data. Please retry without early data."
}
```

### Best Practices

1. **Mark idempotent methods in proto files**:
   ```protobuf
   service ImageService {
     rpc GetMetadata(GetRequest) returns (ImageMetadata) {
       option (quill.rpc) = { idempotent: true };
     }
   }
   ```

2. **Keep 0-RTT disabled by default** - Only enable for specific performance-critical paths

3. **Monitor 425 responses** - Track rejected early data to identify configuration issues

## Compression Side-Channel Protection

### Background

CRIME and BREACH attacks exploit HTTP compression to extract secrets by observing response sizes. Quill mitigates this by excluding sensitive headers from compression.

### Default Exclusions

The following headers are never compressed:

- `Authorization`
- `Cookie`
- `Set-Cookie`
- `X-API-Key`
- `X-Auth-Token`

### Adding Custom Exclusions

```rust
use quill_server::CompressionExclusions;

let mut exclusions = CompressionExclusions::default_exclusions();
exclusions.add_exclusion("X-Custom-Secret");
exclusions.add_exclusion("X-Session-Token");
```

## Fuzz Testing

Quill includes fuzz testing targets to validate parser robustness.

### Running Fuzz Tests

Fuzz testing requires the nightly Rust toolchain and `cargo-fuzz`:

```bash
# Install cargo-fuzz
cargo +nightly install cargo-fuzz

# Run frame parser fuzzer
cd fuzz
cargo +nightly fuzz run fuzz_frame_parser

# Run Problem Details JSON fuzzer
cargo +nightly fuzz run fuzz_problem_details

# Run varint fuzzer
cargo +nightly fuzz run fuzz_varint
```

### Fuzz Targets

#### fuzz_frame_parser

Tests the frame parser against arbitrary binary input:
- Validates handling of malformed varints
- Tests oversized frame rejection (> 4MB)
- Verifies incomplete frame handling
- Checks frame flag parsing

#### fuzz_problem_details

Tests Problem Details JSON deserialization:
- Invalid JSON handling
- Missing required fields
- Type coercion edge cases
- Unicode and escape sequences

#### fuzz_varint

Tests varint encoding/decoding:
- Roundtrip consistency
- Overflow handling (> 64 bits)
- Edge cases (0, max values)

### Corpus Seeds

Add seed inputs to `fuzz/corpus/<target>/` for better coverage:

```bash
# Add a valid frame as seed
mkdir -p fuzz/corpus/fuzz_frame_parser
echo -ne '\x05\x01hello' > fuzz/corpus/fuzz_frame_parser/valid_frame

# Add valid Problem Details JSON
mkdir -p fuzz/corpus/fuzz_problem_details
echo '{"type":"urn:test","title":"Test","status":200}' > fuzz/corpus/fuzz_problem_details/valid.json
```

## TLS Configuration

### Requirements

- TLS 1.3 is required for all connections
- mTLS for service-to-service communication
- JWT/OIDC for end-user authentication

### Server Configuration

```rust
use rustls::{ServerConfig, Certificate, PrivateKey};

// Load certificates
let certs = load_certs("server.crt");
let key = load_private_key("server.key");

// Create TLS config with TLS 1.3 only
let config = ServerConfig::builder()
    .with_safe_default_cipher_suites()
    .with_safe_default_kx_groups()
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3 required")
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .expect("Invalid certificate");
```

### Client Configuration

```rust
use rustls::{ClientConfig, RootCertStore};

let mut root_store = RootCertStore::empty();
root_store.add_parsable_certificates(webpki_roots::TLS_SERVER_ROOTS);

let config = ClientConfig::builder()
    .with_safe_default_cipher_suites()
    .with_safe_default_kx_groups()
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("TLS 1.3 required")
    .with_root_certificates(root_store)
    .with_no_client_auth();
```

## Security Testing

### Unit Tests

The security module includes comprehensive tests:

```bash
cargo test --package quill-server security
```

Tests cover:
- Idempotency checking
- Early data validation
- Compression exclusions
- Header case-insensitivity

### Integration Tests

For end-to-end security testing:

1. **0-RTT Replay Test**:
   ```bash
   # Start server with 0-RTT enabled
   ./server --enable-0rtt

   # Capture and replay 0-RTT data
   # Non-idempotent methods should return 425
   ```

2. **Compression Test**:
   ```bash
   # Verify Authorization header is not in compressed payload
   # by checking response size doesn't correlate with header value
   ```

## Security Checklist

Before deploying Quill services:

- [ ] TLS 1.3 enabled
- [ ] 0-RTT disabled or idempotent methods properly marked
- [ ] Sensitive headers excluded from compression
- [ ] Fuzz testing completed without crashes
- [ ] Problem Details don't leak internal errors
- [ ] Rate limiting configured
- [ ] Authentication middleware enabled

## Reporting Security Issues

Report security vulnerabilities to security@quillprism.dev.

Do not open public issues for security vulnerabilities.
