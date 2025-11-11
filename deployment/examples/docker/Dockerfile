# Multi-stage Dockerfile for Quill services
# Optimized for production use with minimal image size

# Build stage
FROM rust:1.75-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY proto ./proto
COPY examples ./examples

# Build release binary with optimizations
ENV CARGO_PROFILE_RELEASE_LTO=true
ENV CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
RUN cargo build --release --bin echo-server

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 quill && \
    mkdir -p /app /app/logs /app/config && \
    chown -R quill:quill /app

WORKDIR /app

# Copy binary from builder
COPY --from=builder --chown=quill:quill /app/target/release/echo-server /usr/local/bin/

# Switch to non-root user
USER quill

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run service
ENTRYPOINT ["echo-server"]
CMD []
