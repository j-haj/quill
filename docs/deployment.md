# Production Deployment Guide

This guide covers deploying Quill services to production environments, including containerization, orchestration, monitoring, and best practices.

## Table of Contents

- [Docker Containerization](#docker-containerization)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Health Checks & Readiness](#health-checks--readiness)
- [Monitoring & Observability](#monitoring--observability)
- [Configuration Management](#configuration-management)
- [Load Balancing & Scaling](#load-balancing--scaling)
- [Security & Hardening](#security--hardening)

## Docker Containerization

### Multi-Stage Dockerfile

Use multi-stage builds for optimal image size and security:

```dockerfile
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

# Build release binary
RUN cargo build --release --bin your-service

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 quill

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/your-service /usr/local/bin/

# Switch to non-root user
USER quill

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run service
CMD ["your-service"]
```

### Optimized Dockerfile with Caching

Cache dependencies separately for faster builds:

```dockerfile
FROM rust:1.75-slim as builder

RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only dependency files first (for caching)
COPY Cargo.toml Cargo.lock ./
COPY crates/*/Cargo.toml ./crates/

# Create dummy source files to build dependencies
RUN mkdir -p crates/quill-server/src && \
    echo "fn main() {}" > crates/quill-server/src/main.rs

# Build dependencies (cached layer)
RUN cargo build --release

# Remove dummy files
RUN rm -rf crates/*/src

# Copy actual source code
COPY crates ./crates
COPY proto ./proto

# Build with actual source (fast, dependencies cached)
RUN cargo build --release --bin your-service

# Runtime stage (same as above)
FROM debian:bookworm-slim
# ... rest of runtime stage
```

### Docker Compose for Local Development

```yaml
version: '3.8'

services:
  quill-service:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    environment:
      - RUST_LOG=info
      - QUILL_HTTP_VERSION=auto
      - QUILL_MAX_CONNECTIONS=1000
    volumes:
      - ./config:/app/config:ro
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 10s
      timeout: 3s
      retries: 3
    networks:
      - quill-network

  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
    networks:
      - quill-network

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards:ro
      - ./grafana/datasources:/etc/grafana/provisioning/datasources:ro
    networks:
      - quill-network

volumes:
  prometheus-data:
  grafana-data:

networks:
  quill-network:
    driver: bridge
```

### Build Script

Create a `docker-build.sh` script:

```bash
#!/bin/bash
set -e

SERVICE_NAME="quill-service"
VERSION=$(git describe --tags --always --dirty)
REGISTRY="your-registry.example.com"

echo "Building ${SERVICE_NAME}:${VERSION}"

# Build image
docker build -t ${SERVICE_NAME}:${VERSION} .
docker tag ${SERVICE_NAME}:${VERSION} ${SERVICE_NAME}:latest

# Optional: Push to registry
if [ "$1" == "push" ]; then
    docker tag ${SERVICE_NAME}:${VERSION} ${REGISTRY}/${SERVICE_NAME}:${VERSION}
    docker tag ${SERVICE_NAME}:${VERSION} ${REGISTRY}/${SERVICE_NAME}:latest
    docker push ${REGISTRY}/${SERVICE_NAME}:${VERSION}
    docker push ${REGISTRY}/${SERVICE_NAME}:latest
fi

echo "Build complete!"
```

## Kubernetes Deployment

### Deployment Manifest

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: quill-service
  namespace: production
  labels:
    app: quill-service
    version: v1
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: quill-service
  template:
    metadata:
      labels:
        app: quill-service
        version: v1
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
        prometheus.io/path: "/metrics"
    spec:
      # Security context
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000

      # Pod anti-affinity for high availability
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchLabels:
                    app: quill-service
                topologyKey: kubernetes.io/hostname

      containers:
        - name: quill-service
          image: your-registry.example.com/quill-service:v1.0.0
          imagePullPolicy: IfNotPresent

          ports:
            - name: http
              containerPort: 8080
              protocol: TCP

          # Resource limits
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 1000m
              memory: 512Mi

          # Environment variables
          env:
            - name: RUST_LOG
              value: "info"
            - name: QUILL_HTTP_VERSION
              value: "http2"
            - name: QUILL_MAX_CONNECTIONS
              value: "1000"
            - name: POD_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
            - name: POD_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace

          # Liveness probe
          livenessProbe:
            httpGet:
              path: /health
              port: http
            initialDelaySeconds: 15
            periodSeconds: 20
            timeoutSeconds: 3
            failureThreshold: 3

          # Readiness probe
          readinessProbe:
            httpGet:
              path: /ready
              port: http
            initialDelaySeconds: 5
            periodSeconds: 10
            timeoutSeconds: 3
            failureThreshold: 3

          # Startup probe (for slow-starting apps)
          startupProbe:
            httpGet:
              path: /health
              port: http
            initialDelaySeconds: 0
            periodSeconds: 10
            timeoutSeconds: 3
            failureThreshold: 30

          # Volume mounts
          volumeMounts:
            - name: config
              mountPath: /app/config
              readOnly: true

      volumes:
        - name: config
          configMap:
            name: quill-service-config
```

### Service Manifest

```yaml
apiVersion: v1
kind: Service
metadata:
  name: quill-service
  namespace: production
  labels:
    app: quill-service
spec:
  type: ClusterIP
  ports:
    - port: 8080
      targetPort: http
      protocol: TCP
      name: http
  selector:
    app: quill-service
```

### ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: quill-service-config
  namespace: production
data:
  service.yaml: |
    server:
      http_version: http2
      max_connections: 1000
      http2_max_concurrent_streams: 200

    resilience:
      retry_max_attempts: 3
      circuit_breaker_threshold: 5

    observability:
      metrics_enabled: true
      tracing_enabled: true
```

### HorizontalPodAutoscaler

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: quill-service-hpa
  namespace: production
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: quill-service
  minReplicas: 3
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Percent
          value: 50
          periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
        - type: Percent
          value: 100
          periodSeconds: 15
        - type: Pods
          value: 2
          periodSeconds: 15
      selectPolicy: Max
```

### Ingress (for external access)

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: quill-service-ingress
  namespace: production
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/backend-protocol: "HTTP"
    nginx.ingress.kubernetes.io/http2-push-preload: "true"
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - api.example.com
      secretName: quill-service-tls
  rules:
    - host: api.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: quill-service
                port:
                  number: 8080
```

## Health Checks & Readiness

### Implementing Health Endpoints

Add health check endpoints to your server:

```rust
use quill_server::{QuillServer, ServerBuilder};
use http::{Response, StatusCode};
use bytes::Bytes;

async fn health_handler() -> Result<Response<Bytes>, quill_core::QuillError> {
    // Basic health check
    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(Bytes::from(r#"{"status":"healthy"}"#))
        .unwrap())
}

async fn ready_handler() -> Result<Response<Bytes>, quill_core::QuillError> {
    // Check if service is ready (e.g., database connections)
    let is_ready = check_dependencies().await;

    if is_ready {
        Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Bytes::from(r#"{"status":"ready"}"#))
            .unwrap())
    } else {
        Ok(Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(Bytes::from(r#"{"status":"not_ready"}"#))
            .unwrap())
    }
}

async fn check_dependencies() -> bool {
    // Check database, cache, external services, etc.
    true
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = ServerBuilder::new()
        .http2_only()
        .register("health", health_handler)
        .register("ready", ready_handler)
        .register("my.service/Method", actual_handler)
        .build();

    server.serve("0.0.0.0:8080").await?;
    Ok(())
}
```

### Health Check Best Practices

1. **Liveness Probe** - Checks if the process is alive
   - Fast (<1s response time)
   - Doesn't check dependencies
   - Failure = restart pod

2. **Readiness Probe** - Checks if ready to accept traffic
   - Can check dependencies
   - Failure = remove from load balancer
   - More thorough than liveness

3. **Startup Probe** - For slow-starting applications
   - Gives more time for initialization
   - Prevents premature restarts

## Monitoring & Observability

### Prometheus Configuration

`prometheus.yml`:

```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'quill-services'
    kubernetes_sd_configs:
      - role: pod
        namespaces:
          names:
            - production
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_scrape]
        action: keep
        regex: true
      - source_labels: [__meta_kubernetes_pod_annotation_prometheus_io_path]
        action: replace
        target_label: __metrics_path__
        regex: (.+)
      - source_labels: [__address__, __meta_kubernetes_pod_annotation_prometheus_io_port]
        action: replace
        regex: ([^:]+)(?::\d+)?;(\d+)
        replacement: $1:$2
        target_label: __address__
      - action: labelmap
        regex: __meta_kubernetes_pod_label_(.+)
      - source_labels: [__meta_kubernetes_namespace]
        action: replace
        target_label: kubernetes_namespace
      - source_labels: [__meta_kubernetes_pod_name]
        action: replace
        target_label: kubernetes_pod_name
```

### Metrics Endpoint

Expose metrics in your service:

```rust
use quill_server::middleware::MetricsCollector;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let metrics = Arc::new(MetricsCollector::new());

    // Register metrics endpoint
    let server = ServerBuilder::new()
        .register("metrics", {
            let m = metrics.clone();
            move || {
                let snapshot = m.snapshot();
                let json = serde_json::to_string(&snapshot).unwrap();
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(Bytes::from(json))
                    .unwrap())
            }
        })
        .build();

    Ok(())
}
```

### Grafana Dashboard

Create a dashboard JSON for Quill metrics:

```json
{
  "dashboard": {
    "title": "Quill Service Metrics",
    "panels": [
      {
        "title": "Request Rate",
        "targets": [
          {
            "expr": "rate(quill_requests_total[5m])"
          }
        ]
      },
      {
        "title": "Error Rate",
        "targets": [
          {
            "expr": "rate(quill_errors_total[5m])"
          }
        ]
      },
      {
        "title": "Response Time (p99)",
        "targets": [
          {
            "expr": "histogram_quantile(0.99, quill_request_duration_seconds_bucket)"
          }
        ]
      }
    ]
  }
}
```

### OpenTelemetry Configuration

```rust
use opentelemetry::global;
use opentelemetry::sdk::trace::{Config, Tracer};
use opentelemetry::sdk::Resource;
use opentelemetry_otlp::WithExportConfig;

fn init_tracing() -> Result<Tracer, Box<dyn std::error::Error>> {
    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint("http://jaeger:4317")
        )
        .with_trace_config(
            Config::default()
                .with_resource(Resource::new(vec![
                    opentelemetry::KeyValue::new("service.name", "quill-service"),
                    opentelemetry::KeyValue::new("service.version", "1.0.0"),
                ]))
        )
        .install_batch(opentelemetry::runtime::Tokio)?;

    Ok(tracer)
}
```

## Configuration Management

### Environment-Based Configuration

```rust
use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub observability: ObservabilityConfig,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub http_version: String,
    pub max_connections: usize,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            server: ServerConfig {
                host: env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
                port: env::var("SERVER_PORT")
                    .unwrap_or_else(|_| "8080".to_string())
                    .parse()?,
                http_version: env::var("HTTP_VERSION").unwrap_or_else(|_| "auto".to_string()),
                max_connections: env::var("MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "1000".to_string())
                    .parse()?,
            },
            // ... other config sections
        })
    }

    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&contents)?;
        Ok(config)
    }
}
```

### Configuration Precedence

1. **Command-line arguments** (highest priority)
2. **Environment variables**
3. **Configuration file**
4. **Default values** (lowest priority)

```rust
fn load_config() -> Result<Config, Box<dyn std::error::Error>> {
    let mut config = Config::default();

    // Load from file if specified
    if let Ok(config_path) = env::var("CONFIG_FILE") {
        config = Config::from_file(&config_path)?;
    }

    // Override with environment variables
    if let Ok(port) = env::var("SERVER_PORT") {
        config.server.port = port.parse()?;
    }

    // Command-line args would override here

    Ok(config)
}
```

## Load Balancing & Scaling

### Horizontal Scaling Strategy

Quill services are designed for horizontal scaling:

1. **Stateless Design**: No session affinity required
2. **Connection Pooling**: Efficient resource usage
3. **HTTP/2 Multiplexing**: Multiple requests per connection
4. **Circuit Breakers**: Prevent cascade failures

### Load Balancer Configuration

**Nginx Configuration**:

```nginx
upstream quill_backend {
    least_conn;  # or ip_hash, round_robin

    server quill-1:8080 max_fails=3 fail_timeout=30s;
    server quill-2:8080 max_fails=3 fail_timeout=30s;
    server quill-3:8080 max_fails=3 fail_timeout=30s;

    keepalive 32;
    keepalive_requests 100;
}

server {
    listen 80 http2;
    server_name api.example.com;

    location / {
        proxy_pass http://quill_backend;
        proxy_http_version 1.1;

        # Connection pooling
        proxy_set_header Connection "";

        # Preserve client info
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 5s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    location /health {
        access_log off;
        proxy_pass http://quill_backend;
    }
}
```

### Scaling Guidelines

| Traffic Level | Replicas | CPU Request | Memory Request |
|---------------|----------|-------------|----------------|
| Low (< 100 RPS) | 2-3 | 100m | 128Mi |
| Medium (100-1000 RPS) | 3-5 | 250m | 256Mi |
| High (1000-10000 RPS) | 5-20 | 500m | 512Mi |
| Very High (> 10000 RPS) | 20+ | 1000m | 1Gi |

**Scaling Metrics**:
- CPU usage > 70%
- Memory usage > 80%
- Request latency p99 > 500ms
- Connection pool saturation

## Security & Hardening

### Security Checklist

- [ ] Run as non-root user
- [ ] Use read-only root filesystem
- [ ] Drop unnecessary capabilities
- [ ] Enable TLS for all communication
- [ ] Use network policies
- [ ] Implement rate limiting
- [ ] Enable authentication
- [ ] Scan images for vulnerabilities
- [ ] Use secrets management
- [ ] Enable audit logging

### Secured Pod Spec

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: quill-service
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
    seccompProfile:
      type: RuntimeDefault

  containers:
    - name: quill-service
      image: quill-service:v1
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop:
            - ALL
      volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /app/cache

  volumes:
    - name: tmp
      emptyDir: {}
    - name: cache
      emptyDir: {}
```

### TLS Configuration

```rust
use quill_server::ServerBuilder;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = ServerBuilder::new()
        .tls_cert_path("/app/certs/tls.crt")
        .tls_key_path("/app/certs/tls.key")
        .build();

    server.serve("0.0.0.0:8443").await?;
    Ok(())
}
```

### Network Policy

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: quill-service-netpol
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: quill-service
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: production
      ports:
        - protocol: TCP
          port: 8080
  egress:
    - to:
        - namespaceSelector:
            matchLabels:
              name: production
      ports:
        - protocol: TCP
          port: 5432  # Database
        - protocol: TCP
          port: 6379  # Redis
    - to:
        - namespaceSelector: {}
      ports:
        - protocol: TCP
          port: 53  # DNS
        - protocol: UDP
          port: 53
```

## See Also

- [HTTP/2 Configuration](http2.md)
- [Resilience Guide](resilience.md)
- [Performance Guide](performance.md)
- [Middleware Guide](middleware.md)

## References

- [Kubernetes Best Practices](https://kubernetes.io/docs/concepts/configuration/overview/)
- [Docker Security](https://docs.docker.com/engine/security/)
- [Prometheus Monitoring](https://prometheus.io/docs/introduction/overview/)
- [12-Factor App](https://12factor.net/)
