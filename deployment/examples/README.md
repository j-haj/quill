# Quill Deployment Examples

This directory contains production-ready deployment examples for Quill services.

## Directory Structure

```
deployment/examples/
├── docker/              # Docker and Docker Compose examples
│   ├── Dockerfile       # Production-ready multi-stage Dockerfile
│   └── docker-compose.yml  # Local development stack
├── kubernetes/          # Kubernetes manifests
│   ├── deployment.yaml  # Deployment with security hardening
│   ├── service.yaml     # Service and headless service
│   ├── configmap.yaml   # Configuration management
│   └── hpa.yaml         # Horizontal Pod Autoscaler
└── monitoring/          # Monitoring configurations
    └── prometheus.yml   # Prometheus scrape configuration
```

## Quick Start

### Docker Compose (Local Development)

```bash
# From the root of the repository
cd deployment/examples/docker
docker-compose up -d

# Access services:
# - Quill Echo Service: http://localhost:8080
# - Prometheus: http://localhost:9090
# - Grafana: http://localhost:3000 (admin/admin)
# - Jaeger UI: http://localhost:16686
```

### Kubernetes (Production)

```bash
# From the deployment/examples directory

# 1. Create namespace (optional)
kubectl create namespace production

# 2. Apply ConfigMap
kubectl apply -f kubernetes/configmap.yaml

# 3. Apply Deployment
kubectl apply -f kubernetes/deployment.yaml

# 4. Apply Service
kubectl apply -f kubernetes/service.yaml

# 5. Apply HorizontalPodAutoscaler
kubectl apply -f kubernetes/hpa.yaml

# 6. Verify deployment
kubectl get pods -n default
kubectl get svc -n default

# 7. Check logs
kubectl logs -f deployment/quill-service -n default
```

## Docker

### Building the Image

```bash
# From the repository root
docker build -f deployment/examples/docker/Dockerfile -t quill-service:latest .
```

### Running Standalone

```bash
docker run -d \
  --name quill-service \
  -p 8080:8080 \
  -e RUST_LOG=info \
  -e QUILL_HTTP_VERSION=http2 \
  quill-service:latest
```

### Multi-Stage Build Benefits

- **Small image size**: ~50MB runtime image vs ~2GB build image
- **Security**: No build tools in production image
- **Fast deployments**: Smaller images deploy faster
- **Layer caching**: Dependencies cached separately

## Kubernetes

### Configuration

Edit `kubernetes/configmap.yaml` to customize:

- HTTP version (http1, http2, auto)
- Connection limits
- Retry policy
- Circuit breaker settings
- Compression settings
- Logging levels

### Scaling

Manual scaling:
```bash
kubectl scale deployment quill-service --replicas=5
```

Automatic scaling with HPA:
```bash
kubectl get hpa quill-service
kubectl describe hpa quill-service
```

### Health Checks

The deployment includes three types of probes:

1. **Liveness Probe** (`/health`)
   - Checks if the process is alive
   - Failure triggers container restart

2. **Readiness Probe** (`/ready`)
   - Checks if ready to serve traffic
   - Failure removes pod from load balancer

3. **Startup Probe** (`/health`)
   - For slow-starting containers
   - Gives more time during initialization

### Security Features

The Kubernetes deployment includes:

- ✅ Non-root user (UID 1000)
- ✅ Read-only root filesystem
- ✅ Dropped capabilities (ALL)
- ✅ No privilege escalation
- ✅ Seccomp profile
- ✅ Resource limits
- ✅ Pod anti-affinity

### Updating the Deployment

Rolling update:
```bash
kubectl set image deployment/quill-service \
  quill-service=your-registry.example.com/quill-service:v1.1.0
```

Rollback:
```bash
kubectl rollout undo deployment/quill-service
```

Check status:
```bash
kubectl rollout status deployment/quill-service
```

## Monitoring

### Prometheus

The Prometheus configuration includes scrape targets for:

- Quill services (via annotations)
- Kubernetes nodes
- cAdvisor (container metrics)

Access Prometheus:
- Docker Compose: http://localhost:9090
- Kubernetes: Port-forward with `kubectl port-forward svc/prometheus 9090:9090`

### Key Metrics

Query examples:

```promql
# Request rate
rate(quill_requests_total[5m])

# Error rate
rate(quill_errors_total[5m]) / rate(quill_requests_total[5m])

# Response time p99
histogram_quantile(0.99, rate(quill_request_duration_seconds_bucket[5m]))

# Active connections
quill_active_connections

# Circuit breaker state
quill_circuit_breaker_state
```

### Grafana

Import the Quill dashboard:

1. Access Grafana (http://localhost:3000)
2. Add Prometheus datasource
3. Import dashboard from `monitoring/grafana/dashboards/quill-overview.json`

## Best Practices

### Resource Requests and Limits

Start with these values and adjust based on monitoring:

| Traffic Level | CPU Request | CPU Limit | Memory Request | Memory Limit |
|---------------|-------------|-----------|----------------|--------------|
| Low           | 100m        | 500m      | 128Mi          | 256Mi        |
| Medium        | 250m        | 1000m     | 256Mi          | 512Mi        |
| High          | 500m        | 2000m     | 512Mi          | 1Gi          |

### Number of Replicas

- **Minimum**: 3 (for high availability)
- **Production**: 5-10 (depends on traffic)
- **High traffic**: 10-50+ (with HPA)

### Connection Pooling

Configure based on your load:

```yaml
# Low traffic
max_connections: 100
pool_max_idle_per_host: 10

# Medium traffic
max_connections: 1000
pool_max_idle_per_host: 32

# High traffic
max_connections: 5000
pool_max_idle_per_host: 64
```

### Circuit Breaker Tuning

```yaml
# Conservative (fail slowly)
failure_threshold: 10
timeout: 120s

# Aggressive (fail fast)
failure_threshold: 3
timeout: 30s
```

## Troubleshooting

### Container Won't Start

Check logs:
```bash
# Docker
docker logs quill-service

# Kubernetes
kubectl logs -f deployment/quill-service
```

Common issues:
- Port already in use
- Missing configuration
- Invalid environment variables

### Liveness Probe Failing

```bash
# Test health endpoint manually
kubectl exec -it <pod-name> -- curl http://localhost:8080/health

# Check probe configuration
kubectl describe pod <pod-name>
```

### High Memory Usage

```bash
# Check current usage
kubectl top pods

# Increase memory limit in deployment.yaml
resources:
  limits:
    memory: 1Gi  # Increase from 512Mi
```

### Slow Response Times

1. Check HTTP version:
   ```bash
   kubectl logs deployment/quill-service | grep "HTTP version"
   ```

2. Enable compression:
   ```yaml
   compression:
     enabled: true
     threshold_bytes: 1024
   ```

3. Increase connection pool:
   ```yaml
   max_connections: 2000
   pool_max_idle_per_host: 64
   ```

### Pods Not Scaling

Check HPA status:
```bash
kubectl get hpa quill-service
kubectl describe hpa quill-service
```

Ensure metrics-server is installed:
```bash
kubectl get deployment metrics-server -n kube-system
```

## Next Steps

- Review [Deployment Guide](../../docs/deployment.md) for detailed information
- Check [HTTP/2 Configuration](../../docs/http2.md) for performance tuning
- Read [Resilience Guide](../../docs/resilience.md) for retry and circuit breaker setup
- See [Monitoring Guide](../../docs/deployment.md#monitoring--observability) for observability setup

## Support

For issues or questions:
- GitHub Issues: https://github.com/your-org/quill/issues
- Documentation: https://your-org.github.io/quill/
