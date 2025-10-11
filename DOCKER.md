# ZTAP Docker Deployment

This directory contains Docker and Docker Compose configurations for running ZTAP in containerized environments.

## Quick Start

### Using Docker Compose (Recommended)

Run the complete ZTAP stack with Prometheus, Grafana, and Anomaly Detection:

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop all services
docker-compose down

# Stop and remove volumes
docker-compose down -v
```

### Using Docker Build Directly

Build and run ZTAP container standalone:

```bash
# Build the image
docker build -t ztap:latest .

# Run the container
docker run -d \
  --name ztap \
  --privileged \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_ADMIN \
  --cap-add=BPF \
  -p 9090:9090 \
  -v $(pwd)/examples:/etc/ztap/examples:ro \
  ztap:latest metrics --port 9090
```

## Services

The Docker Compose stack includes:

### ZTAP Core (`ztap`)

- **Port**: 9090 (metrics)
- **Capabilities**: Requires privileged mode for eBPF on Linux
- **Volumes**: Policy examples, logs, and data
- **Command**: Runs metrics server by default

### Prometheus (`prometheus`)

- **Port**: 9091 (web UI)
- **Purpose**: Metrics collection and storage
- **Configuration**: `deployments/prometheus.yml`
- **Retention**: 30 days

### Grafana (`grafana`)

- **Port**: 3000 (web UI)
- **Credentials**: admin / ztap
- **Dashboards**: Pre-configured ZTAP dashboards
- **Configuration**: `deployments/grafana/`

### Anomaly Detector (`anomaly-detector`)

- **Port**: 5000 (API)
- **Purpose**: ML-based traffic anomaly detection
- **Technology**: Python + Flask + scikit-learn
- **Health Check**: `/health` endpoint

## Architecture

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│    ZTAP     │ ──────> │  Prometheus  │ ──────> │   Grafana   │
│  (Metrics)  │  :9090  │   (Storage)  │  :9091  │    (UI)     │
└─────────────┘         └──────────────┘         └─────────────┘
       │                                                 │
       │                                                 │
       v                                                 v
┌─────────────┐                                   Port: 3000
│  Anomaly    │                                   User: admin
│  Detector   │                                   Pass: ztap
│  (ML API)   │
└─────────────┘
   Port: 5000
```

## Configuration

### Environment Variables

Configure ZTAP via environment variables in `docker-compose.yml`:

```yaml
environment:
  - ZTAP_LOG_LEVEL=info
  - ZTAP_METRICS_PORT=9090
  - ZTAP_AUTH_DB=/var/lib/ztap/auth.db
```

### Volumes

Persistent data is stored in Docker volumes:

- `ztap-data`: Policy state and authentication database
- `ztap-logs`: Enforcement logs
- `prometheus-data`: Metrics time-series data
- `grafana-data`: Dashboards and configuration
- `anomaly-data`: ML training data
- `anomaly-models`: Saved ML models

### Network

All services run on a custom bridge network (`ztap-net`) with subnet `172.20.0.0/16`.

## Requirements

### System Requirements

- **Docker**: 20.10+
- **Docker Compose**: 2.0+
- **OS**: Linux (for eBPF), macOS (development)
- **Memory**: 2GB+ recommended
- **Disk**: 10GB+ for logs and metrics

### Linux-Specific Requirements

For eBPF enforcement on Linux:

- Kernel 5.7+ (for BTF and CO-RE support)
- Privileged container or specific capabilities:
  - `CAP_NET_ADMIN`
  - `CAP_SYS_ADMIN`
  - `CAP_BPF`
- Access to `/sys/fs/cgroup` for cgroup attachment

## Usage Examples

### Apply a Policy

```bash
# Copy policy to container
docker cp examples/web-to-db.yaml ztap:/tmp/

# Enforce the policy
docker exec ztap ztap enforce -f /tmp/web-to-db.yaml
```

### View Status

```bash
docker exec ztap ztap status
```

### Access Grafana Dashboard

1. Navigate to http://localhost:3000
2. Login with `admin` / `ztap`
3. Browse pre-configured ZTAP dashboards

### Train Anomaly Detector

```bash
# Send training data
curl -X POST http://localhost:5000/train \
  -H "Content-Type: application/json" \
  -d '{
    "flows": [
      {
        "source_ip": "192.168.1.10",
        "dest_ip": "10.0.0.1",
        "protocol": "TCP",
        "port": 443,
        "bytes": 1024,
        "timestamp": "2025-01-01T12:00:00"
      }
    ]
  }'
```

### Check Anomaly Detector Health

```bash
curl http://localhost:5000/health
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose logs ztap

# Verify privileged mode (Linux only)
docker inspect ztap | grep Privileged
```

### eBPF Errors on Linux

If you see eBPF-related errors:

1. Verify kernel version: `uname -r` (should be 5.7+)
2. Check kernel headers: `ls /usr/src/linux-headers-$(uname -r)`
3. Ensure privileged mode or capabilities are granted
4. Check cgroup v2 support: `ls /sys/fs/cgroup/cgroup.controllers`

### Permission Denied

If you encounter permission issues:

```bash
# Run with elevated privileges
sudo docker-compose up -d

# Or add user to docker group
sudo usermod -aG docker $USER
# Log out and back in
```

### Metrics Not Appearing in Grafana

1. Check Prometheus is scraping: http://localhost:9091/targets
2. Verify ZTAP metrics endpoint: http://localhost:9090/metrics
3. Check Grafana datasource configuration

### Anomaly Detector Not Training

1. Verify Python dependencies are installed
2. Check for sufficient training data (minimum 10 samples)
3. Review logs: `docker-compose logs anomaly-detector`

## Development

### Rebuild After Code Changes

```bash
# Rebuild specific service
docker-compose build ztap

# Rebuild and restart
docker-compose up -d --build ztap
```

### Run Tests in Container

```bash
# Go tests
docker-compose run --rm ztap go test ./... -v

# Python tests
docker-compose run --rm anomaly-detector python -m pytest test_service.py -v
```

### Debug Mode

```bash
# Run with debug logging
docker-compose run --rm ztap ztap --debug status

# Interactive shell
docker-compose run --rm ztap sh
```

## Production Considerations

### Security

- **Change default passwords**: Update Grafana admin password
- **Use secrets**: Store sensitive config in Docker secrets
- **Network isolation**: Use custom networks with restricted access
- **Read-only volumes**: Mount config files as read-only

### Performance

- **Resource limits**: Set CPU and memory limits in `docker-compose.yml`
- **Volume drivers**: Use optimized volume drivers for production
- **Log rotation**: Configure log rotation to prevent disk fill

### Monitoring

- **Health checks**: All services include health checks
- **Restart policy**: Configured to restart unless stopped
- **Backup**: Regularly backup volumes (especially `prometheus-data` and `grafana-data`)

### Scaling

For production deployments:

1. Use container orchestration (Kubernetes, Docker Swarm)
2. Separate ZTAP agents across multiple nodes
3. Use external Prometheus and Grafana instances
4. Scale anomaly detector horizontally behind a load balancer

## Multi-Platform Support

### Linux (Production)

Full eBPF enforcement supported:

```bash
docker-compose up -d
```

### macOS (Development)

Limited to pf (packet filter):

```bash
# Use without privileged mode
docker-compose -f docker-compose.yml -f docker-compose.mac.yml up -d
```

Create `docker-compose.mac.yml`:

```yaml
version: "3.8"
services:
  ztap:
    privileged: false
    cap_drop:
      - ALL
```

### Windows

Not officially supported for eBPF. Use WSL2 with Linux kernel.

## Further Reading

- [ZTAP Documentation](../docs/)
- [eBPF Setup Guide](../docs/EBPF.md)
- [Testing Guide](../docs/TESTING_GUIDE.md)
- [Architecture Overview](../docs/architecture.md)
