# ZTAP Setup Guide

## Prerequisites

### System Requirements

- **Operating System**: macOS 12+ or Linux (kernel ≥5.7 for eBPF)
- **Go**: 1.25.2 or later
- **Memory**: 2 GB RAM minimum
- **Disk**: 200 MB for binary, policies, and logs

### Optional Components

- **AWS Account**: For cloud integration and Security Group sync
- **Docker**: For full stack deployment (Prometheus + Grafana + Anomaly Detector)
- **Python 3.11+**: For anomaly detection service development

## Installation

### Method 1: Build from Source

```bash
# Clone repository
git clone https://github.com/saad-build/ZTAP.git
cd ZTAP

# Install dependencies
go mod download

# Build binary
go build -o ztap

# Install (optional)
sudo mv ztap /usr/local/bin/
```

### Method 2: Using Docker (Recommended for Production)

```bash
# Clone repository
git clone https://github.com/saad-build/ZTAP.git
cd ZTAP

# Start full stack with Docker Compose
docker-compose up -d

# Access services:
# - ZTAP metrics: http://localhost:9090/metrics
# - Prometheus: http://localhost:9091
# - Grafana: http://localhost:3000 (admin/ztap)
# - Anomaly Detector: http://localhost:5000
```

See [DOCKER.md](../DOCKER.md) for detailed Docker deployment.

## Configuration

### 1. Basic Setup

```bash
# Verify installation
ztap --help

# Check system status
ztap status
```

### 2. macOS-Specific Setup

ZTAP uses pf (packet filter) on macOS, which requires sudo:

```bash
# Check if pf is enabled
sudo pfctl -s info

# Enable pf (if disabled)
sudo pfctl -e

# Note: ZTAP will prompt for sudo when enforcing policies
```

### 3. Linux-Specific Setup

ZTAP uses eBPF on Linux for kernel-level enforcement:

```bash
# Check kernel version (must be ≥5.7 for cgroup v2)
uname -r

# Verify eBPF support
ls /sys/fs/bpf/

# Install eBPF build dependencies
sudo apt-get install clang llvm make linux-headers-$(uname -r)

# Compile eBPF programs
cd bpf && make
```

See [eBPF Setup Guide](EBPF.md) for detailed Linux configuration.

### 4. AWS Integration (Optional)

```bash
# Configure AWS credentials
aws configure

# Or set environment variables
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
export AWS_REGION="us-east-1"

# Test AWS connectivity
ztap status --aws --region us-east-1
```

## Quick Start

### 1. Enforce a Policy

```bash
# Use example policy
ztap enforce -f examples/web-to-db.yaml

# Output:
# Loaded 2 policy(ies) from examples/web-to-db.yaml
# Enforcing via pf (macOS)...
# Applying 2 pf-based policies on macOS
# Enforcement complete.
```

### 2. View Logs

```bash
# View all logs
ztap logs

# Filter by policy
ztap logs --policy web-to-db

# Follow logs in real-time
ztap logs --follow
```

### 3. Check Status

```bash
# Local system only
ztap status

# Include AWS resources
ztap status --aws --region us-east-1
```

### 4. Start Metrics Server

```bash
# Start Prometheus exporter
ztap metrics --port 9090

# In another terminal, query metrics
curl http://localhost:9090/metrics
```

## Running Observability Stack

### Start Prometheus and Grafana

```bash
cd deployments
docker-compose up -d

# Access Grafana at http://localhost:3000
# Username: admin
# Password: ztap
```

### Import Dashboard

The dashboard is automatically provisioned at `/etc/grafana/provisioning/dashboards/ztap.json`

Or manually import:

1. Open Grafana (http://localhost:3000)
2. Go to Dashboards > Import
3. Upload `deployments/grafana-dashboard.json`

## Running Anomaly Detection Service

```bash
# Install Python dependencies
cd pkg/anomaly
pip3 install flask scikit-learn numpy

# Start service
python3 service.py

# In another terminal, test it
curl -X POST http://localhost:5000/detect \
  -H "Content-Type: application/json" \
  -d '{"source_ip":"10.0.0.1","dest_ip":"192.168.1.100","port":22,"protocol":"TCP","bytes":5000000,"timestamp":"2025-10-09T03:00:00"}'
```

## Troubleshooting

### Issue: "Permission denied" when enforcing policies

**Solution**: ZTAP needs sudo to modify pf rules on macOS

```bash
# Run with sudo
sudo ztap enforce -f policy.yaml
```

### Issue: "No AWS resources found"

**Solution**: Check credentials and region

```bash
# Verify credentials
aws sts get-caller-identity

# Try different region
ztap status --aws --region us-west-2
```

### Issue: "Failed to load policy"

**Solution**: Validate YAML syntax

```bash
# Check for YAML errors
cat policy.yaml | python3 -m yaml
```

### Issue: Metrics server won't start

**Solution**: Port may be in use

```bash
# Check if port is in use
lsof -i :9090

# Use different port
ztap metrics --port 9091
```

## Next Steps

- Read [Architecture](architecture.md) to understand internals
- Check [examples/](../examples/) for sample policies
- See [evaluation.md](evaluation.md) for testing scenarios
