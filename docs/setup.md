# ZTAP Setup Guide

## Prerequisites

### System Requirements

- **Operating System**: macOS 12+, Linux (eBPF requires kernel ≥5.7; automatically falls back to iptables on older kernels), or Windows (WFP)
- **Go**: 1.24 or later
- **Memory**: 2 GB RAM minimum
- **Disk**: 200 MB for binary, policies, and logs
- **Note on eBPF**: Production binaries include pre-compiled bytecode. Runtime dependencies like `clang` or `llvm` are **not** required for enforcement.

### Optional Components (Development)

- **Clang/LLVM**: Required only if you plan to modify and recompile the eBPF source code (`bpf/filter.c`).
- **AWS Account**: For cloud integration and Security Group sync
- **Azure Subscription**: For cloud integration and NSG sync
- **Docker**: For full stack deployment (Prometheus + Grafana + Anomaly Detector)
- **Python 3.11+**: For anomaly detection service development
- **Kubernetes Cluster**: For the Kubernetes operator + node agent workflow (Linux nodes)

## Installation

### Method 1: Build from Source

```bash
# Clone repository
git clone https://github.com/msaadshabir/ZTAP.git
cd ZTAP

# Install dependencies
go mod download

# Build binary
go build -o ztap

# Build operator binary
go build -o ztap-operator ./cmd/ztap-operator

# Install (optional)
sudo mv ztap /usr/local/bin/
```

### Method 2: Using Docker (Recommended for Production)

```bash
# Clone repository
git clone https://github.com/msaadshabir/ZTAP.git
cd ZTAP

# Start full stack with Docker Compose
docker compose up -d

# Access services:
# - ZTAP metrics: http://localhost:9090/metrics
# - Prometheus: http://localhost:9091
# - Grafana: http://localhost:3000 (admin/ztap)
# - Anomaly Detector: http://localhost:5000
```

See [Deployment Guide](deployment.md) for detailed Docker deployment.

## Kubernetes (Operator + Agent)

ZTAP includes a Kubernetes operator and an in-cluster node agent path that publishes policies from a CRD and enforces them on nodes.

Install the operator + agent bundle:

```bash
# Build images (operator + agent)
docker build -t ztap:latest .
docker build -f Dockerfile.operator -t ztap-operator:latest .

# Push to your registry (or load into your local cluster)
docker push ztap:latest
docker push ztap-operator:latest

# Apply the full bundle (Namespace + CRD + Operator + Agent)
kubectl apply -f deployments/kubernetes/ztap-install.yaml
```

Install the CRD and operator separately (dev-only):

```bash
# Build an operator image
docker build -f Dockerfile.operator -t ztap-operator:latest .

# Apply the CRD and operator deployment
kubectl apply -f deployments/kubernetes/ztapnetworkpolicy-crd.yaml
kubectl apply -f deployments/kubernetes/ztap-operator.yaml
```

- Entry points:
  - Operator binary: `ztap-operator`
  - Agent command: `ztap agent`

Pod IP auto-discovery:

- The agent resolves `podSelector` targets (matchLabels + matchExpressions), optionally scoped by `namespaceSelector`, to live Pod IPs via the Kubernetes API and translates them into host CIDRs (`/32` for IPv4, `/128` for IPv6) `ipBlock` rules for enforcement.
- For local development (out-of-cluster), `ztap enforce` resolves `podSelector` targets automatically when `discovery.backend: k8s` is configured (kubeconfig-based), and refreshes resolution while it is running.
  - Tune refresh with `--resolve-labels-interval` (default: `5s`; set to `0` to resolve once).
  - If a selector currently resolves to zero targets (e.g., rollouts/scale-to-zero), enforcement still starts; the rule is inactive until targets appear and resolution refreshes.

Named ports and port ranges:

- Port ranges are expressed with `endPort` (TCP/UDP only).
- Named ports are supported for selector-based rules.
  - Egress: resolved per destination pod.
  - Ingress: requires Linux subject-scoped enforcement (per-pod cgroup) to resolve named ports.

Minimal out-of-cluster discovery config:

```yaml
# config.yaml (or file set via ZTAP_CONFIG)
discovery:
  backend: k8s
  k8s:
    namespace: default
    # kubeconfig: /absolute/path/to/kubeconfig (optional; defaults to $KUBECONFIG or ~/.kube/config)
```

Multi-namespace / multi-tenant notes:

- In Kubernetes deployments, tenant == namespace.
- The agent can watch policies in one namespace, an allow-list, or all namespaces:
  - Single namespace: `ztap agent --namespace default` (or `ZTAP_NAMESPACE=default`)
  - Allow-list: `ztap agent --namespaces ns-a,ns-b`
  - All namespaces: `ztap agent --all-namespaces`
- Linux eBPF enforcement programs per-cgroup rules. In Kubernetes agent mode, ZTAP resolves selected pod cgroups and installs rules per selected cgroup.
- When running scoped (per-cgroup) enforcement, ZTAP uses Kubernetes NetworkPolicy-style semantics: pods not selected by any policy are not isolated.
- If eBPF is unavailable and the agent falls back to iptables, tenant isolation is not guaranteed.

## Configuration

### 1. Basic Setup

```bash
# Verify installation
ztap --help

# Check system status
ztap status
```

### 2. TLS Configuration (Recommended for Production)

ZTAP supports HTTPS for the REST API and TLS for the gRPC API. You can configure this via `config.yaml` or CLI flags.

### 3. API Rate Limiting (Optional)

Rate limiting is supported on both REST and gRPC endpoints to reduce abuse and accidental overload.

- Default: disabled
- REST behavior: returns HTTP `429` with `Retry-After` and JSON `{ "error": "rate_limited" }`
- gRPC behavior: returns `RESOURCE_EXHAUSTED` and includes `RetryInfo` (retry delay)

**Using `config.yaml`:**

```yaml
api:
  rate_limit:
    enabled: true
    trust_proxy_headers: false
    unauthenticated:
      rps: 5
      burst: 10
    per_ip:
      rps: 20
      burst: 40
    per_token:
      rps: 10
      burst: 20
    exempt_paths:
      - /healthz
      - /readyz
      - /metrics

grpc:
  rate_limit:
    enabled: true
    unauthenticated:
      rps: 5
      burst: 10
    per_ip:
      rps: 20
      burst: 40
    per_token:
      rps: 10
      burst: 20
    exempt_methods:
      - /grpc.health.v1.Health/*
      - /ztap.api.v1.AuthService/Login
```

**Using CLI flags:**

```bash
# REST (enable with defaults)
ztap api serve --rate-limit

# REST (tune)
ztap api serve --rate-limit \
  --rate-limit-per-ip-rps 20 --rate-limit-per-ip-burst 40 \
  --rate-limit-per-token-rps 10 --rate-limit-per-token-burst 20 \
  --rate-limit-unauth-rps 5 --rate-limit-unauth-burst 10

# gRPC (enable with defaults)
ztap grpc serve --rate-limit

# gRPC (tune)
ztap grpc serve --rate-limit \
  --rate-limit-per-ip-rps 20 --rate-limit-per-ip-burst 40 \
  --rate-limit-per-token-rps 10 --rate-limit-per-token-burst 20 \
  --rate-limit-unauth-rps 5 --rate-limit-unauth-burst 10
```

Notes:

- If auth is enabled, invalid/expired bearer tokens are treated as unauthenticated for rate limiting.
- REST probes (`/healthz`, `/readyz`) are always exempt from rate limiting (safe for kubelet probes), even if not listed in `api.rate_limit.exempt_paths`.
- gRPC health RPCs (`/grpc.health.v1.Health/Check`, `/grpc.health.v1.Health/Watch`) are always exempt from rate limiting, even if not listed in `grpc.rate_limit.exempt_methods`.

**Using `config.yaml`:**

```yaml
api:
  listen: 127.0.0.1:8080
  tls:
    enabled: true
    cert_file: "/path/to/server.crt"
    key_file: "/path/to/server.key"
    # Optional mTLS (client certificate auth)
    client_auth: true
    client_ca_file: "/path/to/client-ca.pem"

grpc:
  listen: 127.0.0.1:9092
  tls:
    enabled: true
    cert_file: "/path/to/grpc.crt"
    key_file: "/path/to/grpc.key"
    # Optional mTLS (client certificate auth)
    client_auth: true
    client_ca_file: "/path/to/client-ca.pem"
```

**Using CLI flags:**

```bash
# Start REST API with TLS
ztap api serve --tls --tls-cert /path/to/cert.crt --tls-key /path/to/key.key

# Start gRPC API with TLS
ztap grpc serve --tls --tls-cert /path/to/cert.crt --tls-key /path/to/key.key
```

### 3. macOS-Specific Setup

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
cd bpf && make && cd ..
```

See [eBPF Setup Guide](ebpf.md) for detailed Linux configuration.

### 4. Windows-Specific Setup

ZTAP uses Windows Filtering Platform (WFP) on Windows.

- Run `ztap enforce` from an elevated terminal (Administrator).
- Windows enforcement supports IPv4/IPv6 `ipBlock.cidr` (arbitrary CIDRs) and TCP/UDP/ICMP.
  - For `protocol: ICMP`, the policy `port` is accepted by validation but ignored during enforcement.
  - By default, WFP installs permit rules only. Optional strict default-deny can be enabled with `ZTAP_WFP_STRICT=1` (use with care).
- Flow monitoring on Windows uses WFP NetEvents and requires an elevated terminal. See `docs/runbooks/windows-flow-monitoring.md`.

### 5. AWS Integration (Optional)

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

### 6. Azure NSG Synchronization (Optional)

ZTAP can reconcile ZTAP NetworkPolicy objects into Azure NSG security rules.

Auth uses Azure Identity default credentials (the standard DefaultAzureCredential chain). Typical options:

```bash
# Use Azure CLI auth
az login

# Then sync rules into an NSG
ztap azure nsg-sync examples/web-to-db.yaml \
  --subscription-id <sub-id> \
  --resource-group <rg> \
  --nsg <nsg-name>
```

You can also configure defaults in config.yaml (or via ZTAP_CONFIG):

```yaml
azure:
  enabled: false
  subscription_id: "..."
  resource_group: "..."
  nsg: "..."
  rule_prefix: ztap-
  priority_base: 2000
```

Environment variable overrides:

- ZTAP_AZURE_SUBSCRIPTION_ID
- ZTAP_AZURE_RESOURCE_GROUP
- ZTAP_AZURE_NSG
- ZTAP_AZURE_RULE_PREFIX
- ZTAP_AZURE_PRIORITY_BASE

### 7. GCP Firewall Synchronization (Optional)

ZTAP can reconcile ZTAP NetworkPolicy objects into GCP VPC firewall rules using Application Default Credentials (ADC).

Common auth options:

```bash
gcloud auth application-default login
# or use a service account key
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
```

Required permissions (at minimum):

- List instances in the project (for `podSelector` resolution)
- List/create/update/delete VPC firewall rules in the target network

Sync rules into a network:

```bash
ztap gcp firewall-sync examples/web-to-db.yaml \
  --project-id <project> \
  --network <vpc-network>
```

Optional flags:

```bash
# Print planned changes but do not apply them
ztap gcp firewall-sync examples/web-to-db.yaml --dry-run \
  --project-id <project> \
  --network <vpc-network>

# Reconcile again when the policy file changes
ztap gcp firewall-sync examples/web-to-db.yaml --watch --watch-interval 2s \
  --project-id <project> \
  --network <vpc-network>
```

Selector-based rules:

- `podSelector` targets (matchLabels + matchExpressions) are resolved against GCE instance labels.
- Matching instances are discovered within the specified VPC network, and their NIC IPs are translated into single-host CIDRs (`/32` for IPv4, `/128` for IPv6) for use in firewall rules.

Config file (config.yaml or ZTAP_CONFIG):

```yaml
gcp:
  enabled: false
  project_id: "my-project"
  network: "default"
  rule_prefix: ztap-
  priority_base: 2000
```

Environment variable overrides:

- ZTAP_GCP_PROJECT_ID
- ZTAP_GCP_NETWORK
- ZTAP_GCP_RULE_PREFIX
- ZTAP_GCP_PRIORITY_BASE

## Quick Start

### 0. First Run: Admin Bootstrap

On first run, if no user database exists yet, ZTAP creates an `admin` user.

- If `ZTAP_BOOTSTRAP_ADMIN_PASSWORD` is set, that value is used as the initial password.
- Otherwise, ZTAP generates a random bootstrap password and writes it to `~/.ztap/bootstrap_admin_password.txt` (permissions `0600`).

Delete the bootstrap password file after you log in and rotate the password.

### 1. Enforce a Policy

```bash
# Verify policy safely (Dry Run)
ztap enforce -f examples/web-to-db.yaml --dry-run

# macOS (pf)
ztap enforce -f examples/web-to-db.yaml

# Output:
# Loaded 2 policy(ies) from examples/web-to-db.yaml
# Enforcing via pf (macOS)...
# Enforcement complete.

# Linux (eBPF)
# Note: this requires root and runs until Ctrl+C.
# Supports IPv4/IPv6 CIDRs and TCP/UDP/ICMP (ICMP ignores `port`).
sudo ztap enforce -f policy.yaml

# Output:
# Loaded N policy(ies) from policy.yaml
# Enforcing via eBPF (Linux)...
# Enforcement active. Press Ctrl+C to stop.
```

### 2. View Logs

```bash
# View all logs
ztap logs

# Only show warnings/errors
ztap logs --level warn

# Filter by policy
ztap logs --policy web-to-db

# Follow logs in real-time
ztap logs --follow
```

You can control log verbosity globally with:

```bash
ztap --log-level debug status

# Or via environment variables
export ZTAP_LOG_LEVEL=debug
export ZTAP_LOG_FORMAT=json
export ZTAP_LOG_FILE=~/.ztap/ztap.log
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

Notes:

- By default, `ztap metrics` binds to `127.0.0.1:<port>`.
- To change the bind address (e.g., for containers), set `ZTAP_METRICS_LISTEN`, for example:

```bash
export ZTAP_METRICS_LISTEN="0.0.0.0:9090"
```

### 5. Start API Server

ZTAP includes a minimal REST API server.

```bash
# Starts HTTP server (defaults come from config.yaml.example)
ztap api serve

# Liveness check
curl -s http://127.0.0.1:8080/healthz

# Readiness check
curl -s http://127.0.0.1:8080/readyz
```

If API auth is enabled, `/metrics` on this server requires a valid bearer token with `view_metrics` permission.

Compliance endpoints:

- `POST /v1/compliance/report` (requires `view_compliance`)
- `POST /v1/compliance/export` (requires `view_compliance`)

Configuration:

````yaml
# config.yaml (or file set via ZTAP_CONFIG)
api:
  listen: 127.0.0.1:8080
  auth:
    enabled: true

### 6. Start gRPC API Server

ZTAP also includes a minimal gRPC API server.

Health checks:

- REST probes: `GET /healthz` (liveness) and `GET /readyz` (readiness)
- gRPC probe: standard `grpc.health.v1.Health` (`/grpc.health.v1.Health/Check`, `/grpc.health.v1.Health/Watch`)

```bash
# Starts gRPC server (defaults come from config.yaml.example)
ztap grpc serve
```

Configuration:

```yaml
# config.yaml (or file set via ZTAP_CONFIG)
grpc:
  listen: 127.0.0.1:9092
  auth:
    enabled: true
```

## Alerting (Slack, PagerDuty)

ZTAP can emit alerts (webhooks) on policy enforcement results from:

- `ztap api serve` (REST)
- `ztap grpc serve` (gRPC)
- cluster policy enforcement (PolicyEnforcer)

Configuration (in `config.yaml` or file set via `ZTAP_CONFIG`):

```yaml
alerting:
  enabled: true
  # async dispatch settings
  queue_size: 128
  workers: 2
  timeout: 5s
  dedupe_ttl: 5m
  slack:
    webhook_url: "https://hooks.slack.com/services/..."
  pagerduty:
    routing_key: "YOUR_ROUTING_KEY"
    source: ztap
```

Environment variable overrides (recommended for secrets):

```bash
export ZTAP_ALERT_SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."
export ZTAP_ALERT_PAGERDUTY_ROUTING_KEY="YOUR_ROUTING_KEY"
export ZTAP_ALERT_PAGERDUTY_SOURCE="ztap"
```

Send a test alert:

```bash
ztap alert test
```

## Running Observability Stack

### Start Prometheus and Grafana

```bash
docker compose up -d

# Access Grafana at http://localhost:3000
# Username: admin
# Password: ztap
```

### Import Dashboard

The dashboard is automatically provisioned at `/etc/grafana/provisioning/dashboards/ztap-dashboard.json`

Or manually import:

1. Open Grafana (http://localhost:3000)
2. Go to Dashboards > Import
3. Upload `deployments/grafana/dashboards/ztap-dashboard.json`

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
- See [Testing Guide](testing.md) for test scenarios
