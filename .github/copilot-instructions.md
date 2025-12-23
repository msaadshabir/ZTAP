# ZTAP AI Instructions

## Project Overview

ZTAP (Zero Trust Access Platform) is a Go 1.24+ CLI for zero-trust microsegmentation. It enforces network policies at the kernel level using eBPF (Linux) or pf (macOS), with distributed coordination via etcd.

## Architecture

```
CLI (cmd/) / API Server (pkg/apihttp) -> Policy Engine (pkg/policy) -> Enforcer (pkg/enforcer)
                                                           -> Flow Monitor (pkg/flow)
                                                           -> Alerting (pkg/alert)
                                                           -> Cloud Sync (pkg/cloud)
                                                           -> Cluster Sync (pkg/cluster)
```

- **Policy Engine**: Parses Kubernetes-style YAML (`apiVersion: ztap/v1`), validates CIDR/ports/protocols, resolves labels via `ServiceDiscovery` interface
- **API Server**: Minimal REST server (`ztap api serve`) and minimal gRPC server (`ztap grpc serve`) exposing auth/status/enforcement/flows (metrics remains HTTP)
- **Enforcer**: Platform-specific - Linux eBPF (`ebpf_linux.go`) and macOS pf (`enforcer.go`)
- **Flow Monitor**: `pkg/flow/` provides the monitor + readers; on Linux, `ztap flows --follow` streams real events when `ztap enforce` is active (via the pinned `flow_events` map)
- **Alerting**: `pkg/alert/` provides webhook sinks (Slack, PagerDuty) and async dispatch with optional TTL dedupe (configured via `alerting.*`)
- **Cluster**: Leader election + policy sync - `election_memory.go` (dev), `election_etcd.go` (production)
- **Discovery**: Label-to-IP resolution - `InMemoryDiscovery` (dev), DNS/Consul/K8s backends (stubs)

## Key Interfaces

```go
// pkg/policy/policy.go - All discovery backends implement this
type ServiceDiscovery interface {
    ResolveLabels(labels map[string]string) ([]string, error)
}

// pkg/cluster/types.go - Leader election backends
type LeaderElection interface {
    Start(ctx context.Context) error
    IsLeader() bool
    GetLeader() *Node
}

// pkg/cluster/types.go - Policy distribution
type PolicySync interface {
    SyncPolicy(ctx context.Context, policyName string, policyYAML []byte) error
    SubscribePolicies(ctx context.Context) <-chan PolicyUpdate
}

// pkg/flow/types.go - Flow event monitoring
type FlowMonitor interface {
    Start(ctx context.Context) error
    Stop() error
    Subscribe(ctx context.Context) <-chan FlowEvent
    GetStats() FlowStats
    IsRunning() bool
}
```

## Platform-Specific Code

- Linux eBPF: `pkg/enforcer/ebpf_linux.go` with `//go:build linux` tag
- macOS pf: Falls back to `EnforceWithPF()` in `pkg/enforcer/enforcer.go`
- eBPF requires: compiled `bpf/filter.o`, root/CAP_BPF, kernel 5.7+
- Linux `ztap enforce` keeps running while enforcement is active; Ctrl+C detaches and exits
- CLI flags for Linux enforcement: `--cgroup`, `--bpf-object`, `--debug-ebpf` (and env vars `ZTAP_BPF_OBJECT`, `ZTAP_DEBUG_EBPF`)

## API Server Notes

- Command: `ztap api serve` (implemented in `cmd/api.go` and `pkg/apihttp/`)
- Command: `ztap grpc serve` (implemented in `cmd/grpc.go` and `pkg/apigrpc/`)
- Auth: bearer tokens via `Authorization: Bearer <token>`; sessions are currently in-memory (non-persistent across restarts)
- Flow streaming: `GET /v1/flows/stream` uses SSE; on Linux it will read the pinned eBPF map when available, otherwise it falls back to simulated events
- Flow streaming (gRPC): `ztap.api.v1.FlowsService/Stream` is server-streaming; send `authorization: Bearer <token>` via gRPC metadata
- Metrics: `GET /metrics` is served via promhttp; avoid registering Prometheus collectors in constructors (global registry)

## Alerting Notes

- CLI: `ztap alert test` sends a test alert using configured sinks
- Config: `alerting.enabled`, `alerting.slack.webhook_url`, `alerting.pagerduty.routing_key`, `alerting.pagerduty.source`, plus queue/timeout/dedupe settings (see `config.yaml.example`)
- Env overrides (recommended for secrets): `ZTAP_ALERT_SLACK_WEBHOOK_URL`, `ZTAP_ALERT_PAGERDUTY_ROUTING_KEY`, `ZTAP_ALERT_PAGERDUTY_SOURCE`, `ZTAP_ALERT_ENABLED`
- Secrets: treat webhook URLs and routing keys as secrets; never log them

## Testing Patterns

```bash
# Unit tests (always run)
go test ./...

# eBPF integration (Linux + root only)
sudo go test -tags integration ./pkg/enforcer -run TestEBPFIntegration -v

# Race detection
go test ./... -race
```

Tests use:

- `t.TempDir()` for file isolation
- Table-driven tests with descriptive names (see `pkg/policy/policy_test.go`)
- Mock implementations: `mockDiscovery`, `InMemoryElection`, `InMemoryPolicySync`

## Error Handling

```go
// Wrap errors with context
return fmt.Errorf("loading policy %s: %w", name, err)

// Custom validation errors (pkg/policy/policy.go)
type ValidationError struct {
    PolicyName string
    Field      string
    Message    string
}
```

## Audit Logging

`pkg/audit/audit.go` uses SHA-256 hash chaining for tamper detection:

```go
auditLogger.Log(audit.EventPolicyEnforced, "system", policyName, "enforce", details)
auditLogger.VerifyIntegrity() // Detects tampering
```

## Policy YAML Format

The policy engine supports Kubernetes-style constructs (selectors, CIDRs, TCP/UDP/ICMP), but the Linux eBPF enforcer is currently more limited and will fail fast to avoid partial enforcement.

```yaml
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: web-to-db # DNS-1123 format: lowercase, hyphens only
spec:
  podSelector:
    matchLabels:
      app: web
  egress:
    - to:
        ipBlock:
          cidr: 10.0.0.0/8 # OR podSelector, not both
      ports:
        - protocol: TCP # TCP, UDP, or ICMP
          port: 5432 # 1-65535
  ingress: # Optional, same structure as egress
```

Current Linux eBPF enforcement constraints:

- Only IPv4 `ipBlock` rules with `/32` CIDRs
- TCP/UDP only (ICMP is rejected)
- `podSelector` targets are not supported yet

## Code Standards

- Lowercase error messages without trailing punctuation
- `context.Context` as first parameter for cancellable operations
- Never log credentials or secrets
- Validate all external inputs (CIDR, ports, file paths)

## Development Commands

```bash
go build                  # Build CLI
cd bpf && make           # Compile eBPF (Linux only)
./demo.sh                # Interactive demo
docker-compose up -d     # Prometheus + Grafana stack

# REST API server
ztap api serve

# gRPC API server
ztap grpc serve
```

## Output Rules

- No emojis in code, comments, or docs
- State assumptions explicitly
- Provide complete code with imports

# Remove AI code slop

Check the diff against main, and remove all AI generated slop introduced in this branch.

This includes:

- Extra comments that a human wouldn't add or is inconsistent with the rest of the file
- Extra defensive checks or try/catch blocks that are abnormal for that area of the codebase (especially if called by trusted / validated codepaths)
- Casts to any to get around type issues
- Any other style that is inconsistent with the file

Report at the end with only a 1-3 sentence summary of what you changed
