# Security Audit & Checks

This project has both **local privileged operations** (eBPF/pf enforcement) and **network-facing APIs** (REST + gRPC). The goal of this document is to make security review repeatable and to record the current hardening decisions.

## Quick Run (Local)

```bash
scripts/security_check.sh
```

What it runs:

- `go test ./...`
- `go vet ./...`
- `govulncheck ./...`
- `gosec` (with `G304` excluded)

### Why `G304` is excluded

`G304` flags reading files from a variable path (possible traversal). In ZTAP:

- Some reads are **intentionally operator-specified** (policy YAML, config files). That’s core CLI behavior.
- Some reads are **local app state** (tokens, logs) under `~/.ztap/`.

We still treat file-path handling as a review item (see “File IO checklist” below), but we don’t fail CI on `G304` by default.

## Deployment Modes

### Mode A: Dev laptop (localhost-only)

- Acceptable: cleartext HTTP/gRPC on loopback.
- Required:
  - Bind REST/gRPC/metrics to loopback.
  - No secrets in logs.
  - Local files under `~/.ztap/` must be user-private.

### Mode B: Single-node server daemon

- Required:
  - Auth enabled.
  - Encrypted transport if any listener is reachable off-host.
  - Metrics and flow streams treated as sensitive telemetry.
  - Tight file permissions for logs/audit/token/state.

### Mode C: Multi-node cluster (etcd)

- Required:
  - TLS/mTLS for etcd and API transport.
  - Strong node identity and least-privilege access to policy distribution.
  - Treat policy injection into etcd as “cluster takeover” severity.

## Review Checklists

### Auth / Secrets

- Verify no passwords/tokens are printed in logs.
- Verify `/metrics` exposure matches intended mode (localhost vs authenticated).
- Verify auth gates cover:
  - Enforcement start/stop
  - Flow streaming (SSE + gRPC)
  - Status endpoints

### HTTP/gRPC Hardening

- Confirm HTTP server timeouts are set (`ReadHeaderTimeout`, `ReadTimeout`, `WriteTimeout`, `IdleTimeout`).
- Confirm request-body size limits exist where needed (login, policy apply, etc.)

### File IO

- For operator-specified paths: verify the code treats these as trusted operator inputs and doesn’t combine them with privileged writes.
- For app state under `~/.ztap/`: verify `0700` dirs and `0600` files.
- For privileged system paths (pf.conf, bpffs pinning): verify safe permissions and no symlink surprises.

### Enforcement

- Linux eBPF:
  - Verify fail-fast behavior when policy is unsupported (avoid partial enforcement).
  - Verify pinned map ownership/permissions.
- macOS pf:
  - Verify anchor file permissions and pf.conf modifications are safe.

### Cluster / etcd

- Ensure etcd client requires TLS in cluster deployments.
- Ensure leader election and policy updates are authenticated and authorized.

## Known High-Risk Areas (Keep Watching)

- Any endpoint that can trigger enforcement while the daemon runs privileged.
- Metrics/flow streams accidentally bound to non-loopback.
- Logging of credentials or bootstrap secrets.
