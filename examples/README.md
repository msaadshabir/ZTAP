# Examples

Sample ZTAP policies and programs demonstrating zero-trust scenarios and cluster features.

## Programs

### etcd_election

Distributed leader election using etcd backend.

```bash
# Terminal 1
go run ./examples/etcd_election node1

# Terminal 2
go run ./examples/etcd_election node2
```

See [etcd Setup](../docs/etcd.md) for prerequisites.

### policy_sync

Distributed policy synchronization across a 3-node cluster.

```bash
go run ./examples/policy_sync
```

Once a policy is synced, you can view revisions or roll back:

```bash
ztap policy history web-to-db
ztap policy rollback web-to-db --to 1 --reason "back to known-good"
```

See [Cluster Documentation](../docs/CLUSTER.md) for details.

## Policy Examples

Note: on Linux, the eBPF enforcer currently supports IPv4 `ipBlock` rules with `/32` CIDRs and TCP/UDP only.
Policies that use non-/32 CIDRs will be rejected by the eBPF enforcer. See `docs/EBPF.md`.
Policies that use `podSelector` targets can be enforced by resolving selectors into `/32` `ipBlock` rules first (in-cluster via `ztap agent`, or locally via `ztap enforce --resolve-labels` with `discovery.backend: k8s`).
Cloud sync backends may still translate selectors (for example, `ztap gcp firewall-sync` resolves `podSelector.matchLabels` via GCE instance labels).

Kubernetes multi-namespace agent mode:

- Watch an allow-list: `ztap agent --namespaces ns-a,ns-b`
- Watch all namespaces: `ztap agent --all-namespaces`
- Tenant isolation requires Linux eBPF (iptables fallback can't guarantee isolation)

### web-to-db.yaml

Three-tier application: web to API, IoT to internet.

```bash
# Validate the policy offline
ztap policy validate -f web-to-db.yaml

# Enforce locally
ztap enforce -f web-to-db.yaml
```

### lateral-movement.yaml

Prevent lateral movement in compromised environments.

### pci-compliant.yaml

PCI-DSS compliant payment processor (HTTPS only, internal network).

Compliance exports:

```bash
ztap compliance export -f pci-compliant.yaml --format json
ztap compliance export -f pci-compliant.yaml --format csv --out pci.csv
ztap compliance report -f pci-compliant.yaml --format md
```

### deny-all.yaml

Deny-by-default with explicit DNS allowed.

### microservices.yaml

Zero-trust microservices (auth to MongoDB/Redis, monitoring to internal).

### bidirectional.yaml

Bidirectional enforcement with both ingress and egress rules for web tier applications.

```bash
ztap enforce -f bidirectional.yaml
```

### ingress-only.yaml

Ingress-only policies for protecting backend services (databases, caches, SSH bastions).

```bash
ztap enforce -f ingress-only.yaml
```

## Policy Patterns

### Label-Based Rules

Note: the Linux eBPF enforcer requires concrete `/32` IPv4 `ipBlock` rules.
`podSelector.matchLabels` targets can be translated to `/32` rules via Kubernetes discovery (recommended: `ztap agent`), or via `ztap enforce --resolve-labels` when `discovery.backend: k8s` is configured.
For GCP firewall sync, `podSelector.matchLabels` is resolved against GCE instance labels within the specified VPC network.

```yaml
egress:
  - to:
      podSelector:
        matchLabels:
          app: database
```

### IP-Based Rules

```yaml
egress:
  - to:
      ipBlock:
        cidr: 10.0.0.0/8
```

### Ingress Rules (Inbound)

```yaml
ingress:
  - from:
      ipBlock:
        cidr: 192.168.0.0/16
    ports:
      - protocol: TCP
        port: 8080
```

### Ingress with Pod Selector

```yaml
ingress:
  - from:
      podSelector:
        matchLabels:
          app: web
    ports:
      - protocol: TCP
        port: 5432
```

### Port Restrictions

```yaml
ports:
  - protocol: TCP
    port: 443
```

## Creating Custom Policies

```yaml
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: your-policy-name
spec:
  podSelector:
    matchLabels:
      app: your-app
  egress:
    - to:
        podSelector:
          matchLabels:
            app: target-app
      ports:
        - protocol: TCP
          port: 443
  ingress:
    - from:
        ipBlock:
          cidr: 10.0.0.0/24
      ports:
        - protocol: TCP
          port: 8080
```

### Best Practices

1. Start restrictive (deny-all, add explicit allows)
2. Use labels over IPs (more maintainable)
3. Test incrementally

## Related Documentation

- [Architecture](../docs/architecture.md)
- [Setup Guide](../docs/setup.md)
- [Testing](../docs/TESTING.md)
