# NetworkPolicy Parity Extension Plan

Status: Implemented
Owner: ZTAP Core
Date: 2026-01-30

## Summary

This document specifies how we will extend the ZTAP policy spec toward Kubernetes NetworkPolicy parity.
It covers spec changes, validation rules, selector resolution, enforcement updates, and the test plan.

## Goals

- Add `namespaceSelector`, `matchExpressions`, `ipBlock.except`, named ports, and port ranges.
- Preserve existing policies and behavior by keeping changes additive.
- Make selector and named-port resolution deterministic and safe (deny on ambiguity).

## Non-goals

- Full parity with all Kubernetes NetworkPolicy features (e.g., `policyTypes`).
- Cross-platform parity for every feature on day one (platform-specific constraints remain).

## Recommendation: Named Ports

Use strict per-destination resolution for named ports.

- Egress: resolve named ports against the selected destination pods and emit per-IP numeric ports.
- Ingress: require subject-scoped enforcement (per-pod cgroup on Linux) to resolve named ports.
  - If subject scoping is unavailable, treat named ports in ingress rules as a validation error.

Rationale: unioning ports across pods over-permits and deviates from Kubernetes semantics; strict resolution
keeps the default posture safe and predictable.

## Spec Changes

### LabelSelector

Add `matchExpressions` with Kubernetes-style operators.

```
matchExpressions:
  - key: app
    operator: In
    values: ["web", "api"]
  - key: tier
    operator: Exists
```

Supported operators: `In`, `NotIn`, `Exists`, `DoesNotExist`.

### NetworkPolicyPeer

Add namespace selection and allow combined pod+namespace selectors.

```
to:
  namespaceSelector: { matchLabels: { team: payments } }
  podSelector: { matchExpressions: [...] }
```

Rules:
- `ipBlock` is mutually exclusive with any selector.
- `namespaceSelector` alone is allowed (selects all pods in matching namespaces).
- `podSelector` alone selects pods in the policy namespace (current behavior).
- `podSelector` + `namespaceSelector` selects pods in matching namespaces.

### IPBlock

Add `except` to exclude CIDR subsets.

```
ipBlock:
  cidr: 10.0.0.0/8
  except:
    - 10.0.1.0/24
    - 10.0.2.0/24
```

### Ports

Support named ports and ranges.

```
ports:
  - protocol: TCP
    port: http
  - protocol: TCP
    port: 8000
    endPort: 8080
```

Rules:
- `port` may be an integer or a string name.
- `endPort` is only valid when `port` is an integer.
- Ranges only apply to TCP/UDP (not ICMP).

## Validation and Normalization

### Validation

- A selector is valid if either `matchLabels` or `matchExpressions` is present.
- `ipBlock.except` CIDRs must match the family of `ipBlock.cidr` and be subsets of it.
- Named ports must match `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`.
- `endPort` must be >= `port` and <= 65535.
- Disallow `endPort` with named ports or ICMP.

### Normalization Pipeline

1) Expand `ipBlock.except` into a bounded set of non-overlapping CIDRs.
2) Resolve selectors to concrete Pod IPs and convert to host CIDRs (/32 or /128).
3) Resolve named ports to numeric ports using pod specs.
4) Convert port ranges to an internal range representation (or expand when required by a backend).

Safeguards:
- Cap CIDR subtraction expansion (e.g., 1024 entries) and fail fast when exceeded.
- Cap port range expansion for backends that cannot express ranges.

## Selector Resolution and Discovery

### Interfaces

Add optional discovery interfaces to preserve current backends:

- ResolvePods selector API returning `{IP, Ports, Namespace, Labels}`.
- Namespace selector resolution for `namespaceSelector`.

`ServiceDiscovery` remains unchanged for legacy callers; advanced resolution uses capability checks.

### Kubernetes Discovery

- Add namespace informer/lister in `K8sDiscoveryAllNamespaces`.
- Implement selector evaluation using `matchLabels` + `matchExpressions`.
- For `namespaceSelector`, resolve namespaces first, then pods within each namespace.
- Update watch logic to trigger on both pod and namespace label changes.

### In-Memory Discovery

- Extend label matching to support matchExpressions.
- Named port resolution works when the discovery backend can return pod ports (Kubernetes discovery does; in-memory discovery does not model ports).

## Enforcement and Translators

### Linux

- eBPF: CIDR LPM trie is supported.
  - Port ranges and named ports are not supported by the eBPF enforcer; policies fall back to iptables on Linux.
- iptables: emit `--dport start:end` for ranges.

### macOS (pf)

- Emit port ranges using `port start:end`.

### Windows (WFP)

- Add port-range conditions to WFP translation and engine bindings.
- Preserve ICMP behavior (ignore port).

### Cloud

- AWS: use `FromPort`/`ToPort` for ranges.
- Azure: use `DestinationPortRange: "start-end"`.
- GCP: use `Allowed.Ports: ["start-end"]` (TCP/UDP only).

## Operator and CRD

- Extend `pkg/operator/api/v1alpha1/ztapnetworkpolicy_types.go` with new fields.
- Update `deployments/kubernetes/ztapnetworkpolicy-crd.yaml` schema.
- Update `pkg/operator/controllers/converter.go` to map new fields.

## Testing Plan

### Policy Package

- Validate selectors with matchExpressions, namespaceSelector combinations, and invalid mixes.
- Validate ipBlock.except family/subset rules and expansion limits.
- Validate named ports, port ranges, and invalid permutations.

### Resolver

- Resolve namespaceSelector + podSelector to concrete IPs via fake clientset.
- Resolve named ports from pod specs (egress and ingress).
- Verify CIDR subtraction outputs are stable and sorted.

### Discovery

- K8s discovery tests for namespace selector scoping and watch triggers.

### Enforcers

- iptables: assert range rendering.
- WFP: assert range conditions in generated specs.

### Cloud

- AWS/Azure/GCP: assert range formatting and rule naming stability.

## Rollout and Compatibility

- Changes are additive; existing policies continue to validate and enforce.
- New fields are gated by discovery and enforcement capabilities; when unsupported, fail fast with
  actionable validation errors.
- Emit warnings when resolution yields zero targets or named ports cannot be resolved.

## Open Follow-ups

- Consider adding a config flag to opt into unioning named ports (not recommended).
- Explore BPF port-range support to remove iptables fallback.
