# Example Policies

This directory contains sample ZTAP policies demonstrating various zero-trust scenarios.

## Basic Policies

### web-to-db.yaml

Classic three-tier application:

- Web tier can only talk to API tier
- IoT devices can only reach internet (DNS + HTTPS)

```bash
ztap enforce -f web-to-db.yaml
```

## Security Scenarios

### lateral-movement.yaml

Prevents lateral movement in compromised environment:

- Web servers can only reach API tier
- API servers can only reach database
- No cross-tier communication allowed

**Use case**: Mitigate impact of web server compromise

```bash
ztap enforce -f lateral-movement.yaml
```

### pci-compliant.yaml

PCI-DSS compliant payment processor:

- Only internal network (10.0.0.0/8) access
- HTTPS only (port 443)
- Blocks all other traffic

**Use case**: Payment card processing compliance

```bash
ztap enforce -f pci-compliant.yaml
```

### deny-all.yaml

Strictest security posture:

- Default deny all egress
- Only explicit DNS allowed

**Use case**: High-security environment, isolated services

```bash
ztap enforce -f deny-all.yaml
```

### microservices.yaml

Zero-trust microservices architecture:

- Auth service → User DB (MongoDB:27017) + Cache (Redis:6379)
- Monitoring → Internal metrics endpoints only

**Use case**: Cloud-native microservices

```bash
ztap enforce -f microservices.yaml
```

## Policy Patterns

### Label-Based Rules

```yaml
egress:
  - to:
      podSelector:
        matchLabels:
          app: database
          tier: backend
```

### IP-Based Rules

```yaml
egress:
  - to:
      ipBlock:
        cidr: 10.0.0.0/8
```

### Port Restrictions

```yaml
ports:
  - protocol: TCP
    port: 443
  - protocol: UDP
    port: 53
```

## Testing Policies

### 1. Validate Syntax

```bash
# Check YAML format
cat policy.yaml | python3 -m yaml

# Validate with ZTAP (future feature)
ztap validate -f policy.yaml
```

### 2. Dry Run

```bash
# See what would happen without enforcing
ztap enforce -f policy.yaml --dry-run
```

### 3. Monitor Logs

```bash
# Apply policy
ztap enforce -f policy.yaml

# Watch logs
ztap logs --policy your-policy-name --follow
```

## Creating Custom Policies

### Template

```yaml
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: your-policy-name # lowercase, alphanumeric, hyphens
spec:
  podSelector:
    matchLabels:
      app: your-app # Labels to match source workloads
  egress:
    - to:
        # Option 1: Label selector
        podSelector:
          matchLabels:
            app: target-app
        # Option 2: IP block
        # ipBlock:
        #   cidr: 10.0.0.0/24
      ports:
        - protocol: TCP # TCP, UDP, or ICMP
          port: 443 # 1-65535
```

### Best Practices

1. **Start Restrictive**: Begin with deny-all, add explicit allows
2. **Use Labels**: Prefer label selectors over IPs (more maintainable)
3. **Document Intent**: Use clear policy names
4. **Test Incrementally**: Apply one policy at a time
5. **Monitor Impact**: Check logs before full rollout

### Common Mistakes

1. **Missing podSelector**: Must have at least one label
2. **Invalid CIDR**: Use proper notation (e.g., 10.0.0.0/8)
3. **Mixed selectors**: Don't use podSelector + ipBlock together
4. **Port out of range**: Must be 1-65535
5. **Wrong protocol**: Use TCP, UDP, or ICMP (case-sensitive)

## Policy Composition

You can combine multiple policies in one file using `---` separator:

```yaml
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: policy-one
spec:
  # ... spec here ...
---
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: policy-two
spec:
  # ... spec here ...
```

## Next Steps

- Review [Architecture](../docs/architecture.md) for how policies are enforced
- See [Evaluation](../docs/evaluation.md) for testing scenarios
- Read [Setup Guide](../docs/setup.md) for deployment options
