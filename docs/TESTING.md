# ZTAP Testing Documentation

## Overview

ZTAP includes comprehensive test coverage across all critical components with unit tests, integration tests, and validation scenarios.

## Test Coverage

### Unit Tests

#### Policy Package (`pkg/policy/policy_test.go`)

- **TestLoadFromFile**: Validates YAML policy file loading
- **TestValidate**: Tests policy validation rules
  - Valid policy structure
  - Missing apiVersion
  - Invalid CIDR notation
  - Invalid port numbers
  - Invalid protocol types
- **TestPolicyResolver**: Tests label resolution with service discovery

**Run**: `go test ./pkg/policy/... -v`

#### Discovery Package (`pkg/discovery/discovery_test.go`)

- **TestInMemoryDiscovery_RegisterAndResolve**: Service registration and label-based resolution
- **TestInMemoryDiscovery_NoMatch**: Handling non-existent services
- **TestInMemoryDiscovery_InvalidIP**: IP address validation
- **TestInMemoryDiscovery_Deregister**: Service removal
- **TestInMemoryDiscovery_ListServices**: Listing all registered services
- **TestInMemoryDiscovery_Watch**: Dynamic service change notifications
- **TestDNSDiscovery**: DNS-based discovery validation
- **TestCacheDiscovery**: Caching layer functionality
  - Cache hits and misses
  - TTL expiration
  - Cache clearing
- **TestMatchLabels**: Label selector matching logic

**Run**: `go test ./pkg/discovery/... -v`

#### Cloud Package (`pkg/cloud/aws_test.go`)

- **TestMatchResourcesByLabels**: Ensures label selectors align with AWS tags
- **TestDiscoverResources**: Discovers running EC2 instances and captures metadata
- **TestDiscoverResourcesError**: Propagates DescribeInstances failures
- **TestSyncPolicyWithIPBlock**: Syncs multi-port Security Group egress rules
- **TestSyncPolicyAuthorizeError**: Handles authorization API failures
- **TestAuthorizeEgressDuplicate**: Suppresses duplicate rule errors
- **TestRevokeAllEgress**: Revokes existing egress rules for cleanup
- **TestRevokeAllEgressNoRules**: No-op when no rules exist
- **TestRevokeAllEgressNotFound**: Detects missing Security Groups

**Run**: `go test ./pkg/cloud/... -v`

#### Metrics Package (`pkg/metrics/collector_test.go`)

- **TestGetCollectorSingleton**: Verifies singleton initialization semantics
- **TestCollectorCounters**: Confirms counter increments for policies and flows
- **TestCollectorGaugeAndHistogram**: Validates gauge state and histogram buckets

**Run**: `go test ./pkg/metrics/... -v`

### Integration Tests (`tests/integration_test.go`)

#### Policy-Discovery Integration

- **TestPolicyDiscoveryIntegration**: End-to-end label resolution flow
- **TestPolicyLoadAndValidate**: Policy loading, parsing, and validation
- **TestMultiplePoliciesWithDiscovery**: Complex multi-label queries

#### Dynamic Service Management

- **TestDynamicServiceUpdates**: Real-time service change tracking
- **TestDiscoveryWithCache**: Cache performance and correctness

#### Validation Scenarios

- **TestPolicyValidationErrors**: Comprehensive error handling
  - Valid policy acceptance
  - Invalid CIDR rejection
  - Invalid port rejection
  - Invalid protocol rejection

**Run**: `go test ./tests/... -v`

## Running Tests

### All Tests

```bash
go test ./... -v
```

### Specific Package

```bash
go test ./pkg/policy/... -v
go test ./pkg/cloud/... -v
go test ./pkg/discovery/... -v
go test ./pkg/metrics/... -v
go test ./tests/... -v
```

### With Coverage

```bash
go test ./... -cover
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Race Detection

```bash
go test ./... -race
```

## Test Results Summary

```
Package            Tests  Pass  Coverage
─────────────────────────────────────────
pkg/auth             7     7    72.4%
pkg/cloud            9     9    90.0%
pkg/discovery       10    10    76.3%
pkg/metrics          3     3    85.2%
pkg/policy           3     3    73.6%
tests/integration    6     6    N/A
─────────────────────────────────────────
Total               38    38
```

## Test Data

### Sample Policy (tests/fixtures/test-policy.yaml)

```yaml
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: web-to-db
spec:
  podSelector:
    matchLabels:
      app: web
  egress:
    - to:
        ipBlock:
          cidr: 10.0.2.0/24
      ports:
        - protocol: TCP
          port: 5432
```

### Service Discovery Test Data

```go
services := []Service{
    {Name: "web-1", IP: "10.0.1.1", Labels: {"app": "web", "tier": "frontend"}},
    {Name: "web-2", IP: "10.0.1.2", Labels: {"app": "web", "tier": "frontend"}},
    {Name: "db-1", IP: "10.0.2.1", Labels: {"app": "database", "tier": "backend"}},
}
```

## Continuous Integration

### GitHub Actions (Recommended)

```yaml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
        with:
          go-version: "1.22"
      - run: go test ./... -v -race -coverprofile=coverage.out
      - run: go tool cover -func=coverage.out
```

## Testing Best Practices

1. **Isolation**: Each test uses `t.TempDir()` for isolated file operations
2. **Cleanup**: Automatic cleanup of test resources via `defer` and temp directories
3. **Parallelism**: Tests can run in parallel (add `t.Parallel()` where appropriate)
4. **Table-Driven**: Complex scenarios use table-driven tests for clarity
5. **Error Checking**: Both success and failure paths are validated

## Future Testing Needs

### Unit Tests (TODO)

- [ ] `pkg/anomaly/detector_test.go` - Anomaly detection microservice
- [ ] `pkg/cmd/...` - CLI command flows (enforce, status, logs)
- [ ] Expand `pkg/enforcer` coverage on Linux runners

### Integration Tests (TODO)

- [ ] End-to-end policy enforcement with eBPF
- [ ] AWS Security Group synchronization against live AWS account
- [ ] Anomaly detection with real traffic
- [ ] Multi-node distributed testing

### Performance Tests (TODO)

- [ ] Policy evaluation latency benchmarks
- [ ] Service discovery scalability tests
- [ ] Memory usage under load
- [ ] Concurrent policy enforcement

## Troubleshooting

### Test Failures

**"no services found matching labels"**

- Check label selector syntax
- Verify services are registered before resolution

**"invalid CIDR"**

- Ensure CIDR notation includes subnet mask (e.g., `10.0.0.0/8`)

**"session expired"**

- Tests manipulate time; ensure timing expectations are reasonable

### Running Individual Tests

```bash
go test ./pkg/policy -run TestLoadFromFile -v
go test ./pkg/discovery -run TestInMemoryDiscovery_Watch -v
```

## Test Maintenance

- Update tests when adding new policy validation rules
- Add integration tests for new service discovery backends (Consul, K8s)
- Keep test data synchronized with documentation examples
- Run `go test ./... -race` regularly to detect concurrency issues
