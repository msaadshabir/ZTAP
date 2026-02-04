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

#### Compliance Package (`pkg/compliance`)

- Mapping extraction from policy annotations and mapping files
- Audit evidence evaluation (integrity + `policy.enforced` event presence)
- JSON/CSV exporters and Markdown report rendering

**Run**: `go test ./pkg/compliance/... -v`

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
- **TestSyncPolicyWithSelectorResolution**: Resolves podSelector targets via EC2 tags and syncs host CIDRs
- **TestSyncPolicyWithSelectorExpressions**: Resolves matchExpressions selector targets via EC2 tags
- **TestAuthorizeEgressDuplicate**: Suppresses duplicate rule errors
- **TestSyncPolicyReplaceEgressReauthorizesExistingDesiredRule**: Takeover mode re-adds desired rules after clearing egress
- **TestRevokeAllEgress**: Revokes existing egress rules for cleanup
- **TestRevokeAllEgressNoRules**: No-op when no rules exist

#### Cloud Package (Azure/GCP inventory)

- **TestAzureDiscoverResources**: Discovers NIC inventory and resolves public IPs
- **TestAzureClientCountManagedRules**: Counts managed NSG rules by prefix
- **TestGCPDiscoverResources**: Discovers GCE instance inventory within a network
- **TestGCPClientCountManagedFirewalls**: Counts managed firewall rules by prefix

### Integration Tests

#### Enforcer Package (`pkg/enforcer/ebpf_linux_integration_test.go`)

> **Note**: These tests require Linux, root privileges, and a kernel supporting eBPF (5.7+).

- **TestEBPFIntegrationLoadAndAttach**: Verifies eBPF program compilation, map population, and cgroup attachment
- **TestEBPFIntegrationCgroupScopedMapKey**: Verifies non-zero cgroup key programming and selected-only config
- **TestEBPFIntegrationCgroupIsolationBetweenCgroups**: Verifies a rule programmed for cgroup A does not match cgroup B
- **TestEBPFIntegrationSelectedOnlySemantics**: Verifies non-enforced cgroups default-allow and enforced cgroups default-deny on miss
- **TestEBPFGracefulReload**: Verifies that policy updates are applied using atomic `bpf_link` updates without detaching the program (ensuring zero downtime)

Run prerequisites (Linux only):

- root (or sufficient capabilities to load/attach cgroup BPF)
- kernel 5.7+
- `make`, `clang`, and `llvm-strip` available (the tests recompile `bpf/filter.o`)

**Run**: `sudo go test -tags=integration ./pkg/enforcer -run TestEBPFIntegration -v`

- **TestRevokeAllEgressNotFound**: Detects missing Security Groups

**Run**: `go test ./pkg/cloud/... -v`

#### Metrics Package (`pkg/metrics/collector_test.go`)

- **TestGetCollectorSingleton**: Verifies singleton initialization semantics
- **TestCollectorCounters**: Confirms counter increments for flows
- **TestCollectorGaugeAndHistogram**: Validates gauge state and histogram buckets

**Run**: `go test ./pkg/metrics/... -v`

#### Enforcer Package (`pkg/enforcer/policy_enforcer_test.go`)

- **TestPolicyEnforcerDryRun**: Verifies that dry-run mode correctly tracks policy versions without applying system changes
- **TestPolicyEnforcerStartStop**: Validates lifecycle management
- **TestPolicyEnforcerAppliesUpdates**: End-to-end enforcement logic check

**Run**: `go test ./pkg/enforcer/... -v`

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

This includes the Kubernetes operator/agent packages. Dedicated unit tests for the operator reconcile loop are included in `pkg/operator/controllers/ztapnetworkpolicy_controller_test.go`.

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

### Windows Notes (WFP)

- Windows support uses Windows Filtering Platform (WFP) and requires an elevated terminal (Administrator) to actually apply/tear down filters.
- Unit tests for policy translation run on any OS; WFP runtime behavior is best validated on Windows.
- Windows WFP integration tests exist behind a build tag and are not part of the default test suite.

Run the Windows WFP flow integration tests (on Windows, elevated terminal):

```bash
go test ./pkg/flow -tags=integration -run TestWFPFlowIntegration -v
```

Compile-check WFP codepaths from non-Windows hosts:

```bash
GOOS=windows GOARCH=amd64 go test ./... -c
```

CI note: `.github/workflows/ci.yml` runs Go unit tests on `windows-latest` and includes Windows in the cross-build matrix.

## Test Results Summary

Test counts and coverage are expected to change as the project evolves.

```bash
# Quick pass/fail
go test ./...

# Coverage (project-wide)
go test ./... -cover
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

The repository ships with `.github/workflows/ci.yml`, which runs Go tests and uploads coverage on push and pull request events.

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
          go-version: "1.24"
      - run: go test ./... -v -race -coverprofile=coverage.out
      - run: go tool cover -func=coverage.out
```

## Testing Best Practices

1. **Isolation**: Each test uses `t.TempDir()` for isolated file operations
2. **Cleanup**: Automatic cleanup of test resources via `defer` and temp directories
3. **Parallelism**: Tests can run in parallel (add `t.Parallel()` where appropriate)
4. **Table-Driven**: Complex scenarios use table-driven tests for clarity
5. **Error Checking**: Both success and failure paths are validated

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
