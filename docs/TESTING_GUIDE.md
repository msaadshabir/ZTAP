# ZTAP Testing Guide

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

# Run with verbose output

go test ./... -v

# Run with coverage

go test ./... -cover

# Run with coverage HTML report

go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html

```

## Test Organization

### Package Structure

```

ZTAP/
├── pkg/
│ ├── auth/
│ │ ├── auth.go
│ │ └── auth_test.go # 7 tests, 72.4% coverage
│ ├── discovery/
│ │ ├── _.go
│ │ └── discovery_test.go # 10 tests, 76.3% coverage
│ ├── cloud/
│ │ ├── aws.go
│ │ └── aws_test.go # 9 tests, 90.0% coverage
│ ├── policy/
│ │ ├── _.go
│ │ └── policy_test.go # 3 tests, 73.6% coverage
│ ├── enforcer/
│ │ ├── ebpf_linux.go
│ │ └── enforcer_test.go # 6 tests (Linux-only)
│ ├── metrics/
│ │ ├── collector.go
│ │ └── collector_test.go # 3 tests, 85.2% coverage
│ └── ...
└── tests/
└── integration_test.go # 6 integration tests

````

## Unit Tests

### Authentication Tests (pkg/auth)

**Run**:

```bash
go test ./pkg/auth -v
````

**Tests**:

1. `TestCreateUser` - User creation, validation, duplicates
2. `TestAuthenticate` - Login success/failure scenarios
3. `TestValidateSession` - Token validation and expiration
4. `TestHasPermission` - RBAC permission checking
5. `TestChangePassword` - Password change workflow
6. `TestDisableEnable` - Account state management
7. `TestDefaultAdmin` - Default admin account verification

**Coverage**: 72.4%

**Example Output**:

```
=== RUN   TestCreateUser
--- PASS: TestCreateUser (0.00s)
=== RUN   TestAuthenticate
--- PASS: TestAuthenticate (0.00s)
...
PASS
ok      ztap/pkg/auth   0.339s  coverage: 72.4% of statements
```

### Service Discovery Tests (pkg/discovery)

**Run**:

```bash
go test ./pkg/discovery -v
```

**Tests**:

1. `TestInMemoryDiscovery_RegisterAndResolve` - Basic registration
2. `TestInMemoryDiscovery_NoMatch` - Non-existent service
3. `TestInMemoryDiscovery_InvalidIP` - Invalid IP handling
4. `TestInMemoryDiscovery_Deregister` - Service removal
5. `TestInMemoryDiscovery_ListServices` - Service enumeration
6. `TestInMemoryDiscovery_Watch` - Dynamic update notifications
7. `TestDNSDiscovery` - DNS resolution
8. `TestCacheDiscovery` - TTL-based caching
9. `TestCacheDiscovery_ClearCache` - Cache invalidation
10. `TestMatchLabels` - Label selector matching

**Coverage**: 76.3%

**Key Scenarios**:

- Service registration and lookup
- Label-based matching
- Cache behavior (10s TTL)
- Watch API with callbacks
- DNS fallback

### Policy Tests (pkg/policy)

**Run**:

```bash
go test ./pkg/policy -v
```

**Tests**:

1. `TestLoadFromFile` - YAML parsing
2. `TestValidate` - Policy validation (CIDR, ports, protocols)
3. `TestPolicyResolver` - Service discovery integration

**Coverage**: 73.6%

**Key Scenarios**:

- Valid policy parsing
- Invalid YAML handling
- CIDR validation
- Port range validation
- Service resolution

### Cloud Integration Tests (pkg/cloud)

**Run**:

```bash
go test ./pkg/cloud -v
```

**Tests**:

1. `TestMatchResourcesByLabels` - Tag-based label matching helper
2. `TestDiscoverResources` - EC2 discovery happy path (running instances only)
3. `TestDiscoverResourcesError` - Error propagation on describe failures
4. `TestSyncPolicyWithIPBlock` - Security Group sync with multiple ports
5. `TestSyncPolicyAuthorizeError` - Duplicate/failed authorization handling
6. `TestAuthorizeEgressDuplicate` - Duplicate rule suppression
7. `TestRevokeAllEgress` - Full egress revoke workflow
8. `TestRevokeAllEgressNoRules` - No-op when nothing to revoke
9. `TestRevokeAllEgressNotFound` - Missing Security Group handling

**Coverage**: 90.0%

**Key Scenarios**:

- Mocked EC2 client ensures deterministic behavior
- Table-driven validation of authorize/revoke requests
- Instance filtering (skips terminated, captures labels)

### Enforcer Tests (pkg/enforcer) - Linux Only

**Run** (on Linux):

```bash
GOOS=linux go test ./pkg/enforcer -v
```

**Tests**:

1. `TestProtocolToNum` - TCP/UDP/ICMP conversion
2. `TestIPToUint32` - IP address to integer conversion
3. `TestIPToUint32_Nil` - Nil IP handling
4. `TestPolicyKey` - BPF map key structure
5. `TestPolicyValue` - BPF map value structure
6. `TestCreatePolicyFromYAML` - Policy parsing

**Coverage**: N/A (Linux build tag)

**Note**: These tests require Linux because they test eBPF-specific code. On macOS, they are skipped automatically.

### Metrics Collector Tests (pkg/metrics)

**Run**:

```bash
go test ./pkg/metrics -v
```

**Tests**:

1. `TestGetCollectorSingleton` - Singleton guard via sync.Once reset
2. `TestCollectorCounters` - Counter increments for enforced/allowed/blocked
3. `TestCollectorGaugeAndHistogram` - Gauge updates and histogram samples

**Coverage**: 85.2%

**Key Scenarios**:

- Global collector reset to avoid cross-test leakage
- Counter totals verified with Prometheus testutil
- Histogram inspected via protobuf DTO for sum/count accuracy

## Integration Tests

### Run Integration Tests

```bash
go test ./tests -v
```

**Tests**:

1. `TestPolicyDiscoveryIntegration` - Policy + Discovery workflow
2. `TestPolicyLoadAndValidate` - Policy validation pipeline
3. `TestDiscoveryWithCache` - Cached discovery behavior
4. `TestDynamicServiceUpdates` - Service updates during runtime
5. `TestMultiplePoliciesWithDiscovery` - Complex label selectors
6. `TestPolicyValidationErrors` - Error handling

**Coverage**: Full workflow testing (no statements to cover)

**Execution Time**: ~1 second (includes 0.8s cache TTL wait)

## Platform-Specific Testing

### macOS Testing

On macOS, eBPF tests are automatically skipped:

```bash
# This will skip enforcer tests
go test ./...
```

**Expected Output**:

```
?       ztap/pkg/enforcer       [no test files]
```

This is correct behavior - the enforcer tests have the `//go:build linux` tag.

### Linux Testing

On Linux, all tests should run:

```bash
# Run all tests including eBPF
go test ./... -v

# Run only enforcer tests
go test ./pkg/enforcer -v
```

**Requirements**:

- Linux kernel 5.7+
- clang, llvm, make
- linux-headers

### Cross-Platform Testing

To test the build on different platforms:

```bash
# Test Linux build on macOS
GOOS=linux GOARCH=amd64 go build

# Test compilation (doesn't run tests)
GOOS=linux go test -c ./pkg/enforcer
```

## Coverage Analysis

### Generate Coverage Report

```bash
# Generate coverage for all packages
go test ./... -coverprofile=coverage.out

# Generate HTML report
go tool cover -html=coverage.out -o coverage.html

# Open in browser (macOS)
open coverage.html

# Open in browser (Linux)
xdg-open coverage.html
```

### Package Coverage

```bash
# Coverage by package
go test ./pkg/auth -cover
go test ./pkg/cloud -cover
go test ./pkg/discovery -cover
go test ./pkg/metrics -cover
go test ./pkg/policy -cover
```

**Current Coverage**:

- `pkg/auth`: 72.4%
- `pkg/cloud`: 90.0%
- `pkg/discovery`: 76.3%
- `pkg/metrics`: 85.2%
- `pkg/policy`: 73.6%
- **Core Average**: 79.5%

### Detailed Coverage

```bash
# Show which lines are covered
go test ./pkg/auth -coverprofile=auth.out
go tool cover -func=auth.out

# Example output:
# auth.go:15:    CreateUser      85.7%
# auth.go:45:    Authenticate    100.0%
# auth.go:78:    ValidateSession 90.0%
```

## Test Data

### Temporary Directories

Tests use `t.TempDir()` for isolation:

```go
func TestExample(t *testing.T) {
    tmpDir := t.TempDir() // Auto-cleaned after test
    dbPath := filepath.Join(tmpDir, "test.db")
    // ...
}
```

**Benefits**:

- No cleanup needed
- Parallel test safety
- No leftover files

### Example Policies

Tests use inline YAML for policies:

```go
yaml := `
apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: test-policy
spec:
  podSelector:
    matchLabels:
      app: web
  egress:
    - to:
        podSelector:
          matchLabels:
            app: db
      ports:
        - protocol: TCP
          port: 5432
`
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
        go: ["1.22", "1.23"]

    runs-on: ${{ matrix.os }}

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: ${{ matrix.go }}

      - name: Install eBPF dependencies (Linux)
        if: runner.os == 'Linux'
        run: |
          sudo apt-get update
          sudo apt-get install -y clang llvm make linux-headers-$(uname -r)

      - name: Run tests
        run: go test ./... -v -race -coverprofile=coverage.out

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.out
```

## Performance Testing

### Benchmark Tests

```go
func BenchmarkAuthenticate(b *testing.B) {
    mgr := NewAuthManager("test.db")
    defer mgr.Close()

    mgr.CreateUser("testuser", "password", RoleAdmin)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        mgr.Authenticate("testuser", "password")
    }
}
```

**Run Benchmarks**:

```bash
# Run all benchmarks
go test -bench=. ./...

# Run specific benchmark
go test -bench=BenchmarkAuthenticate ./pkg/auth

# With memory allocation stats
go test -bench=. -benchmem ./...
```

### Load Testing

For load testing the full system:

```bash
# Start ZTAP
./ztap daemon &

# Apply policies
for i in {1..100}; do
    ./ztap enforce -f examples/policy-$i.yaml
done

# Measure enforcement time
time ./ztap enforce -f examples/load-test-policy.yaml
```

## Debugging Tests

### Verbose Output

```bash
# Show all test output
go test ./... -v

# Show only failures
go test ./...
```

### Run Single Test

```bash
# Run one test function
go test ./pkg/auth -run TestAuthenticate -v

# Run tests matching pattern
go test ./pkg/auth -run "Test.*Password" -v
```

### Print Debugging

```go
func TestExample(t *testing.T) {
    t.Log("Debug info")           // Only shown with -v
    t.Logf("Value: %v", value)    // Formatted output

    fmt.Println("Always prints")  // Prints even without -v
}
```

### Race Detector

```bash
# Detect race conditions
go test ./... -race

# Example race:
# WARNING: DATA RACE
# Write at 0x00c000012345 by goroutine 7:
# ...
```

### Test Timeout

```bash
# Increase timeout for slow tests
go test ./... -timeout 5m

# Per-test timeout
func TestSlow(t *testing.T) {
    if testing.Short() {
        t.Skip("Skipping slow test")
    }
    // ...
}

# Run without slow tests
go test -short ./...
```

## Common Issues

### Issue 1: "no test files" on macOS

**Symptom**:

```
?       ztap/pkg/enforcer       [no test files]
```

**Cause**: Tests have Linux build tag

**Solution**: This is expected. Run on Linux or use:

```bash
GOOS=linux go test -c ./pkg/enforcer
```

### Issue 2: Test database conflicts

**Symptom**:

```
panic: database is locked
```

**Cause**: Tests sharing database file

**Solution**: Use `t.TempDir()`:

```go
tmpDir := t.TempDir()
dbPath := filepath.Join(tmpDir, "test.db")
```

### Issue 3: Port conflicts

**Symptom**:

```
listen tcp :8080: bind: address already in use
```

**Cause**: Test server port collision

**Solution**: Use random ports:

```go
listener, _ := net.Listen("tcp", "127.0.0.1:0")
port := listener.Addr().(*net.TCPAddr).Port
```

### Issue 4: Missing eBPF headers

**Symptom**:

```
fatal error: 'linux/bpf.h' file not found
```

**Cause**: Missing kernel headers

**Solution**: Install headers:

```bash
# Ubuntu
sudo apt-get install linux-headers-$(uname -r)

# Fedora
sudo dnf install kernel-headers kernel-devel
```

### Issue 5: Test cache issues

**Symptom**: Tests fail after code changes

**Solution**: Clear test cache:

```bash
go clean -testcache
go test ./...
```

## Test Best Practices

### 1. Use Table-Driven Tests

```go
func TestProtocolToNum(t *testing.T) {
    tests := []struct {
        protocol string
        expected uint8
    }{
        {"TCP", 6},
        {"UDP", 17},
        {"ICMP", 1},
    }

    for _, tt := range tests {
        t.Run(tt.protocol, func(t *testing.T) {
            result := protocolToNum(tt.protocol)
            if result != tt.expected {
                t.Errorf("got %d, want %d", result, tt.expected)
            }
        })
    }
}
```

### 2. Use Subtests

```go
func TestPermissions(t *testing.T) {
    t.Run("admin can manage", func(t *testing.T) {
        // ...
    })

    t.Run("operator can view", func(t *testing.T) {
        // ...
    })
}
```

### 3. Clean Up Resources

```go
func TestWithCleanup(t *testing.T) {
    resource := acquireResource()
    t.Cleanup(func() {
        resource.Close()
    })
    // ...
}
```

### 4. Test Error Cases

```go
func TestErrorHandling(t *testing.T) {
    err := someFunction()
    if err == nil {
        t.Fatal("expected error, got nil")
    }

    if !strings.Contains(err.Error(), "expected text") {
        t.Errorf("wrong error: %v", err)
    }
}
```

### 5. Use Helper Functions

```go
func createTestUser(t *testing.T, mgr *AuthManager) string {
    t.Helper()
    username := "test-" + randomString()
    if err := mgr.CreateUser(username, "password", RoleAdmin); err != nil {
        t.Fatal(err)
    }
    return username
}
```

## CI/CD Integration

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "Running tests..."
go test ./...

if [ $? -ne 0 ]; then
    echo "Tests failed. Commit aborted."
    exit 1
fi

echo "All tests passed!"
```

### Make Targets

```makefile
# Makefile
.PHONY: test test-verbose test-coverage test-race

test:
	go test ./...

test-verbose:
	go test ./... -v

test-coverage:
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out

test-race:
	go test ./... -race

test-all: test-race test-coverage
```

**Usage**:

```bash
make test
make test-coverage
make test-all
```

## Summary

ZTAP has comprehensive test coverage:

- **26 tests** across 4 test suites
- **74.1% average coverage** for core packages
- **Integration tests** for full workflows
- **Platform-aware** testing (Linux/macOS)
- **Fast execution** (< 2 seconds)

**Run All Tests**:

```bash
go test ./... -v -cover
```

**Expected Output**:

```
**Expected Output**:
```

[PASS] pkg/auth: 7 tests (72.4% coverage)
[PASS] pkg/discovery: 10 tests (76.3% coverage)
[PASS] pkg/policy: 3 tests (73.6% coverage)
[PASS] tests: 6 tests (integration)
──────────────────────────────────────────────
[PASS] TOTAL: 26 tests (all passing)

```

For more information, see:
```

For more information, see:

- [STATUS.md](STATUS.md) - Implementation status
- [EBPF.md](EBPF.md) - eBPF-specific testing
- [architecture.md](architecture.md) - System design

---

_Happy Testing!_
