# Changelog

All notable changes to this project will be documented in this file.

This project aims to follow Keep a Changelog (https://keepachangelog.com/en/1.1.0/)
and Semantic Versioning (https://semver.org/).

## [Unreleased]

### Added

- New audit tests: `TestVerifyIntegrityDetailed_EntryCount`, `TestLoadLastHash_ResetsCounterOnReopen`, `TestVerifyIntegrityDetailed_EmptyLog`, `TestEntryHash_NilEntry`, `TestEntryHash_ValidEntry`, `TestEntryHash_NonSerializableDetails`.
- New flow monitor tests: `TestMonitor_SubscriberLifecycle_NoPanic`, `TestMonitor_SubscribeAfterStop`, `TestMonitor_ConcurrentSubscribeUnsubscribe`.
- New discovery test: `TestK8sDiscovery_WatchNoMatchInitialState`.
- New gRPC interceptor regression tests for malformed/unknown method paths.
- Documented comprehensive local security audit workflow in `README.md`, `CONTRIBUTING.md`, and `docs/guides/testing.md`.

### Changed

- Dependencies: upgraded `google.golang.org/grpc` to v1.79.3.
- Tooling: bumped Go toolchain to 1.25.8 for the security workflow.
- Dependencies: refreshed Go module and GitHub Actions versions via Dependabot.
- **CI: optimized GitHub Actions workflows** across all four workflow files (`ci.yml`, `security.yml`, `codeql.yml`, `release.yml`):
  - Removed redundant `gofmt` and `go vet` steps from lint job (golangci-lint covers both).
  - Parallelized Docker builds via matrix strategy (ztap, ztap-anomaly, ztap-operator build concurrently).
  - Reduced CI schedule from nightly to weekly. Reduced CodeQL timeout from 360 to 90 minutes.
  - Added `paths-ignore` to push triggers so doc-only changes skip CI/security/CodeQL pipelines.
  - Added `pull_request` trigger to CodeQL with path filters for Go and Python source files.
  - Removed `needs: security` from Trivy scan job so security checks run in parallel.
  - Pinned all runners from `ubuntu-latest` to `ubuntu-24.04` for reproducibility.
  - Added artifact retention policies (14 days for coverage, 30 days for benchmarks, 7 days for release artifacts).
  - Added `actions/cache` for govulncheck/gosec binaries to avoid recompilation on each run.
  - Replaced `sleep 10` in Docker Compose test with `docker compose up --wait`.
  - Refactored actionlint job to use the pinned `rhysd/actionlint` action instead of compiling from source via Go.
  - Removed duplicated `GOFLAGS` env declarations from jobs (inherited from workflow level).
  - Added concurrency group to release workflow. Added SHA256 checksums to release artifacts.
  - Filtered `download-artifact` in coverage report to only download `coverage-*` pattern.
- Updated documentation (`CONTRIBUTING.md`, `README.md`, `docs/guides/testing.md`, `.github/copilot-instructions.md`, `docs/project-status.md`) to reflect CI/CD changes.
- **BREAKING**: `auth.Authenticate` signature changed from `Authenticate(username, password string)` to `Authenticate(ctx context.Context, username, password string)`. All internal callers (gRPC, REST, CLI) have been updated. External consumers of the library API must pass a `context.Context` as the first argument.
- **BREAKING**: `audit.EntryHash` return type changed from `string` to `(string, error)`. Callers must handle the error (returned when `Details` cannot be JSON-serialized).
- **Documentation overhaul**: restructured docs into `guides/`, `concepts/`, `reference/`, and `runbooks/` subdirectories. Created `docs/index.md` as navigation hub and dedicated CLI, Configuration, and API reference pages. Replaced `docs/roadmap.md` with `docs/project-status.md`. Fixed Go version (1.25), Python version (3.11+), removed nonexistent `ztap daemon` command, corrected admin bootstrap workflow, standardized `docker compose` (no hyphen), and removed stale coverage numbers.
- Clarified recommended contributor test workflow to include race detection (`go test ./... -race`).

### Removed

- Deleted `CODE_OF_CONDUCT.md` and removed all references to it from `README.md`, `CONTRIBUTING.md`, and `docs/project-status.md`.

### Fixed

- **Cluster: watcher/subscriber channel lifecycle fixes** across in-memory election, in-memory policy sync, and Kubernetes-backed policy sync (remove-before-close, restart-safe `stopCh`, accurate subscriber accounting).
- **Audit: `VerifyIntegrityDetailed` double-counted entries**: The entry position was incremented twice per iteration, inflating `EntryCount` in the verification result.
- **Audit: `loadLastHash` accumulated `entryCount` across calls**: Reopening an audit log file caused `entryCount` to grow without bound. The index cache was also exposed in a partially-built state during loading. Fixed by building a local cache and assigning atomically under the lock.
- **Audit: `EntryHash` silently ignored marshal errors**: If `Details` contained a non-serializable value, `json.Marshal` would fail silently and produce an incorrect hash. `EntryHash` now returns an error.
- **Audit: truncation detection test fragility**: `TestAuditLogger_TruncationDetection` now removes the last full JSON entry instead of a single trailing byte, ensuring a deterministic checkpoint mismatch.
- **Discovery: K8s watchers ignored initial resolve errors**: `Watch` and `WatchSelector` in `K8sDiscovery` discarded errors from `ResolveLabels`/`ResolveSelector` when sending initial state. Real errors are now propagated to the caller; `NoMatchesError` is treated as empty initial state.
- **gRPC: raw error strings leaked internal details**: Several gRPC handlers returned `err.Error()` or `fmt.Errorf(...).Error()` directly to clients. Handlers now log full error details server-side and return sanitized `status.Error` responses with appropriate gRPC codes.
- **Flow: `Monitor.Subscribe` used `recover()` to catch double-close panics**: This masked a channel ownership/race problem. Replaced with a `subscriber` struct that tracks a `closed` flag; both `Stop()` and context-cancel coordinate closure under a lock.
- **Auth: `Authenticate` used `context.Background()` for session store calls**: Requests were un-cancelable. `Authenticate` now accepts and propagates a caller-supplied `context.Context`.
- Removed data races in flow-stream API tests by avoiding concurrent reads/writes of `httptest.ResponseRecorder` in `pkg/apihttp/flows_test.go`.
- Resolved `staticcheck` `SA5011` nil-dereference warning in `cmd/policy.go` by returning early in `policy show` when a policy is not found.
- Fixed Windows CI failure in `.github/workflows/ci.yml` by removing bash-only line continuation from the advisory coverage gate step so matrix jobs run correctly under PowerShell.
- Fixed advisory coverage gate behavior in `.github/workflows/ci.yml` to skip `covergate` when `coverage-<os>.out` is missing and avoid failing the job on Windows shell semantics.

### Security

- **gRPC: hardened auth interceptors against malformed/unknown method paths** to prevent `:path`-based auth bypass; added regression tests.
- Added documented secret-scanning step using `gitleaks detect --source . --redact --no-banner`.

[Unreleased]: https://github.com/msaadshabir/ZTAP/commits/main
