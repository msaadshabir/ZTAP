# Contributing

Thanks for contributing to ZTAP.

- Security issues: see `SECURITY.md` (please do not file public issues for vulnerabilities)

## Ways To Contribute

- File bugs and feature requests via GitHub Issues
- Improve documentation (docs, examples, runbooks)
- Submit pull requests for fixes and enhancements

## Development Setup

### Prerequisites

- Go (use the version declared in `go.mod`)
- Optional (Linux/eBPF development): `clang`, `llvm`, `make`
- Optional (proto changes): `buf` (the script installs it via `go install`)
- Optional (anomaly service): Python 3.11+

### Local Build

```bash
go mod download
go build ./...
```

### Tests

```bash
go test ./... -v
go test ./... -race
```

### Lint / Format

```bash
gofmt -w .
go vet ./...
```

CI also runs `golangci-lint` (see `.github/workflows/ci.yml`).

When editing GitHub Actions, keep `run:` commands shell-agnostic for matrix jobs that include Windows (`pwsh`) and Linux/macOS (bash). Avoid bash-only line continuations (for example trailing `\`) in shared steps.

### Security Audit

Run the project security checks before opening a PR:

```bash
bash scripts/security_check.sh
```

This runs unit tests, `go vet`, `govulncheck`, and `gosec`.

Optional secret scan (recommended):

```bash
gitleaks detect --source . --redact --no-banner
```

## Project-Specific Workflows

### Protobuf / gRPC Codegen

If you change files under `proto/`, regenerate generated Go code:

```bash
./scripts/gen_proto.sh
```

### eBPF (Linux)

If you change `bpf/filter.c`, rebuild the object:

```bash
make -C bpf
```

## Pull Request Guidelines

- Keep PRs focused and small when possible
- Include tests and docs updates for behavior changes
- Make sure `go test ./...` passes locally
- Run `bash scripts/security_check.sh` before submitting
- Run `gofmt` on any Go changes

## Error Handling Conventions

- **API handlers** (REST and gRPC): log full error details server-side; return sanitized messages to clients. For gRPC, use `status.Error(codes.*, "short message")`. Never return `err.Error()` directly.
- **Audit hashing**: `EntryHash` returns `(string, error)`. Callers must check the error.
- **Context propagation**: functions that perform I/O or interact with external stores should accept `context.Context` as the first parameter.
- **Channel lifecycle**: do not use `recover()` to suppress double-close panics. Use explicit close-once coordination (e.g., a `closed` flag under a lock).

By submitting a contribution, you agree that your work will be licensed under
the MIT License (see `LICENSE`).
