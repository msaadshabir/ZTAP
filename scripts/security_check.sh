#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "==> go test"
go test ./...

echo "==> go vet"
go vet ./...

echo "==> govulncheck"
if ! command -v govulncheck >/dev/null 2>&1; then
  echo "Installing govulncheck..."
  go install golang.org/x/vuln/cmd/govulncheck@latest
fi
export PATH="$(go env GOPATH)/bin:$PATH"
govulncheck ./...

echo "==> gosec"
if ! command -v gosec >/dev/null 2>&1; then
  echo "Installing gosec..."
  go install github.com/securego/gosec/v2/cmd/gosec@latest
fi
export PATH="$(go env GOPATH)/bin:$PATH"

# G304 (variable file path) is expected in a CLI that intentionally reads operator-specified files.
# G602 (slice bounds) false positive on fixed-length arrays (e.g., [4]uint32 index 0).
gosec -exclude=G304,G602 ./...

echo "All security checks passed."
