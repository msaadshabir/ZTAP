#!/usr/bin/env bash
set -euo pipefail

GOVULNCHECK_VERSION="v1.1.4"
GOSEC_VERSION="v2.22.11"

cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "==> go test"
go test ./...

echo "==> go vet"
go vet ./...

echo "==> govulncheck"
if ! command -v govulncheck >/dev/null 2>&1; then
  echo "Installing govulncheck..."
  go install "golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION}"
fi
export PATH="$(go env GOPATH)/bin:$PATH"
govulncheck ./...

echo "==> gosec"
if ! command -v gosec >/dev/null 2>&1; then
  echo "Installing gosec..."
  go install "github.com/securego/gosec/v2/cmd/gosec@${GOSEC_VERSION}"
fi
export PATH="$(go env GOPATH)/bin:$PATH"

# G304 (variable file path) is expected in a CLI that intentionally reads operator-specified files.
# G602 (slice bounds) false positive on fixed-length arrays (e.g., [4]uint32 index 0).
# Skip generated code to avoid false positives in protobuf outputs.
gosec -exclude=G304,G602 -exclude-generated ./...

echo "All security checks passed."
