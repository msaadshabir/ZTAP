#!/usr/bin/env bash
set -euo pipefail

BUF_VERSION="v1.64.0"
PROTOC_GEN_GO_VERSION="v1.36.8"
PROTOC_GEN_GO_GRPC_VERSION="v1.6.0"

cd "$(dirname "${BASH_SOURCE[0]}")/.."

export PATH="$(go env GOPATH)/bin:$PATH"

if ! command -v buf >/dev/null 2>&1; then
  echo "Installing buf (${BUF_VERSION})..."
  go install "github.com/bufbuild/buf/cmd/buf@${BUF_VERSION}"
fi

if ! command -v protoc-gen-go >/dev/null 2>&1; then
  echo "Installing protoc-gen-go (${PROTOC_GEN_GO_VERSION})..."
  go install "google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOC_GEN_GO_VERSION}"
fi

if ! command -v protoc-gen-go-grpc >/dev/null 2>&1; then
  echo "Installing protoc-gen-go-grpc (${PROTOC_GEN_GO_GRPC_VERSION})..."
  go install "google.golang.org/grpc/cmd/protoc-gen-go-grpc@${PROTOC_GEN_GO_GRPC_VERSION}"
fi

buf generate
