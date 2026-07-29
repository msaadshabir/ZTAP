# Build stage for Go application
FROM golang:1.26.5-alpine AS go-builder

# eBPF bytecode is vendored (pkg/enforcer/bpf_bpf*.o) and regeneration is
# verified by the CI drift check, so no clang/llvm/make/git toolchain is
# needed in this image.

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" -o ztap .

# Final stage - minimal runtime image
FROM alpine:3.22

ARG VERSION=dev
ARG REVISION=unknown

LABEL org.opencontainers.image.source="https://github.com/msaadshabir/ZTAP" \
      org.opencontainers.image.title="ZTAP" \
      org.opencontainers.image.description="Zero Trust Access Platform: eBPF-based microsegmentation and policy enforcement" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

# Install runtime dependencies
RUN apk add --no-cache ca-certificates iptables

# Create non-root user
RUN addgroup -g 1000 ztap && \
    adduser -D -u 1000 -G ztap ztap

# Create necessary directories
RUN mkdir -p /etc/ztap /var/lib/ztap /var/log/ztap && \
    chown -R ztap:ztap /etc/ztap /var/lib/ztap /var/log/ztap

# Copy compiled binary
COPY --from=go-builder /app/ztap /usr/local/bin/ztap

# Copy example configs
COPY examples/ /etc/ztap/examples/

# Set user
USER ztap

# Expose metrics port
EXPOSE 9090

# Set working directory
WORKDIR /etc/ztap

# Default command
ENTRYPOINT ["/usr/local/bin/ztap"]
CMD ["--help"]
