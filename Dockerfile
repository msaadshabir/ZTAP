# Build stage for eBPF compilation
FROM ubuntu:22.04 AS ebpf-builder

# Install eBPF build dependencies
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    make \
    linux-headers-generic \
    libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy eBPF source
WORKDIR /build
COPY bpf/ ./bpf/

# Compile eBPF program with proper headers (optional - may fail in CI)
WORKDIR /build/bpf
RUN KERNEL_VERSION=$(ls /usr/src/ | grep linux-headers | grep -v common | head -1 | sed 's/linux-headers-//') && \
    export KERNEL_HEADERS=/usr/src/linux-headers-${KERNEL_VERSION} && \
    make || (echo "eBPF compilation failed - will compile at runtime" && mkdir -p /build/bpf && touch /build/bpf/.skip)

# Build stage for Go application
FROM golang:1.25.2-alpine AS go-builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o ztap .

# Final stage - minimal runtime image
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

# Create non-root user
RUN addgroup -g 1000 ztap && \
    adduser -D -u 1000 -G ztap ztap

# Create necessary directories
RUN mkdir -p /etc/ztap /var/lib/ztap /var/log/ztap && \
    chown -R ztap:ztap /etc/ztap /var/lib/ztap /var/log/ztap

# Copy compiled binary
COPY --from=go-builder /app/ztap /usr/local/bin/ztap

# Copy eBPF source for runtime compilation
COPY bpf/ /etc/ztap/bpf/

# Copy pre-compiled eBPF object files if they exist
COPY --from=ebpf-builder /build/bpf/*.o /etc/ztap/bpf/ 2>/dev/null || true

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
