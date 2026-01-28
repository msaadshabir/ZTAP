# Build stage for Go application
FROM golang:1.25-alpine AS go-builder

# Install build dependencies
RUN apk add --no-cache git make clang llvm

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Generate eBPF pre-compiled bytecode
RUN go generate ./pkg/enforcer/...

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
