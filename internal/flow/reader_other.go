//go:build !linux && !windows

package flow

import (
	"context"
	"errors"
	"sync"
	"time"

	"ztap/internal/logging"
)

var processStart = time.Now()

func init() {
	uptimeNsFunc = func() int64 { return time.Since(processStart).Nanoseconds() }
}

// StubReader provides a stub flow reader for non-Linux platforms.
// On macOS, this could be extended to parse pf logs in the future.
type StubReader struct {
	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
}

// NewStubReader creates a stub reader for non-Linux platforms.
func NewStubReader() *StubReader {
	return &StubReader{
		stopCh: make(chan struct{}),
	}
}

// Start logs a warning and returns since eBPF is not available.
func (r *StubReader) Start(ctx context.Context, eventCh chan<- RawFlowEvent) error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return nil
	}
	r.running = true
	r.mu.Unlock()

	logging.Warn("Flow monitoring is not available on this platform (requires Linux with eBPF)", nil)
	logging.Warn("Running in simulation mode - no actual flow events will be captured", nil)

	// Block until stopped or context cancelled
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.stopCh:
		return nil
	}
}

// Stop stops the stub reader.
func (r *StubReader) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running {
		return nil
	}
	r.running = false
	close(r.stopCh)
	return nil
}

// Available returns false since eBPF is not available on non-Linux platforms.
func (r *StubReader) Available() bool {
	return false
}

// CreateDefaultReader creates the appropriate flow reader for this platform.
func CreateDefaultReader() FlowReader {
	return NewStubReader()
}

// ErrNotSupported is returned when flow monitoring is not available.
var ErrNotSupported = errors.New("flow monitoring requires Linux with eBPF support")
