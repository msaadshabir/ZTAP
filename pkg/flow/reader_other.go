//go:build !linux
// +build !linux

package flow

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

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

	log.Println("Flow monitoring is not available on this platform (requires Linux with eBPF)")
	log.Println("Running in simulation mode - no actual flow events will be captured")

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

// SimulatedReader provides simulated flow events for testing on any platform.
type SimulatedReader struct {
	mu       sync.Mutex
	running  bool
	stopCh   chan struct{}
	events   []RawFlowEvent
	interval time.Duration
}

// NewSimulatedReader creates a reader that emits simulated events at the given interval.
func NewSimulatedReader(events []RawFlowEvent, interval time.Duration) *SimulatedReader {
	if interval == 0 {
		interval = 100 * time.Millisecond
	}
	return &SimulatedReader{
		stopCh:   make(chan struct{}),
		events:   events,
		interval: interval,
	}
}

// Start emits simulated events periodically.
func (r *SimulatedReader) Start(ctx context.Context, eventCh chan<- RawFlowEvent) error {
	r.mu.Lock()
	r.running = true
	r.mu.Unlock()

	log.Println("Simulated flow reader started")

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	idx := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.stopCh:
			return nil
		case <-ticker.C:
			if len(r.events) == 0 {
				continue
			}
			event := r.events[idx%len(r.events)]
			event.TimestampNs = uint64(time.Now().UnixNano())
			select {
			case eventCh <- event:
			default:
			}
			idx++
		}
	}
}

// Stop stops the simulated reader.
func (r *SimulatedReader) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		close(r.stopCh)
		r.running = false
	}
	return nil
}

// Available returns true for simulated reader.
func (r *SimulatedReader) Available() bool {
	return true
}

// CreateDefaultReader creates the appropriate flow reader for this platform.
func CreateDefaultReader() FlowReader {
	return NewStubReader()
}

// ErrNotSupported is returned when flow monitoring is not available.
var ErrNotSupported = fmt.Errorf("flow monitoring requires Linux with eBPF support")
