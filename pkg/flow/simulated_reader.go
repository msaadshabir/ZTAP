package flow

import (
	"context"
	"sync"
	"time"
)

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

// Start emits the configured events periodically.
func (r *SimulatedReader) Start(ctx context.Context, eventCh chan<- RawFlowEvent) error {
	r.mu.Lock()
	r.running = true
	r.mu.Unlock()

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
			ns := uptimeNsFunc()
			if ns < 0 {
				ns = 0
			}
			event.TimestampNs = uint64(ns) // #nosec G115 -- ns is clamped to >=0 above
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
