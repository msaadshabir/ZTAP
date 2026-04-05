package flow

import (
	"context"
	"sync"
	"time"

	"ztap/pkg/logging"
)

// subscriber wraps a flow event channel with close-once semantics.
type subscriber struct {
	id     uint64
	ch     chan FlowEvent
	closed bool
}

// Monitor implements FlowMonitor with subscriber management.
type Monitor struct {
	mu          sync.RWMutex
	running     bool
	stopCh      chan struct{}
	subscribers map[uint64]*subscriber
	nextSubID   uint64
	stats       FlowStats
	reader      FlowReader // Platform-specific reader
}

// FlowReader is the platform-specific interface for reading flow events.
type FlowReader interface {
	// Start begins reading flow events from the kernel.
	Start(ctx context.Context, eventCh chan<- RawFlowEvent) error
	// Stop stops the reader.
	Stop() error
	// Available returns true if the reader can be used on this platform.
	Available() bool
}

// NewMonitor creates a new flow monitor with the given reader.
func NewMonitor(reader FlowReader) *Monitor {
	return &Monitor{
		stopCh:      make(chan struct{}),
		subscribers: make(map[uint64]*subscriber),
		reader:      reader,
	}
}

// Start begins monitoring flow events.
func (m *Monitor) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = true
	m.stats.MonitorStarted = time.Now()
	// Capture stopCh under lock to avoid race with Stop()
	stopCh := m.stopCh
	m.mu.Unlock()

	// Create channel for raw events from reader
	rawEvents := make(chan RawFlowEvent, 1000)

	// Get boot time for timestamp conversion
	bootTime := getBootTime()

	// Start the platform-specific reader
	go func() {
		err := m.reader.Start(ctx, rawEvents)
		close(rawEvents)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logging.Warnf("Flow reader error: %v", err)
		}
	}()

	// Process events and distribute to subscribers
	go m.processEvents(ctx, rawEvents, bootTime, stopCh)

	logging.Info("Flow monitor started", nil)
	return nil
}

// Stop stops the flow monitor.
func (m *Monitor) Stop() error {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = false

	// Close stopCh to signal processEvents to exit
	select {
	case <-m.stopCh:
		// Already closed
	default:
		close(m.stopCh)
	}

	// Close all subscriber channels under the lock
	for _, sub := range m.subscribers {
		if !sub.closed {
			sub.closed = true
			close(sub.ch)
		}
	}
	m.subscribers = make(map[uint64]*subscriber)

	// Recreate stopCh for potential restart
	m.stopCh = make(chan struct{})
	m.mu.Unlock()

	if err := m.reader.Stop(); err != nil {
		return err
	}

	logging.Info("Flow monitor stopped", nil)
	return nil
}

// Subscribe returns a channel that receives flow events.
func (m *Monitor) Subscribe(ctx context.Context) <-chan FlowEvent {
	ch := make(chan FlowEvent, 100)

	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		close(ch)
		return ch
	}
	m.nextSubID++
	sub := &subscriber{id: m.nextSubID, ch: ch}
	m.subscribers[sub.id] = sub
	m.mu.Unlock()

	// Handle context cancellation
	go func() {
		<-ctx.Done()
		m.mu.Lock()
		defer m.mu.Unlock()

		// Remove this subscriber and close the channel if not already closed
		if tracked, ok := m.subscribers[sub.id]; ok {
			delete(m.subscribers, sub.id)
			if !tracked.closed {
				tracked.closed = true
				close(tracked.ch)
			}
		}
	}()

	return ch
}

// GetStats returns current flow statistics.
func (m *Monitor) GetStats() FlowStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := m.stats
	if !stats.MonitorStarted.IsZero() {
		elapsed := time.Since(stats.MonitorStarted).Seconds()
		if elapsed > 0 {
			stats.EventsPerSec = float64(stats.TotalEvents) / elapsed
		}
	}
	return stats
}

// IsRunning returns true if the monitor is actively running.
func (m *Monitor) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// processEvents converts raw events and distributes to subscribers.
func (m *Monitor) processEvents(ctx context.Context, rawEvents <-chan RawFlowEvent, bootTime time.Time, stopCh <-chan struct{}) {
	for {
		select {
		case <-stopCh:
			return
		case <-ctx.Done():
			return
		case raw, ok := <-rawEvents:
			if !ok {
				return
			}

			event := raw.ToFlowEvent(bootTime)

			// Update stats under write lock.
			m.mu.Lock()
			m.stats.TotalEvents++
			m.stats.LastEventTime = event.Timestamp
			if event.Action == "allowed" {
				m.stats.AllowedEvents++
			} else {
				m.stats.BlockedEvents++
			}
			if event.Direction == "egress" {
				m.stats.EgressEvents++
			} else {
				m.stats.IngressEvents++
			}
			m.mu.Unlock()

			// Broadcast under read lock to avoid writer contention.
			m.mu.RLock()
			for _, sub := range m.subscribers {
				if !sub.closed {
					select {
					case sub.ch <- event:
					default:
						// Drop event if subscriber is slow
					}
				}
			}
			m.mu.RUnlock()
		}
	}
}

// getBootTime returns the system boot time for converting kernel timestamps.
func getBootTime() time.Time {
	// Kernel timestamps from bpf_ktime_get_ns() are nanoseconds since boot.
	// We need the boot time to convert to wall clock time.
	// This is a simplified approach - on Linux we could read /proc/uptime.
	return time.Now().Add(-time.Duration(uptimeNsFunc()))
}

var uptimeNsFunc = func() int64 { return 0 }
