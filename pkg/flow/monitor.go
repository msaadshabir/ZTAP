package flow

import (
	"context"
	"log"
	"sync"
	"time"
)

// Monitor implements FlowMonitor with subscriber management.
type Monitor struct {
	mu          sync.RWMutex
	running     bool
	stopCh      chan struct{}
	subscribers []chan FlowEvent
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
		subscribers: make([]chan FlowEvent, 0),
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
		if err := m.reader.Start(ctx, rawEvents); err != nil {
			log.Printf("Flow reader error: %v", err)
		}
	}()

	// Process events and distribute to subscribers
	go m.processEvents(ctx, rawEvents, bootTime, stopCh)

	log.Println("Flow monitor started")
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

	// Copy subscribers to close outside lock to prevent deadlock
	subsToClose := make([]chan FlowEvent, len(m.subscribers))
	copy(subsToClose, m.subscribers)
	m.subscribers = make([]chan FlowEvent, 0)

	// Recreate stopCh for potential restart
	m.stopCh = make(chan struct{})
	m.mu.Unlock()

	// Close subscriber channels outside the lock
	for _, ch := range subsToClose {
		close(ch)
	}

	if err := m.reader.Stop(); err != nil {
		return err
	}

	log.Println("Flow monitor stopped")
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
	m.subscribers = append(m.subscribers, ch)
	m.mu.Unlock()

	// Handle context cancellation
	go func() {
		<-ctx.Done()
		m.mu.Lock()
		defer m.mu.Unlock()

		// Remove this subscriber and close the channel
		for i, sub := range m.subscribers {
			if sub == ch {
				m.subscribers = append(m.subscribers[:i], m.subscribers[i+1:]...)
				// Safe close - only close if we removed it (not already closed by Stop)
				select {
				case <-ch:
					// Channel already closed or has data, try to close
				default:
				}
				// Use recover to handle double-close panic
				func() {
					defer func() { _ = recover() }()
					close(ch)
				}()
				break
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

			// Update stats
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

			// Broadcast to subscribers
			for _, ch := range m.subscribers {
				select {
				case ch <- event:
				default:
					// Drop event if subscriber is slow
				}
			}
			m.mu.Unlock()
		}
	}
}

// getBootTime returns the system boot time for converting kernel timestamps.
func getBootTime() time.Time {
	// Kernel timestamps from bpf_ktime_get_ns() are nanoseconds since boot.
	// We need the boot time to convert to wall clock time.
	// This is a simplified approach - on Linux we could read /proc/uptime.
	return time.Now().Add(-time.Duration(getUptimeNs()))
}

// getUptimeNs returns system uptime in nanoseconds.
// Platform-specific implementations can override this.
func getUptimeNs() int64 {
	// Default: return 0 (assumes boot time is now)
	// The reader_linux.go will provide a proper implementation
	return 0
}
