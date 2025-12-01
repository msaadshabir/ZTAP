//go:build linux
// +build linux

package flow

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// LinuxReader reads flow events from the eBPF ring buffer on Linux.
type LinuxReader struct {
	mu       sync.Mutex
	ringbuf  *ringbuf.Reader
	flowMap  *ebpf.Map
	running  bool
	stopCh   chan struct{}
	bootTime int64 // nanoseconds since epoch at boot
}

// NewLinuxReader creates a new Linux flow reader.
// The flowEventsMap should be the "flow_events" ring buffer from the loaded eBPF program.
func NewLinuxReader(flowEventsMap *ebpf.Map) (*LinuxReader, error) {
	if flowEventsMap == nil {
		return nil, fmt.Errorf("flow_events map is nil")
	}

	// Verify it's a ring buffer
	info, err := flowEventsMap.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to get map info: %w", err)
	}
	if info.Type != ebpf.RingBuf {
		return nil, fmt.Errorf("expected RingBuf map, got %s", info.Type)
	}

	return &LinuxReader{
		flowMap:  flowEventsMap,
		stopCh:   make(chan struct{}),
		bootTime: getBootTimeNs(),
	}, nil
}

// Start begins reading flow events from the ring buffer.
func (r *LinuxReader) Start(ctx context.Context, eventCh chan<- RawFlowEvent) error {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return nil
	}

	reader, err := ringbuf.NewReader(r.flowMap)
	if err != nil {
		r.mu.Unlock()
		return fmt.Errorf("failed to create ring buffer reader: %w", err)
	}
	r.ringbuf = reader
	r.running = true
	r.mu.Unlock()

	log.Println("Linux flow reader started")

	// Read events in a loop
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.stopCh:
			return nil
		default:
			record, err := reader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return nil
				}
				log.Printf("Error reading from ring buffer: %v", err)
				continue
			}

			// Parse the raw event
			event, err := parseRawEvent(record.RawSample)
			if err != nil {
				log.Printf("Error parsing flow event: %v", err)
				continue
			}

			// Send to channel (non-blocking)
			select {
			case eventCh <- event:
			default:
				// Drop if channel is full
			}
		}
	}
}

// Stop stops the reader.
func (r *LinuxReader) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running {
		return nil
	}
	r.running = false
	close(r.stopCh)

	if r.ringbuf != nil {
		if err := r.ringbuf.Close(); err != nil {
			return fmt.Errorf("failed to close ring buffer: %w", err)
		}
	}

	log.Println("Linux flow reader stopped")
	return nil
}

// Available returns true since this is the Linux implementation.
func (r *LinuxReader) Available() bool {
	return true
}

// parseRawEvent parses a raw ring buffer record into a RawFlowEvent.
func parseRawEvent(data []byte) (RawFlowEvent, error) {
	if len(data) < 24 {
		return RawFlowEvent{}, fmt.Errorf("event data too short: %d bytes", len(data))
	}

	// Parse according to struct flow_event layout in filter.c
	// Timestamp: native byte order (little-endian on x86/ARM)
	// IPs: network byte order (big-endian) as received from kernel
	// Ports: host byte order (little-endian) - already converted by bpf_ntohs in eBPF
	event := RawFlowEvent{
		TimestampNs: binary.LittleEndian.Uint64(data[0:8]),
		SrcIP:       binary.BigEndian.Uint32(data[8:12]),     // Network byte order
		DestIP:      binary.BigEndian.Uint32(data[12:16]),    // Network byte order
		SrcPort:     binary.LittleEndian.Uint16(data[16:18]), // Host byte order (converted by bpf_ntohs)
		DestPort:    binary.LittleEndian.Uint16(data[18:20]), // Host byte order (converted by bpf_ntohs)
		Protocol:    data[20],
		Direction:   data[21],
		Action:      data[22],
		Pad:         data[23],
	}

	return event, nil
}

// getBootTimeNs returns the boot time in nanoseconds since Unix epoch.
func getBootTimeNs() int64 {
	var info syscall.Sysinfo_t
	if err := syscall.Sysinfo(&info); err != nil {
		return 0
	}
	return int64(info.Uptime) * 1e9
}

// CreateFlowReader creates a flow reader for the given eBPF flow_events map.
// This is the entry point for platform-specific reader creation.
func CreateFlowReader(flowEventsMap *ebpf.Map) (FlowReader, error) {
	return NewLinuxReader(flowEventsMap)
}

// SimulatedReader provides a simulated flow reader for testing.
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

// Available returns true.
func (r *SimulatedReader) Available() bool {
	return true
}

// init registers the Linux-specific uptime function.
func init() {
	// Override the default getUptimeNs in monitor.go
	// This is done via a package-level function registration
}

// GetLinuxUptimeNs returns uptime in nanoseconds on Linux.
func GetLinuxUptimeNs() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	var uptime float64
	if _, err := fmt.Sscanf(string(data), "%f", &uptime); err != nil {
		return 0
	}
	return int64(uptime * 1e9)
}
