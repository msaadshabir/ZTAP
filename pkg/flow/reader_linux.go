//go:build linux
// +build linux

package flow

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"

	"ztap/pkg/logging"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// LinuxReader reads flow events from the eBPF ring buffer on Linux.
type LinuxReader struct {
	mu      sync.Mutex
	ringbuf *ringbuf.Reader
	flowMap *ebpf.Map
	running bool
	stopCh  chan struct{}
}

// NewLinuxReader creates a new Linux flow reader.
// The flowEventsMap should be the "flow_events" ring buffer from the loaded eBPF program.
func NewLinuxReader(flowEventsMap *ebpf.Map) (*LinuxReader, error) {
	if flowEventsMap == nil {
		return nil, errors.New("flow_events map is nil")
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
		flowMap: flowEventsMap,
		stopCh:  make(chan struct{}),
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

	logging.Info("Linux flow reader started", nil)

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
				logging.Warnf("Error reading from ring buffer: %v", err)
				continue
			}

			// Parse the raw event
			event, err := parseRawEvent(record.RawSample)
			if err != nil {
				logging.Warnf("Error parsing flow event: %v", err)
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

	logging.Info("Linux flow reader stopped", nil)
	return nil
}

// Available returns true since this is the Linux implementation.
func (r *LinuxReader) Available() bool {
	return true
}

// parseRawEvent parses a raw ring buffer record into a RawFlowEvent.
func parseRawEvent(data []byte) (RawFlowEvent, error) {
	if len(data) < 48 {
		return RawFlowEvent{}, fmt.Errorf("event data too short: %d bytes", len(data))
	}

	event := RawFlowEvent{}
	event.TimestampNs = binary.LittleEndian.Uint64(data[0:8])

	for i := 0; i < 4; i++ {
		start := 8 + i*4
		event.SrcIP[i] = binary.LittleEndian.Uint32(data[start : start+4])
	}
	for i := 0; i < 4; i++ {
		start := 24 + i*4
		event.DestIP[i] = binary.LittleEndian.Uint32(data[start : start+4])
	}

	event.SrcPort = binary.LittleEndian.Uint16(data[40:42])
	event.DestPort = binary.LittleEndian.Uint16(data[42:44])
	event.Protocol = data[44]
	event.Direction = data[45]
	event.Action = data[46]
	event.Family = data[47]

	return event, nil
}

// CreateFlowReader creates a flow reader for the given eBPF flow_events map.
// This is the entry point for platform-specific reader creation.
func CreateFlowReader(flowEventsMap *ebpf.Map) (FlowReader, error) {
	return NewLinuxReader(flowEventsMap)
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

func init() {
	uptimeNsFunc = GetLinuxUptimeNs
}
