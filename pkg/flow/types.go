package flow

import (
	"context"
	"net"
	"time"
)

// Direction constants matching eBPF program
const (
	DirectionEgress  = 0
	DirectionIngress = 1
)

// Action constants matching eBPF program
const (
	ActionBlocked = 0
	ActionAllowed = 1
)

// Protocol constants
const (
	ProtocolICMP = 1
	ProtocolTCP  = 6
	ProtocolUDP  = 17
)

// FlowEvent represents a network flow event from the eBPF program.
// This structure matches the flow_event struct in bpf/filter.c.
type FlowEvent struct {
	Timestamp  time.Time // Event timestamp
	SourceIP   net.IP    // Source IP address
	DestIP     net.IP    // Destination IP address
	SourcePort uint16    // Source port
	DestPort   uint16    // Destination port
	Protocol   string    // Protocol name: "TCP", "UDP", "ICMP"
	Direction  string    // "egress" or "ingress"
	Action     string    // "allowed" or "blocked"
}

// RawFlowEvent is the raw structure from eBPF ring buffer.
// Must match struct flow_event in bpf/filter.c exactly.
type RawFlowEvent struct {
	TimestampNs uint64    // Kernel timestamp in nanoseconds
	SrcIP       [4]uint32 // Source IP (v4 uses first word)
	DestIP      [4]uint32 // Destination IP (v4 uses first word)
	SrcPort     uint16    // Source port
	DestPort    uint16    // Destination port
	Protocol    uint8     // Protocol number
	Direction   uint8     // 0=egress, 1=ingress
	Action      uint8     // 0=blocked, 1=allowed
	Family      uint8     // 4=IPv4, 6=IPv6
}

// ToFlowEvent converts a raw eBPF event to a FlowEvent.
func (r *RawFlowEvent) ToFlowEvent(bootTime time.Time) FlowEvent {
	// time.Duration is int64 nanoseconds; clamp to avoid overflow.
	ns := r.TimestampNs
	const maxInt64 = int64(^uint64(0) >> 1)
	if ns > uint64(maxInt64) {
		ns = uint64(maxInt64)
	}
	return FlowEvent{
		Timestamp:  bootTime.Add(time.Duration(int64(ns))), // #nosec G115 -- ns is clamped to max int64 above
		SourceIP:   uint32ArrayToIP(r.SrcIP, r.Family),
		DestIP:     uint32ArrayToIP(r.DestIP, r.Family),
		SourcePort: r.SrcPort,
		DestPort:   r.DestPort,
		Protocol:   protocolToString(r.Protocol),
		Direction:  directionToString(r.Direction),
		Action:     actionToString(r.Action),
	}
}

// FlowStats provides aggregate statistics about flow events.
type FlowStats struct {
	TotalEvents    uint64
	AllowedEvents  uint64
	BlockedEvents  uint64
	EgressEvents   uint64
	IngressEvents  uint64
	EventsPerSec   float64
	LastEventTime  time.Time
	MonitorStarted time.Time
}

// FlowMonitor is the interface for flow event monitoring.
type FlowMonitor interface {
	// Start begins monitoring flow events.
	Start(ctx context.Context) error
	// Stop stops the flow monitor.
	Stop() error
	// Subscribe returns a channel that receives flow events.
	// The channel is closed when the context is cancelled or Stop is called.
	Subscribe(ctx context.Context) <-chan FlowEvent
	// GetStats returns current flow statistics.
	GetStats() FlowStats
	// IsRunning returns true if the monitor is actively running.
	IsRunning() bool
}

// FlowFilter defines criteria for filtering flow events.
type FlowFilter struct {
	Action    string // "allowed", "blocked", or empty for all
	Direction string // "egress", "ingress", or empty for all
	Protocol  string // "TCP", "UDP", "ICMP", or empty for all
	SourceIP  net.IP // Filter by source IP, nil for all
	DestIP    net.IP // Filter by destination IP, nil for all
	Port      uint16 // Filter by port (src or dest), 0 for all
}

// Matches returns true if the flow event matches the filter criteria.
func (f *FlowFilter) Matches(event FlowEvent) bool {
	if f.Action != "" && f.Action != event.Action {
		return false
	}
	if f.Direction != "" && f.Direction != event.Direction {
		return false
	}
	if f.Protocol != "" && f.Protocol != event.Protocol {
		return false
	}
	if f.SourceIP != nil && !f.SourceIP.Equal(event.SourceIP) {
		return false
	}
	if f.DestIP != nil && !f.DestIP.Equal(event.DestIP) {
		return false
	}
	if f.Port != 0 && f.Port != event.SourcePort && f.Port != event.DestPort {
		return false
	}
	return true
}

// uint32ToIP converts a uint32 IP address from network byte order (big-endian) to net.IP.
// Network byte order stores the most significant byte first, so 10.0.1.1 is stored as 0x0A000101.
func uint32ToIP(ip uint32) net.IP {
	return net.IPv4(
		byte(ip>>24),
		byte(ip>>16),
		byte(ip>>8),
		byte(ip),
	)
}

func uint32ArrayToIP(ip [4]uint32, family uint8) net.IP {
	if family == 6 {
		res := make(net.IP, 16)
		for i := 0; i < 4; i++ {
			res[i*4] = byte(ip[i])
			res[i*4+1] = byte(ip[i] >> 8)
			res[i*4+2] = byte(ip[i] >> 16)
			res[i*4+3] = byte(ip[i] >> 24)
		}
		return res
	}
	return uint32ToIP(ip[0]) //nolint:gosec // ip is a fixed-length array; index 0 is always valid
}

func protocolToString(proto uint8) string {
	switch proto {
	case ProtocolTCP:
		return "TCP"
	case ProtocolUDP:
		return "UDP"
	case ProtocolICMP:
		return "ICMP"
	default:
		return "UNKNOWN"
	}
}

func directionToString(dir uint8) string {
	if dir == DirectionEgress {
		return "egress"
	}
	return "ingress"
}

func actionToString(action uint8) string {
	if action == ActionAllowed {
		return "allowed"
	}
	return "blocked"
}
