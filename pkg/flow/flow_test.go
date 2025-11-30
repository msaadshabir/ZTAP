package flow

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

func TestFlowEventConversion(t *testing.T) {
	bootTime := time.Now().Add(-1 * time.Hour)

	tests := []struct {
		name     string
		raw      RawFlowEvent
		expected FlowEvent
	}{
		{
			name: "TCP egress allowed",
			raw: RawFlowEvent{
				TimestampNs: uint64(1 * time.Second),
				SrcIP:       0x0A000101, // 10.0.1.1 in big-endian
				DestIP:      0x0A000201, // 10.0.2.1
				SrcPort:     45678,
				DestPort:    5432,
				Protocol:    ProtocolTCP,
				Direction:   DirectionEgress,
				Action:      ActionAllowed,
			},
			expected: FlowEvent{
				SourceIP:   net.IPv4(10, 0, 1, 1),
				DestIP:     net.IPv4(10, 0, 2, 1),
				SourcePort: 45678,
				DestPort:   5432,
				Protocol:   "TCP",
				Direction:  "egress",
				Action:     "allowed",
			},
		},
		{
			name: "UDP ingress blocked",
			raw: RawFlowEvent{
				TimestampNs: uint64(2 * time.Second),
				SrcIP:       0xC0A80164, // 192.168.1.100
				DestIP:      0x0A000101,
				SrcPort:     53421,
				DestPort:    53,
				Protocol:    ProtocolUDP,
				Direction:   DirectionIngress,
				Action:      ActionBlocked,
			},
			expected: FlowEvent{
				SourceIP:   net.IPv4(192, 168, 1, 100),
				DestIP:     net.IPv4(10, 0, 1, 1),
				SourcePort: 53421,
				DestPort:   53,
				Protocol:   "UDP",
				Direction:  "ingress",
				Action:     "blocked",
			},
		},
		{
			name: "ICMP egress",
			raw: RawFlowEvent{
				TimestampNs: uint64(3 * time.Second),
				SrcIP:       0x0A000101,
				DestIP:      0x08080808, // 8.8.8.8
				SrcPort:     0,
				DestPort:    0,
				Protocol:    ProtocolICMP,
				Direction:   DirectionEgress,
				Action:      ActionAllowed,
			},
			expected: FlowEvent{
				SourceIP:   net.IPv4(10, 0, 1, 1),
				DestIP:     net.IPv4(8, 8, 8, 8),
				SourcePort: 0,
				DestPort:   0,
				Protocol:   "ICMP",
				Direction:  "egress",
				Action:     "allowed",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.raw.ToFlowEvent(bootTime)
			if !result.SourceIP.Equal(tt.expected.SourceIP) {
				t.Errorf("SourceIP = %v, want %v", result.SourceIP, tt.expected.SourceIP)
			}
			if !result.DestIP.Equal(tt.expected.DestIP) {
				t.Errorf("DestIP = %v, want %v", result.DestIP, tt.expected.DestIP)
			}
			if result.SourcePort != tt.expected.SourcePort {
				t.Errorf("SourcePort = %d, want %d", result.SourcePort, tt.expected.SourcePort)
			}
			if result.DestPort != tt.expected.DestPort {
				t.Errorf("DestPort = %d, want %d", result.DestPort, tt.expected.DestPort)
			}
			if result.Protocol != tt.expected.Protocol {
				t.Errorf("Protocol = %s, want %s", result.Protocol, tt.expected.Protocol)
			}
			if result.Direction != tt.expected.Direction {
				t.Errorf("Direction = %s, want %s", result.Direction, tt.expected.Direction)
			}
			if result.Action != tt.expected.Action {
				t.Errorf("Action = %s, want %s", result.Action, tt.expected.Action)
			}
		})
	}
}

func TestFlowFilter(t *testing.T) {
	event := FlowEvent{
		Timestamp:  time.Now(),
		SourceIP:   net.IPv4(10, 0, 1, 1),
		DestIP:     net.IPv4(10, 0, 2, 1),
		SourcePort: 45678,
		DestPort:   5432,
		Protocol:   "TCP",
		Direction:  "egress",
		Action:     "allowed",
	}

	tests := []struct {
		name    string
		filter  FlowFilter
		matches bool
	}{
		{
			name:    "empty filter matches all",
			filter:  FlowFilter{},
			matches: true,
		},
		{
			name:    "action filter matches",
			filter:  FlowFilter{Action: "allowed"},
			matches: true,
		},
		{
			name:    "action filter no match",
			filter:  FlowFilter{Action: "blocked"},
			matches: false,
		},
		{
			name:    "protocol filter matches",
			filter:  FlowFilter{Protocol: "TCP"},
			matches: true,
		},
		{
			name:    "protocol filter no match",
			filter:  FlowFilter{Protocol: "UDP"},
			matches: false,
		},
		{
			name:    "direction filter matches",
			filter:  FlowFilter{Direction: "egress"},
			matches: true,
		},
		{
			name:    "direction filter no match",
			filter:  FlowFilter{Direction: "ingress"},
			matches: false,
		},
		{
			name:    "source IP filter matches",
			filter:  FlowFilter{SourceIP: net.IPv4(10, 0, 1, 1)},
			matches: true,
		},
		{
			name:    "source IP filter no match",
			filter:  FlowFilter{SourceIP: net.IPv4(192, 168, 1, 1)},
			matches: false,
		},
		{
			name:    "port filter matches source",
			filter:  FlowFilter{Port: 45678},
			matches: true,
		},
		{
			name:    "port filter matches dest",
			filter:  FlowFilter{Port: 5432},
			matches: true,
		},
		{
			name:    "port filter no match",
			filter:  FlowFilter{Port: 80},
			matches: false,
		},
		{
			name:    "combined filters match",
			filter:  FlowFilter{Action: "allowed", Protocol: "TCP", Direction: "egress"},
			matches: true,
		},
		{
			name:    "combined filters partial no match",
			filter:  FlowFilter{Action: "allowed", Protocol: "UDP", Direction: "egress"},
			matches: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.filter.Matches(event)
			if result != tt.matches {
				t.Errorf("Matches() = %v, want %v", result, tt.matches)
			}
		})
	}
}

// testReader is a simple reader for testing that sends pre-configured events.
type testReader struct {
	mu      sync.Mutex
	events  []RawFlowEvent
	running bool
}

func (r *testReader) Start(ctx context.Context, eventCh chan<- RawFlowEvent) error {
	r.mu.Lock()
	r.running = true
	r.mu.Unlock()

	for _, event := range r.events {
		event.TimestampNs = uint64(time.Now().UnixNano())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case eventCh <- event:
		}
	}
	// Keep running until context cancelled
	<-ctx.Done()
	return ctx.Err()
}

func (r *testReader) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running = false
	return nil
}

func (r *testReader) Available() bool {
	return true
}

func TestMonitorSubscription(t *testing.T) {
	// Create a mock reader that sends events with delay
	events := []RawFlowEvent{
		{
			TimestampNs: uint64(time.Now().UnixNano()),
			SrcIP:       0x0A000101,
			DestIP:      0x0A000201,
			SrcPort:     45678,
			DestPort:    5432,
			Protocol:    ProtocolTCP,
			Direction:   DirectionEgress,
			Action:      ActionAllowed,
		},
		{
			TimestampNs: uint64(time.Now().UnixNano()),
			SrcIP:       0xC0A80164,
			DestIP:      0x0A000101,
			SrcPort:     53421,
			DestPort:    22,
			Protocol:    ProtocolTCP,
			Direction:   DirectionIngress,
			Action:      ActionBlocked,
		},
	}
	reader := &delayedReader{events: events, delay: 100 * time.Millisecond}
	monitor := NewMonitor(reader)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start monitor first
	if err := monitor.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	defer func() { _ = monitor.Stop() }()

	// Subscribe after starting (monitor is now running)
	eventCh := monitor.Subscribe(ctx)

	// Collect events
	received := make([]FlowEvent, 0)
	timeout := time.After(1 * time.Second)
loop:
	for {
		select {
		case event, ok := <-eventCh:
			if !ok {
				break loop
			}
			received = append(received, event)
			if len(received) >= len(events) {
				break loop
			}
		case <-timeout:
			break loop
		}
	}

	// Verify we received events
	if len(received) == 0 {
		t.Error("Expected to receive events, got none")
	}

	// Check stats
	stats := monitor.GetStats()
	if stats.TotalEvents == 0 {
		t.Error("Expected TotalEvents > 0")
	}
}

// delayedReader sends events with a delay to allow subscribers to connect
type delayedReader struct {
	mu      sync.Mutex
	events  []RawFlowEvent
	delay   time.Duration
	running bool
}

func (r *delayedReader) Start(ctx context.Context, eventCh chan<- RawFlowEvent) error {
	r.mu.Lock()
	r.running = true
	r.mu.Unlock()

	// Wait a bit to ensure subscriber is connected
	time.Sleep(r.delay)
	for _, event := range r.events {
		event.TimestampNs = uint64(time.Now().UnixNano())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case eventCh <- event:
		}
		time.Sleep(10 * time.Millisecond) // Small delay between events
	}
	// Keep running until context cancelled
	<-ctx.Done()
	return ctx.Err()
}

func (r *delayedReader) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running = false
	return nil
}

func (r *delayedReader) Available() bool {
	return true
}

func TestMonitorStats(t *testing.T) {
	reader := &testReader{events: []RawFlowEvent{
		{Protocol: ProtocolTCP, Direction: DirectionEgress, Action: ActionAllowed},
		{Protocol: ProtocolTCP, Direction: DirectionEgress, Action: ActionBlocked},
		{Protocol: ProtocolUDP, Direction: DirectionIngress, Action: ActionAllowed},
	}}
	monitor := NewMonitor(reader)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_ = monitor.Start(ctx)
	defer func() { _ = monitor.Stop() }()

	// Subscribe and drain events
	eventCh := monitor.Subscribe(ctx)
	count := 0
	timeout := time.After(1 * time.Second)
loop:
	for {
		select {
		case _, ok := <-eventCh:
			if !ok {
				break loop
			}
			count++
			if count >= 3 {
				break loop
			}
		case <-timeout:
			break loop
		}
	}

	stats := monitor.GetStats()
	if stats.AllowedEvents != 2 {
		t.Errorf("AllowedEvents = %d, want 2", stats.AllowedEvents)
	}
	if stats.BlockedEvents != 1 {
		t.Errorf("BlockedEvents = %d, want 1", stats.BlockedEvents)
	}
	if stats.EgressEvents != 2 {
		t.Errorf("EgressEvents = %d, want 2", stats.EgressEvents)
	}
	if stats.IngressEvents != 1 {
		t.Errorf("IngressEvents = %d, want 1", stats.IngressEvents)
	}
}

func TestProtocolToString(t *testing.T) {
	tests := []struct {
		proto    uint8
		expected string
	}{
		{ProtocolTCP, "TCP"},
		{ProtocolUDP, "UDP"},
		{ProtocolICMP, "ICMP"},
		{99, "UNKNOWN"},
	}

	for _, tt := range tests {
		result := protocolToString(tt.proto)
		if result != tt.expected {
			t.Errorf("protocolToString(%d) = %s, want %s", tt.proto, result, tt.expected)
		}
	}
}

func TestUint32ToIP(t *testing.T) {
	tests := []struct {
		input    uint32
		expected net.IP
	}{
		{0x0A000101, net.IPv4(10, 0, 1, 1)},
		{0xC0A80164, net.IPv4(192, 168, 1, 100)},
		{0x08080808, net.IPv4(8, 8, 8, 8)},
		{0x00000000, net.IPv4(0, 0, 0, 0)},
		{0xFFFFFFFF, net.IPv4(255, 255, 255, 255)},
	}

	for _, tt := range tests {
		result := uint32ToIP(tt.input)
		if !result.Equal(tt.expected) {
			t.Errorf("uint32ToIP(0x%08X) = %v, want %v", tt.input, result, tt.expected)
		}
	}
}
