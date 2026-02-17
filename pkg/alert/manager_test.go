package alert

import (
	"context"
	"testing"
	"time"
)

func TestManagerNewRequiresDispatcher(t *testing.T) {
	if _, err := NewManager(ManagerOptions{}); err == nil {
		t.Fatalf("expected error for missing dispatcher")
	}
}

func TestManagerStartAndEmit(t *testing.T) {
	sink := &recordingSink{}
	d, err := NewDispatcher(DispatcherOptions{Sinks: []Sink{sink}, QueueSize: 10, Workers: 1, Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	m, err := NewManager(ManagerOptions{Dispatcher: d, DedupeTTL: 0})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)

	if ok := m.Emit(Alert{Source: "test", Severity: SeverityInfo, Title: "t", Message: "m"}); !ok {
		t.Fatalf("expected emit to succeed")
	}
	m.Close()
}

func TestManagerDedupeDrops(t *testing.T) {
	sink := &recordingSink{}
	d, err := NewDispatcher(DispatcherOptions{Sinks: []Sink{sink}, QueueSize: 10, Workers: 1, Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	m, err := NewManager(ManagerOptions{Dispatcher: d, DedupeTTL: 1 * time.Hour})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)

	alert := Alert{Source: "test", Severity: SeverityInfo, Title: "t", Message: "m", DedupKey: "dup"}
	if ok := m.Emit(alert); !ok {
		t.Fatalf("expected first emit ok")
	}
	if ok := m.Emit(alert); ok {
		t.Fatalf("expected second emit to be dropped")
	}
}

func TestManagerDedupeExpires(t *testing.T) {
	sink := &recordingSink{}
	d, err := NewDispatcher(DispatcherOptions{Sinks: []Sink{sink}, QueueSize: 10, Workers: 1, Timeout: 100 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	m, err := NewManager(ManagerOptions{Dispatcher: d, DedupeTTL: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)

	alert := Alert{Source: "test", Severity: SeverityInfo, Title: "t", Message: "m", DedupKey: "dup"}
	if ok := m.Emit(alert); !ok {
		t.Fatalf("expected first emit ok")
	}

	// Force prune to clear the dedupe entry.
	m.prune(time.Now().Add(1 * time.Hour))
	if ok := m.Emit(alert); !ok {
		t.Fatalf("expected emit after prune")
	}
}
