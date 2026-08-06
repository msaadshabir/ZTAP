package alert

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

type ManagerOptions struct {
	Dispatcher *Dispatcher
	DedupeTTL  time.Duration
}

type Manager struct {
	dispatcher *Dispatcher
	dedupeTTL  time.Duration
	mu         sync.Mutex
	seen       map[string]time.Time
	startOnce  sync.Once
}

func NewManager(opts ManagerOptions) (*Manager, error) {
	if opts.Dispatcher == nil {
		return nil, errors.New("dispatcher is required")
	}

	return &Manager{
		dispatcher: opts.Dispatcher,
		dedupeTTL:  opts.DedupeTTL,
		seen:       make(map[string]time.Time),
	}, nil
}

func (m *Manager) Start(ctx context.Context) {
	m.startOnce.Do(func() {
		m.dispatcher.Start(ctx)
		if m.dedupeTTL > 0 {
			go m.gc(ctx)
		}
	})
}

func (m *Manager) Emit(a Alert) bool {
	if m.shouldDrop(a) {
		return false
	}
	return m.dispatcher.Emit(a)
}

func (m *Manager) Dropped() uint64 {
	return m.dispatcher.Dropped()
}

func (m *Manager) Close() {
	m.dispatcher.Close()
}

func (m *Manager) shouldDrop(a Alert) bool {
	if m.dedupeTTL <= 0 {
		return false
	}
	key := strings.TrimSpace(a.DedupKey)
	if key == "" {
		return false
	}

	now := time.Now()
	cutoff := now.Add(-m.dedupeTTL)

	m.mu.Lock()
	defer m.mu.Unlock()

	if ts, ok := m.seen[key]; ok && ts.After(cutoff) {
		return true
	}

	m.seen[key] = now
	return false
}

func (m *Manager) gc(ctx context.Context) {
	ticker := time.NewTicker(m.dedupeTTL)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.prune(time.Now())
		}
	}
}

func (m *Manager) prune(now time.Time) {
	if m.dedupeTTL <= 0 {
		return
	}
	cutoff := now.Add(-m.dedupeTTL)

	m.mu.Lock()
	for k, ts := range m.seen {
		if ts.Before(cutoff) {
			delete(m.seen, k)
		}
	}
	m.mu.Unlock()
}
