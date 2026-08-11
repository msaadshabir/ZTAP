//go:build linux
// +build linux

package cli

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"ztap/internal/enforcer"
	"ztap/internal/flow"

	"github.com/cilium/ebpf"
)

type mapOwningReader struct {
	inner flow.FlowReader
	m     *ebpf.Map
}

func (r *mapOwningReader) Start(ctx context.Context, eventCh chan<- flow.RawFlowEvent) error {
	return r.inner.Start(ctx, eventCh)
}

func (r *mapOwningReader) Stop() error {
	err := r.inner.Stop()
	if r.m != nil {
		if closeErr := r.m.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}
	return err
}

func (r *mapOwningReader) Available() bool {
	return r.inner.Available()
}

func openPinnedFlowReader() (flow.FlowReader, error) {
	m, err := ebpf.LoadPinnedMap(enforcer.DefaultFlowEventsPinPath, nil)
	if err != nil {
		return nil, fmt.Errorf("loading pinned flow map %s: %w", enforcer.DefaultFlowEventsPinPath, err)
	}

	reader, err := flow.CreateFlowReader(m)
	if err != nil {
		if closeErr := m.Close(); closeErr != nil {
			return nil, fmt.Errorf("creating linux flow reader: %w (closing map: %v)", err, closeErr)
		}
		return nil, fmt.Errorf("creating linux flow reader: %w", err)
	}

	return &mapOwningReader{inner: reader, m: m}, nil
}

// createFlowReader retains the synthetic fallback for the interactive `flows`
// command. Anomaly detection uses createAnomalyFlowReader instead and never
// treats demo events as observed network traffic.
func createFlowReader() flow.FlowReader {
	reader, err := openPinnedFlowReader()
	if err == nil {
		return reader
	}
	fmt.Fprintf(os.Stderr, "note: using simulated flows (%v; run 'ztap enforce' first)\n", err)
	return flow.NewSimulatedReader(generateRawDemoFlows(), 500*time.Millisecond)
}

// createAnomalyFlowReader returns a reader that waits for the real pinned map
// to become available. This covers agent startup, where policy enforcement may
// pin the map shortly after the anomaly runner starts, without ever emitting
// synthetic events.
func createAnomalyFlowReader() (flow.FlowReader, error) {
	return &retryingAnomalyReader{}, nil
}

type retryingAnomalyReader struct {
	mu     sync.Mutex
	inner  flow.FlowReader
	stopCh chan struct{}
}

func (r *retryingAnomalyReader) Start(ctx context.Context, eventCh chan<- flow.RawFlowEvent) error {
	r.mu.Lock()
	stopCh := make(chan struct{})
	r.stopCh = stopCh
	r.mu.Unlock()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var lastLog time.Time

	for {
		reader, err := openPinnedFlowReader()
		if err == nil {
			r.mu.Lock()
			r.inner = reader
			r.mu.Unlock()

			startErr := reader.Start(ctx, eventCh)
			_ = reader.Stop()
			r.mu.Lock()
			if r.inner == reader {
				r.inner = nil
			}
			if r.stopCh == stopCh {
				r.stopCh = nil
			}
			r.mu.Unlock()
			return startErr
		}

		if lastLog.IsZero() || time.Since(lastLog) >= 10*time.Second {
			fmt.Fprintf(os.Stderr, "note: anomaly flow reader waiting for %s: %v\n", enforcer.DefaultFlowEventsPinPath, err)
			lastLog = time.Now()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-stopCh:
			return nil
		case <-ticker.C:
		}
	}
}

func (r *retryingAnomalyReader) Stop() error {
	r.mu.Lock()
	stopCh := r.stopCh
	if stopCh != nil {
		close(stopCh)
		r.stopCh = nil
	}
	inner := r.inner
	r.inner = nil
	r.mu.Unlock()
	if inner != nil {
		return inner.Stop()
	}
	return nil
}

func (r *retryingAnomalyReader) Available() bool {
	return true // It can become available when enforcement pins the map.
}
