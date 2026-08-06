//go:build linux
// +build linux

package cli

import (
	"context"
	"fmt"
	"os"
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

func createFlowReader() flow.FlowReader {
	m, err := ebpf.LoadPinnedMap(enforcer.DefaultFlowEventsPinPath, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "note: using simulated flows (no pinned map at %s; run 'ztap enforce' first)\n", enforcer.DefaultFlowEventsPinPath)
		return flow.NewSimulatedReader(generateRawDemoFlows(), 500*time.Millisecond)
	}

	reader, err := flow.CreateFlowReader(m)
	if err != nil {
		if closeErr := m.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "warning: closing pinned flow map failed: %v\n", closeErr)
		}
		fmt.Fprintf(os.Stderr, "note: using simulated flows (failed to create linux flow reader: %v)\n", err)
		return flow.NewSimulatedReader(generateRawDemoFlows(), 500*time.Millisecond)
	}

	return &mapOwningReader{inner: reader, m: m}
}
