//go:build linux
// +build linux

package apihttp

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"

	"ztap/pkg/enforcer"
	"ztap/pkg/flow"
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
		r.m.Close()
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
		return flow.NewSimulatedReader(demoRawFlows(), 500*time.Millisecond)
	}

	reader, err := flow.CreateFlowReader(m)
	if err != nil {
		m.Close()
		fmt.Fprintf(os.Stderr, "note: using simulated flows (failed to create linux flow reader: %v)\n", err)
		return flow.NewSimulatedReader(demoRawFlows(), 500*time.Millisecond)
	}

	return &mapOwningReader{inner: reader, m: m}
}
