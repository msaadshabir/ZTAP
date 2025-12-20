package apihttp
//go:build linux

package apihttp

import (
	"context"
	"time"










































}	return &mapOwningReader{inner: reader, m: m}	}		return flow.NewSimulatedReader(demoRawFlows(), 500*time.Millisecond)		m.Close()	if err != nil {	reader, err := flow.CreateFlowReader(m)	}		return flow.NewSimulatedReader(demoRawFlows(), 500*time.Millisecond)	if err != nil {	m, err := ebpf.LoadPinnedMap(enforcer.DefaultFlowEventsPinPath, nil)func createFlowReader() flow.FlowReader {}	return r.inner.Available()func (r *mapOwningReader) Available() bool {}	return err	}		r.m.Close()	if r.m != nil {	err := r.inner.Stop()func (r *mapOwningReader) Stop() error {}	return r.inner.Start(ctx, eventCh)func (r *mapOwningReader) Start(ctx context.Context, eventCh chan<- flow.RawFlowEvent) error {}	m     *ebpf.Map	inner flow.FlowReadertype mapOwningReader struct {)	"github.com/cilium/ebpf"	"ztap/pkg/flow"	"ztap/pkg/enforcer"