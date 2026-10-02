//go:build linux

package cli

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/saadshabir/ZTAP/internal/enforcer"
)

type orderedEngineMetricsProvider struct {
	calls        atomic.Uint64
	reads        chan uint64
	releaseFirst chan struct{}
}

func (p *orderedEngineMetricsProvider) MetricsSnapshot(context.Context) (enforcer.EngineMetricsSnapshot, error) {
	call := p.calls.Add(1)
	p.reads <- call
	if call == 1 {
		<-p.releaseFirst
	}
	count := 99 + call
	return enforcer.EngineMetricsSnapshot{
		ActivePolicyEpoch:   call,
		Decisions:           []enforcer.EngineDecisionMetric{{Action: "allowed", Direction: "egress", Reason: "rule", Count: count}},
		EventDrops:          []enforcer.EngineEventDropMetric{{Reason: "ring_full", Count: count}},
		SlotCleanupFailures: count,
	}, nil
}

func TestConcurrentEngineMetricsRefreshPreservesCounterOrder(t *testing.T) {
	provider := &orderedEngineMetricsProvider{reads: make(chan uint64, 4), releaseFirst: make(chan struct{})}
	status := &nativeAgentHTTP{
		activePolicyEpoch: prometheus.NewGauge(prometheus.GaugeOpts{Name: "test_epoch", Help: "test"}),
		packetDecisions: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_decisions", Help: "test"},
			[]string{"action", "direction", "reason"}),
		flowDrops:           prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_drops", Help: "test"}, []string{"reason"}),
		slotCleanupFailures: prometheus.NewCounter(prometheus.CounterOpts{Name: "test_cleanup", Help: "test"}),
	}
	status.setEngineMetricsProvider(provider)
	firstDone, secondDone := make(chan struct{}), make(chan struct{})
	go func() { status.refreshEngineMetrics(); close(firstDone) }()
	<-provider.reads
	go func() { status.refreshEngineMetrics(); close(secondDone) }()
	// The first fetch is held until the second caller has had an opportunity
	// to collect. Without serialization it publishes 101 before delayed 100.
	select {
	case <-provider.reads:
		close(provider.releaseFirst)
		<-firstDone
		<-secondDone
		t.Fatal("second refresh collected before the first snapshot was published")
	case <-time.After(100 * time.Millisecond):
	}
	close(provider.releaseFirst)
	<-firstDone
	<-secondDone
	status.refreshEngineMetrics()
	assertCounter := func(counter prometheus.Counter, want float64) {
		t.Helper()
		metric := &dto.Metric{}
		if err := counter.Write(metric); err != nil {
			t.Fatal(err)
		}
		if got := metric.GetCounter().GetValue(); got != want {
			t.Fatalf("counter = %v, want %v", got, want)
		}
	}
	assertCounter(status.packetDecisions.WithLabelValues("allowed", "egress", "rule"), 102)
	assertCounter(status.flowDrops.WithLabelValues("ring_full"), 102)
	assertCounter(status.slotCleanupFailures, 102)
	// Replacement is a new source, even when its first count exceeds the old
	// count. It must contribute its entire initial value.
	replacement := &orderedEngineMetricsProvider{reads: make(chan uint64, 1)}
	replacement.calls.Store(400)
	status.setEngineMetricsProvider(replacement)
	status.refreshEngineMetrics()
	assertCounter(status.packetDecisions.WithLabelValues("allowed", "egress", "rule"), 602)
}
