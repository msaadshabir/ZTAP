package metrics

import (
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

// resetCollector clears the global collector so each test gets a clean registry.
func resetCollector(t *testing.T) {
	t.Helper()
	if globalCollector != nil {
		prometheus.Unregister(globalCollector.policiesEnforced)
		prometheus.Unregister(globalCollector.flowsAllowed)
		prometheus.Unregister(globalCollector.flowsBlocked)
		prometheus.Unregister(globalCollector.anomalyScore)
		prometheus.Unregister(globalCollector.policyLoadTime)
	}
	globalCollector = nil
	once = sync.Once{}
}

func TestGetCollectorSingleton(t *testing.T) {
	resetCollector(t)

	c1 := GetCollector()
	c2 := GetCollector()

	if c1 == nil {
		t.Fatal("expected collector instance, got nil")
	}
	if c1 != c2 {
		t.Fatal("expected singleton collector")
	}
}

func TestCollectorCounters(t *testing.T) {
	resetCollector(t)
	collector := GetCollector()

	collector.IncPoliciesEnforced()
	collector.IncPoliciesEnforced()
	collector.IncFlowsAllowed()
	collector.IncFlowsBlocked()
	collector.IncFlowsBlocked()

	if got := testutil.ToFloat64(collector.policiesEnforced); got != 2 {
		t.Fatalf("expected policiesEnforced=2, got %v", got)
	}
	if got := testutil.ToFloat64(collector.flowsAllowed); got != 1 {
		t.Fatalf("expected flowsAllowed=1, got %v", got)
	}
	if got := testutil.ToFloat64(collector.flowsBlocked); got != 2 {
		t.Fatalf("expected flowsBlocked=2, got %v", got)
	}
}

func TestCollectorGaugeAndHistogram(t *testing.T) {
	resetCollector(t)
	collector := GetCollector()

	collector.SetAnomalyScore(42.5)
	collector.ObservePolicyLoadTime(0.5)
	collector.ObservePolicyLoadTime(1.5)

	if got := testutil.ToFloat64(collector.anomalyScore); got != 42.5 {
		t.Fatalf("expected anomalyScore=42.5, got %v", got)
	}

	metric := &dto.Metric{}
	if err := collector.policyLoadTime.Write(metric); err != nil {
		t.Fatalf("failed to read histogram metric: %v", err)
	}

	hist := metric.GetHistogram()
	if hist.GetSampleSum() != 2.0 {
		t.Fatalf("expected histogram sum=2.0, got %v", hist.GetSampleSum())
	}
	if hist.GetSampleCount() != 2 {
		t.Fatalf("expected histogram count=2, got %v", hist.GetSampleCount())
	}

	if count := testutil.CollectAndCount(collector.policyLoadTime); count != 1 {
		t.Fatalf("expected histogram to collect once, got %d", count)
	}
}
