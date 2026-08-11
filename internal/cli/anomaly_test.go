package cli

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ztap/internal/config"
	"ztap/internal/flow"
)

func TestStartAnomalyRunnerDisabled(t *testing.T) {
	// anomaly.enabled defaults to false: the runner must be a no-op.
	r, err := startAnomalyRunner(context.Background(), &config.Config{}, nil)
	if err != nil {
		t.Fatalf("startAnomalyRunner: %v", err)
	}
	if r != nil {
		t.Fatalf("expected nil runner when anomaly.enabled is false, got %+v", r)
	}
}

func TestAnomalyRunnerStopNil(t *testing.T) {
	var r *anomalyRunner
	r.Stop() // must not panic
}

func TestFlowToAnomalyRecord(t *testing.T) {
	ts := time.Unix(1700000000, 0)
	rec := flowToAnomalyRecord(flow.FlowEvent{
		Timestamp: ts,
		SourceIP:  net.IPv4(10, 0, 0, 1),
		DestIP:    net.IPv4(10, 0, 0, 2),
		DestPort:  443,
		Protocol:  "TCP",
		Direction: "egress",
		Action:    "blocked",
	})
	if rec.SourceIP != "10.0.0.1" || rec.DestIP != "10.0.0.2" {
		t.Fatalf("unexpected IPs: %+v", rec)
	}
	if rec.Port != 443 || rec.Protocol != "TCP" {
		t.Fatalf("unexpected port/protocol: %+v", rec)
	}
	if !rec.Timestamp.Equal(ts) {
		t.Fatalf("timestamp not preserved: %v", rec.Timestamp)
	}
	if rec.Bytes != 0 {
		t.Fatalf("expected zero bytes (not present on flow events), got %d", rec.Bytes)
	}
}

// TestStartAnomalyRunnerEndToEnd starts the full runner (monitor -> pipeline
// -> httptest detector) with an explicitly injected simulated reader and
// verifies that batches reach the service and the pipeline shuts down cleanly.
// Production anomaly detection never falls back to synthetic events.
func TestStartAnomalyRunnerEndToEnd(t *testing.T) {
	batches := make(chan int, 16)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/batch" {
			t.Errorf("expected /batch, got %s", r.URL.Path)
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		flows, _ := req["flows"].([]any)
		select {
		case batches <- len(flows):
		default:
		}
		predictions := make([]map[string]any, len(flows))
		for i := range flows {
			predictions[i] = map[string]any{
				"index":      i,
				"score":      10.0,
				"is_anomaly": false,
				"reason":     "normal",
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"predictions": predictions,
			"total":       len(flows),
			"anomalies":   0,
		})
	}))
	t.Cleanup(ts.Close)

	cfg := &config.Config{}
	cfg.Anomaly.Enabled = true
	cfg.Anomaly.Endpoint = config.String(ts.URL)
	cfg.Anomaly.Threshold = 50
	cfg.Anomaly.BatchSize = 2
	cfg.Anomaly.FlushInterval = config.Duration(200 * time.Millisecond)
	cfg.Anomaly.FailOpen = true

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	r, err := startAnomalyRunnerWithReader(ctx, cfg, nil, flow.NewSimulatedReader(generateRawDemoFlows(), 20*time.Millisecond))
	if err != nil {
		t.Fatalf("startAnomalyRunner: %v", err)
	}
	if r == nil || r.pipeline == nil || r.monitor == nil {
		t.Fatalf("expected fully wired runner, got %+v", r)
	}

	// Simulated flows are generated every 20ms; with batch size 2 the first
	// flush should arrive well within the timeout.
	select {
	case n := <-batches:
		if n < 1 {
			t.Fatalf("unexpected batch size %d", n)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("no batch reached the detector (stats: %+v)", r.pipeline.Stats())
	}

	r.Stop()
	if got := r.pipeline.Stats().Flushes; got == 0 {
		t.Fatalf("expected at least one flush, got %d", got)
	}
}
