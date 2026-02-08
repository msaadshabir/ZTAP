package anomaly

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPythonDetectorDetect(t *testing.T) {
	var got FlowRecord
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/detect" {
			t.Fatalf("expected /detect, got %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(AnomalyScore{Score: 80.0, IsAnomaly: true, Reason: "test"})
	}))
	t.Cleanup(ts.Close)

	det := NewPythonDetector(ts.URL)
	input := FlowRecord{SourceIP: "10.0.0.1", DestIP: "10.0.0.2", Port: 22, Protocol: "TCP", Bytes: 10, Timestamp: time.Unix(1, 0)}
	score, err := det.Detect(input)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if score.Score != 80.0 || !score.IsAnomaly {
		t.Fatalf("unexpected score: %+v", score)
	}
	if got.Port != input.Port || got.SourceIP != input.SourceIP {
		t.Fatalf("unexpected request payload: %+v", got)
	}
}

func TestPythonDetectorDetectNonOK(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(ts.Close)

	det := NewPythonDetector(ts.URL)
	_, err := det.Detect(FlowRecord{})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "status 400") {
		t.Fatalf("expected status in error, got %q", err.Error())
	}
}

func TestPythonDetectorTrain(t *testing.T) {
	var got []FlowRecord
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/train" {
			t.Fatalf("expected /train, got %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)

	det := NewPythonDetector(ts.URL)
	flows := []FlowRecord{{SourceIP: "1.1.1.1", DestIP: "2.2.2.2", Port: 443, Protocol: "TCP", Bytes: 1, Timestamp: time.Unix(2, 0)}}
	if err := det.Train(flows); err != nil {
		t.Fatalf("Train: %v", err)
	}
	if len(got) != 1 || got[0].Port != 443 {
		t.Fatalf("unexpected train payload: %+v", got)
	}
}

func TestSimpleDetectorScores(t *testing.T) {
	det := NewSimpleDetector()
	score, err := det.Detect(FlowRecord{Port: 22, DestGeo: "RU", Bytes: 200 * 1024 * 1024})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if score.Score <= 50.0 || !score.IsAnomaly {
		t.Fatalf("expected anomaly, got %+v", score)
	}
	if !strings.Contains(score.Reason, "suspicious port") {
		t.Fatalf("expected suspicious port in reason, got %q", score.Reason)
	}
}

func TestSimpleDetectorNormal(t *testing.T) {
	det := NewSimpleDetector()
	score, err := det.Detect(FlowRecord{Port: 80, DestGeo: "US", Bytes: 1024})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if score.IsAnomaly {
		t.Fatalf("expected non-anomaly, got %+v", score)
	}
	if score.Reason != "normal traffic" {
		t.Fatalf("expected normal traffic reason, got %q", score.Reason)
	}
}
