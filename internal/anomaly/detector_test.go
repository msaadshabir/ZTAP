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

func TestPythonDetectorDetectBatch(t *testing.T) {
	var got map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/batch" {
			t.Fatalf("expected /batch, got %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"predictions": []any{
				map[string]any{"index": 0, "score": 10.0, "is_anomaly": false, "reason": "normal"},
				map[string]any{"index": 1, "score": 90.0, "is_anomaly": true, "reason": "suspicious port 22"},
			},
			"total":     2,
			"anomalies": 1,
		})
	}))
	t.Cleanup(ts.Close)

	det := NewPythonDetector(ts.URL)
	flows := []FlowRecord{
		{SourceIP: "10.0.0.1", DestIP: "10.0.0.2", Port: 443, Protocol: "TCP"},
		{SourceIP: "10.0.0.1", DestIP: "10.0.0.3", Port: 22, Protocol: "TCP"},
	}
	scores, err := det.DetectBatch(flows)
	if err != nil {
		t.Fatalf("DetectBatch: %v", err)
	}
	if len(scores) != 2 {
		t.Fatalf("expected 2 scores, got %d", len(scores))
	}
	if scores[0].Score != 10.0 || scores[0].IsAnomaly {
		t.Fatalf("unexpected score[0]: %+v", scores[0])
	}
	if scores[1].Score != 90.0 || !scores[1].IsAnomaly || scores[1].Reason != "suspicious port 22" {
		t.Fatalf("unexpected score[1]: %+v", scores[1])
	}

	flowsAny, ok := got["flows"].([]any)
	if !ok || len(flowsAny) != 2 {
		t.Fatalf("expected {\"flows\": [...]} payload, got %+v", got)
	}
}

func TestPythonDetectorDetectBatchEmpty(t *testing.T) {
	det := NewPythonDetector("http://127.0.0.1:1")
	scores, err := det.DetectBatch(nil)
	if err != nil {
		t.Fatalf("DetectBatch(nil): %v", err)
	}
	if scores != nil {
		t.Fatalf("expected nil scores, got %+v", scores)
	}
}

func TestPythonDetectorAuthToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer secret-token" {
			t.Fatalf("expected Bearer secret-token, got %q", got)
		}
		_ = json.NewEncoder(w).Encode(AnomalyScore{Score: 5, IsAnomaly: false, Reason: "ok"})
	}))
	t.Cleanup(ts.Close)

	det := NewPythonDetector(ts.URL, WithAuthToken("secret-token"))
	if _, err := det.Detect(FlowRecord{}); err != nil {
		t.Fatalf("Detect: %v", err)
	}
}

func TestPythonDetectorNoTokenHeaderWhenUnset(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("expected no Authorization header, got %q", got)
		}
		_ = json.NewEncoder(w).Encode(AnomalyScore{Score: 5, IsAnomaly: false, Reason: "ok"})
	}))
	t.Cleanup(ts.Close)

	det := NewPythonDetector(ts.URL)
	if _, err := det.Detect(FlowRecord{}); err != nil {
		t.Fatalf("Detect: %v", err)
	}
}

func TestPythonDetectorRetriesOn5xx(t *testing.T) {
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(AnomalyScore{Score: 7, IsAnomaly: false, Reason: "ok"})
	}))
	t.Cleanup(ts.Close)

	det := NewPythonDetector(ts.URL, WithRetries(2), WithRetryBackoff(time.Millisecond))
	score, err := det.Detect(FlowRecord{})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("expected 2 attempts (1 retry), got %d", attempts)
	}
	if score.Score != 7 {
		t.Fatalf("unexpected score: %+v", score)
	}
}

func TestPythonDetectorGivesUpAfterRetries(t *testing.T) {
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(ts.Close)

	det := NewPythonDetector(ts.URL, WithRetries(2), WithRetryBackoff(time.Millisecond))
	if _, err := det.Detect(FlowRecord{}); err == nil {
		t.Fatalf("expected error after retries")
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}

func TestPythonDetectorNoRetryOn4xx(t *testing.T) {
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(ts.Close)

	det := NewPythonDetector(ts.URL, WithRetries(2), WithRetryBackoff(time.Millisecond))
	if _, err := det.Detect(FlowRecord{}); err == nil {
		t.Fatalf("expected error")
	}
	if attempts != 1 {
		t.Fatalf("expected no retries on 401, got %d attempts", attempts)
	}
}

func TestPythonDetectorRetriesOnTransportError(t *testing.T) {
	// A panicking handler aborts the connection without a response, which
	// surfaces as a transport error on the client side.
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		panic("connection aborted")
	}))
	t.Cleanup(ts.Close)

	det := NewPythonDetector(ts.URL, WithRetries(1), WithRetryBackoff(time.Millisecond))
	if _, err := det.Detect(FlowRecord{}); err == nil {
		t.Fatalf("expected error after transport failure")
	}
	if attempts != 2 {
		t.Fatalf("expected 2 attempts (1 retry), got %d", attempts)
	}
}

func TestPythonDetectorDetectBatchOutOfRangeIndex(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"predictions": []any{map[string]any{"index": 5, "score": 10.0, "is_anomaly": false, "reason": "x"}},
			"total":       1,
			"anomalies":   0,
		})
	}))
	t.Cleanup(ts.Close)

	det := NewPythonDetector(ts.URL)
	_, err := det.DetectBatch([]FlowRecord{{SourceIP: "10.0.0.1"}})
	if err == nil || !strings.Contains(err.Error(), "out-of-range index 5") {
		t.Fatalf("expected out-of-range error, got %v", err)
	}
}

func TestPythonDetectorDetectBatchRejectsDuplicateIndex(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"predictions": []any{
				map[string]any{"index": 0, "score": 10.0, "is_anomaly": false, "reason": "normal"},
				map[string]any{"index": 0, "score": 90.0, "is_anomaly": true, "reason": "anomaly"},
			},
			"total":     2,
			"anomalies": 1,
		})
	}))
	t.Cleanup(ts.Close)

	det := NewPythonDetector(ts.URL)
	_, err := det.DetectBatch([]FlowRecord{{}, {}})
	if err == nil || !strings.Contains(err.Error(), "duplicate index 0") {
		t.Fatalf("expected duplicate-index error, got %v", err)
	}
}

func TestPythonDetectorDetectBatchRejectsMissingPrediction(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"predictions": []any{
				map[string]any{"index": 0, "score": 10.0, "is_anomaly": false, "reason": "normal"},
			},
			"total":     2,
			"anomalies": 0,
		})
	}))
	t.Cleanup(ts.Close)

	det := NewPythonDetector(ts.URL)
	_, err := det.DetectBatch([]FlowRecord{{}, {}})
	if err == nil || !strings.Contains(err.Error(), "predictions for 2 flows") {
		t.Fatalf("expected prediction-count error, got %v", err)
	}
}

func TestPythonDetectorRetriesOn429(t *testing.T) {
	attempts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(AnomalyScore{Score: 7, IsAnomaly: false, Reason: "ok"})
	}))
	t.Cleanup(ts.Close)

	det := NewPythonDetector(ts.URL, WithRetries(1), WithRetryBackoff(time.Millisecond))
	if _, err := det.Detect(FlowRecord{}); err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("expected one retry after 429, got %d attempts", attempts)
	}
}

func TestPythonDetectorOptions(t *testing.T) {
	det := NewPythonDetector(" http://example.com/",
		WithHTTPClient(&http.Client{Timeout: 3 * time.Second}),
		WithRetries(-1),
		WithRetryBackoff(0),
	)
	if det.endpoint != "http://example.com" {
		t.Fatalf("endpoint not trimmed: %q", det.endpoint)
	}
	if det.client.Timeout != 3*time.Second {
		t.Fatalf("custom client not applied: %+v", det.client)
	}
	if det.retries != 0 {
		t.Fatalf("expected negative retries clamped to 0, got %d", det.retries)
	}
	if det.retryBackoff != time.Nanosecond {
		t.Fatalf("expected zero backoff clamped to 1ns, got %v", det.retryBackoff)
	}
}

func TestSimpleDetectorDetectBatch(t *testing.T) {
	det := NewSimpleDetector()
	scores, err := det.DetectBatch([]FlowRecord{
		{Port: 22, DestGeo: "RU", Bytes: 200 * 1024 * 1024},
		{Port: 80, DestGeo: "US", Bytes: 1024},
	})
	if err != nil {
		t.Fatalf("DetectBatch: %v", err)
	}
	if len(scores) != 2 {
		t.Fatalf("expected 2 scores, got %d", len(scores))
	}
	if !scores[0].IsAnomaly || scores[1].IsAnomaly {
		t.Fatalf("unexpected scores: %+v", scores)
	}
}

func TestSimpleDetectorTrainNoop(t *testing.T) {
	det := NewSimpleDetector()
	if err := det.Train([]FlowRecord{{Port: 80}}); err != nil {
		t.Fatalf("Train: %v", err)
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
