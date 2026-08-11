package anomaly

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"
)

// FlowRecord represents a network flow for anomaly detection
type FlowRecord struct {
	SourceIP  string    `json:"source_ip"`
	DestIP    string    `json:"dest_ip"`
	Port      int       `json:"port"`
	Protocol  string    `json:"protocol"`
	Bytes     int64     `json:"bytes"`
	Timestamp time.Time `json:"timestamp"`
	SourceGeo string    `json:"source_geo,omitempty"`
	DestGeo   string    `json:"dest_geo,omitempty"`
}

// AnomalyScore represents the detection result
type AnomalyScore struct {
	Score     float64 `json:"score"`      // 0-100; pipeline applies its threshold
	IsAnomaly bool    `json:"is_anomaly"` // Service/model classification
	Reason    string  `json:"reason"`     // Human-readable explanation
}

// Detector interface for anomaly detection
type Detector interface {
	Detect(flow FlowRecord) (*AnomalyScore, error)
	DetectBatch(flows []FlowRecord) ([]AnomalyScore, error)
	Train(flows []FlowRecord) error
}

// PythonDetector communicates with Python microservice via HTTP
type PythonDetector struct {
	endpoint     string
	token        string
	client       *http.Client
	retries      int           // retries after the initial attempt
	retryBackoff time.Duration // base backoff, doubled per attempt
}

// PythonDetectorOption configures a PythonDetector.
type PythonDetectorOption func(*PythonDetector)

// WithAuthToken sets the Bearer token presented to the detection service.
// Requests are sent without an Authorization header when token is empty.
func WithAuthToken(token string) PythonDetectorOption {
	return func(d *PythonDetector) {
		d.token = strings.TrimSpace(token)
	}
}

// WithHTTPClient overrides the default HTTP client (timeouts, transport).
func WithHTTPClient(client *http.Client) PythonDetectorOption {
	return func(d *PythonDetector) {
		if client != nil {
			d.client = client
		}
	}
}

// WithRetries sets the number of retries for transient failures (5xx
// responses and transport errors). The default is 2 retries.
func WithRetries(n int) PythonDetectorOption {
	return func(d *PythonDetector) {
		if n < 0 {
			n = 0
		}
		d.retries = n
	}
}

// WithRetryBackoff sets the base backoff between retries; each attempt
// doubles it (200ms, 400ms, 800ms, ... by default).
func WithRetryBackoff(d time.Duration) PythonDetectorOption {
	return func(det *PythonDetector) {
		if d <= 0 {
			d = time.Nanosecond
		}
		det.retryBackoff = d
	}
}

// NewPythonDetector creates a new detector client
func NewPythonDetector(endpoint string, opts ...PythonDetectorOption) *PythonDetector {
	d := &PythonDetector{
		endpoint: strings.TrimRight(strings.TrimSpace(endpoint), "/"),
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		retries:      2,
		retryBackoff: 200 * time.Millisecond,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
}

// Detect sends a flow to the Python service for anomaly detection
func (d *PythonDetector) Detect(flow FlowRecord) (*AnomalyScore, error) {
	var score AnomalyScore
	if err := d.doRequest(context.Background(), "/detect", flow, &score); err != nil {
		return nil, err
	}
	if err := validateAnomalyScore(score); err != nil {
		return nil, err
	}
	return &score, nil
}

// batchResponse mirrors the /batch endpoint response.
type batchResponse struct {
	Predictions []batchPrediction `json:"predictions"`
	Total       *int              `json:"total"`
	Anomalies   *int              `json:"anomalies"`
}

type batchPrediction struct {
	Index     *int     `json:"index"`
	Score     *float64 `json:"score"`
	IsAnomaly *bool    `json:"is_anomaly"`
	Reason    *string  `json:"reason"`
}

// DetectBatch sends a batch of flows to the Python service. The returned
// scores are aligned with the input slice by the response's index field.
func (d *PythonDetector) DetectBatch(flows []FlowRecord) ([]AnomalyScore, error) {
	if len(flows) == 0 {
		return nil, nil
	}

	var resp batchResponse
	if err := d.doRequest(context.Background(), "/batch", map[string]any{"flows": flows}, &resp); err != nil {
		return nil, err
	}

	if resp.Total == nil {
		return nil, fmt.Errorf("detection service response is missing total")
	}
	if *resp.Total != len(flows) {
		return nil, fmt.Errorf("detection service returned total %d for %d flows", *resp.Total, len(flows))
	}
	if resp.Anomalies == nil {
		return nil, fmt.Errorf("detection service response is missing anomalies")
	}
	if len(resp.Predictions) != len(flows) {
		return nil, fmt.Errorf("detection service returned %d predictions for %d flows", len(resp.Predictions), len(flows))
	}

	scores := make([]AnomalyScore, len(flows))
	seen := make([]bool, len(scores))
	anomalyCount := 0
	for _, p := range resp.Predictions {
		if p.Index == nil {
			return nil, fmt.Errorf("detection service prediction is missing index")
		}
		if *p.Index < 0 || *p.Index >= len(scores) {
			return nil, fmt.Errorf("detection service returned out-of-range index %d", *p.Index)
		}
		if seen[*p.Index] {
			return nil, fmt.Errorf("detection service returned duplicate index %d", *p.Index)
		}
		if p.Score == nil || p.IsAnomaly == nil || p.Reason == nil {
			return nil, fmt.Errorf("detection service prediction at index %d is missing fields", *p.Index)
		}
		if err := validateAnomalyScore(AnomalyScore{Score: *p.Score}); err != nil {
			return nil, fmt.Errorf("invalid prediction at index %d: %w", *p.Index, err)
		}
		seen[*p.Index] = true
		if *p.IsAnomaly {
			anomalyCount++
		}
		scores[*p.Index] = AnomalyScore{Score: *p.Score, IsAnomaly: *p.IsAnomaly, Reason: *p.Reason}
	}
	for i, ok := range seen {
		if !ok {
			return nil, fmt.Errorf("detection service response is missing prediction for index %d", i)
		}
	}
	if *resp.Anomalies != anomalyCount {
		return nil, fmt.Errorf("detection service returned anomalies %d, counted %d", *resp.Anomalies, anomalyCount)
	}
	return scores, nil
}

// Train sends training data to the Python service
func (d *PythonDetector) Train(flows []FlowRecord) error {
	return d.doRequest(context.Background(), "/train", flows, nil)
}

// doRequest performs a POST to path with the given payload and decodes the
// response into out (when non-nil). Transient failures — 5xx responses and
// transport errors — are retried with exponential backoff.
func (d *PythonDetector) doRequest(ctx context.Context, path string, payload any, out any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= d.retries; attempt++ {
		if attempt > 0 {
			backoff := d.retryBackoff * time.Duration(1<<(attempt-1))
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.endpoint+path, bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("failed to build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if d.token != "" {
			req.Header.Set("Authorization", "Bearer "+d.token)
		}

		resp, err := d.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("failed to call detection service: %w", err)
			continue // transient transport error — retry
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxDetectionResponseBytes+1))
		_ = resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("failed to read detection service response: %w", readErr)
			continue
		}
		if len(body) > maxDetectionResponseBytes {
			return fmt.Errorf("detection service response exceeds %d bytes", maxDetectionResponseBytes)
		}

		if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("detection service returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
			continue // transient server/rate-limit error — retry
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("detection service returned status %d", resp.StatusCode)
		}
		if out != nil {
			if err := json.Unmarshal(body, out); err != nil {
				return fmt.Errorf("failed to decode response: %w", err)
			}
		}
		return nil
	}
	return lastErr
}

const (
	// Maximum number of anomaly reasons we track
	maxAnomalyReasons = 3
	// Bound response memory usage even if a service returns an unexpectedly
	// large body. Normal batches are far smaller than this limit.
	maxDetectionResponseBytes = 10 << 20
)

func validateAnomalyScore(score AnomalyScore) error {
	if math.IsNaN(score.Score) || math.IsInf(score.Score, 0) {
		return fmt.Errorf("score must be finite")
	}
	if score.Score < 0 || score.Score > 100 {
		return fmt.Errorf("score %.6f is outside 0-100", score.Score)
	}
	return nil
}

// SimpleDetector provides basic rule-based anomaly detection (no ML)
type SimpleDetector struct {
	suspiciousPorts  map[int]bool    // Changed to map for O(1) lookup
	blockedCountries map[string]bool // Changed to map for O(1) lookup
}

// NewSimpleDetector creates a rule-based detector
func NewSimpleDetector() *SimpleDetector {
	return &SimpleDetector{
		suspiciousPorts: map[int]bool{
			22:   true, // SSH (common for attacks)
			23:   true, // Telnet
			3389: true, // RDP
			1433: true, // SQL Server
			3306: true, // MySQL
			5432: true, // PostgreSQL
		},
		blockedCountries: map[string]bool{
			"RU": true, // Russia
			"CN": true, // China
			"KP": true, // North Korea
		},
	}
}

// Detect performs rule-based anomaly detection
func (d *SimpleDetector) Detect(flow FlowRecord) (*AnomalyScore, error) {
	score := 0.0
	reasons := make([]string, 0, maxAnomalyReasons) // Pre-allocate with max capacity

	// Check for suspicious ports - O(1) map lookup
	if d.suspiciousPorts[flow.Port] {
		score += 30.0
		reasons = append(reasons, fmt.Sprintf("suspicious port %d", flow.Port))
	}

	// Check for blocked countries - O(1) map lookup
	if d.blockedCountries[flow.DestGeo] || d.blockedCountries[flow.SourceGeo] {
		score += 50.0
		country := flow.DestGeo
		if d.blockedCountries[flow.SourceGeo] {
			country = flow.SourceGeo
		}
		reasons = append(reasons, "traffic to/from blocked country "+country)
	}

	// Check for unusual traffic volume
	if flow.Bytes > 100*1024*1024 { // > 100 MB
		score += 20.0
		reasons = append(reasons, "high data transfer volume")
	}

	reason := "normal traffic"
	if len(reasons) > 0 {
		reason = strings.Join(reasons, ", ")
	}

	return &AnomalyScore{
		Score:     score,
		IsAnomaly: score > 50.0,
		Reason:    reason,
	}, nil
}

// DetectBatch applies Detect to each flow.
func (d *SimpleDetector) DetectBatch(flows []FlowRecord) ([]AnomalyScore, error) {
	scores := make([]AnomalyScore, 0, len(flows))
	for _, flow := range flows {
		score, err := d.Detect(flow)
		if err != nil {
			return nil, err
		}
		scores = append(scores, *score)
	}
	return scores, nil
}

// Train is a no-op for simple detector (no ML)
func (d *SimpleDetector) Train(flows []FlowRecord) error {
	return nil
}
