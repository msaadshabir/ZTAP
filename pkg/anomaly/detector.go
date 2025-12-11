package anomaly

import (
	"bytes"
	"encoding/json"
	"fmt"
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
	Score     float64 `json:"score"`      // 0-100
	IsAnomaly bool    `json:"is_anomaly"` // True if score > threshold
	Reason    string  `json:"reason"`     // Human-readable explanation
}

// Detector interface for anomaly detection
type Detector interface {
	Detect(flow FlowRecord) (*AnomalyScore, error)
	Train(flows []FlowRecord) error
}

// PythonDetector communicates with Python microservice via HTTP
type PythonDetector struct {
	endpoint string
	client   *http.Client
}

// NewPythonDetector creates a new detector client
func NewPythonDetector(endpoint string) *PythonDetector {
	return &PythonDetector{
		endpoint: endpoint,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Detect sends a flow to the Python service for anomaly detection
func (d *PythonDetector) Detect(flow FlowRecord) (*AnomalyScore, error) {
	data, err := json.Marshal(flow)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal flow: %w", err)
	}

	resp, err := d.client.Post(d.endpoint+"/detect", "application/json", bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("failed to call detection service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("detection service returned status %d", resp.StatusCode)
	}

	var score AnomalyScore
	if err := json.NewDecoder(resp.Body).Decode(&score); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &score, nil
}

// Train sends training data to the Python service
func (d *PythonDetector) Train(flows []FlowRecord) error {
	data, err := json.Marshal(flows)
	if err != nil {
		return fmt.Errorf("failed to marshal flows: %w", err)
	}

	resp, err := d.client.Post(d.endpoint+"/train", "application/json", bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("failed to call training service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("training service returned status %d", resp.StatusCode)
	}

	return nil
}

const (
	// Maximum number of anomaly reasons we track
	maxAnomalyReasons = 3
)

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
		reasons = append(reasons, fmt.Sprintf("traffic to/from blocked country %s", country))
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

// Train is a no-op for simple detector (no ML)
func (d *SimpleDetector) Train(flows []FlowRecord) error {
	return nil
}
