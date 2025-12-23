package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type PagerDutySink struct {
	RoutingKey string
	Source     string
	Client     *http.Client
	Endpoint   string
}

func NewPagerDutySink(routingKey string, source string) (*PagerDutySink, error) {
	if strings.TrimSpace(routingKey) == "" {
		return nil, errors.New("pagerduty routing key is required")
	}
	if strings.TrimSpace(source) == "" {
		source = "ztap"
	}
	return &PagerDutySink{RoutingKey: routingKey, Source: source}, nil
}

func (p *PagerDutySink) Send(ctx context.Context, a Alert) error {
	client := p.Client
	if client == nil {
		client = http.DefaultClient
	}

	endpoint := strings.TrimSpace(p.Endpoint)
	if endpoint == "" {
		endpoint = "https://events.pagerduty.com/v2/enqueue"
	}

	sev := mapPagerDutySeverity(a.Severity)
	summary := strings.TrimSpace(a.Title)
	if summary == "" {
		summary = "ztap alert"
	}

	timestamp := a.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	payload := map[string]any{
		"routing_key":  p.RoutingKey,
		"event_action": "trigger",
		"dedup_key":    strings.TrimSpace(a.DedupKey),
		"payload": map[string]any{
			"summary":        summary,
			"source":         p.Source,
			"severity":       sev,
			"timestamp":      timestamp.UTC().Format(time.RFC3339),
			"custom_details": a.Details,
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("pagerduty enqueue returned %s", resp.Status)
	}

	return nil
}

func mapPagerDutySeverity(s Severity) string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityError:
		return "error"
	case SeverityWarning:
		return "warning"
	case SeverityInfo:
		return "info"
	default:
		return "info"
	}
}
