package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type SlackSink struct {
	WebhookURL string
	Client     *http.Client
}

func NewSlackSink(webhookURL string) (*SlackSink, error) {
	if strings.TrimSpace(webhookURL) == "" {
		return nil, errors.New("slack webhook url is required")
	}
	return &SlackSink{WebhookURL: webhookURL}, nil
}

func (s *SlackSink) Send(ctx context.Context, a Alert) error {
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}

	sev := strings.ToUpper(string(a.Severity))
	if sev == "" {
		sev = "INFO"
	}

	text := fmt.Sprintf("[%s] %s\n%s", sev, a.Title, a.Message)
	body, err := json.Marshal(map[string]any{"text": text})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.WebhookURL, bytes.NewReader(body))
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
		return fmt.Errorf("slack webhook returned %s", resp.Status)
	}

	return nil
}
