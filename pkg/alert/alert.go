package alert

import (
	"context"
	"time"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityError    Severity = "error"
	SeverityCritical Severity = "critical"
)

type Alert struct {
	Timestamp time.Time
	Source    string
	Severity  Severity
	Title     string
	Message   string

	DedupKey string
	Details  map[string]any
}

type Sink interface {
	Send(ctx context.Context, a Alert) error
}
