package alert

import (
	"errors"
	"strings"
	"time"
)

type Config struct {
	Enabled             bool
	SlackWebhookURL     string
	PagerDutyRoutingKey string
	PagerDutySource     string
	QueueSize           int
	Workers             int
	Timeout             time.Duration
	DedupeTTL           time.Duration
}

func NewManagerFromConfig(cfg Config) (*Manager, error) {
	if !cfg.Enabled {
		return nil, errors.New("alerting is disabled")
	}

	sinks := make([]Sink, 0, 2)

	if url := strings.TrimSpace(cfg.SlackWebhookURL); url != "" {
		sink, err := NewSlackSink(url)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, sink)
	}

	if key := strings.TrimSpace(cfg.PagerDutyRoutingKey); key != "" {
		source := strings.TrimSpace(cfg.PagerDutySource)
		if source == "" {
			source = "ztap"
		}
		sink, err := NewPagerDutySink(key, source)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, sink)
	}

	if len(sinks) == 0 {
		return nil, errors.New("no alert sinks configured")
	}

	dispatcher, err := NewDispatcher(DispatcherOptions{
		Sinks:     sinks,
		QueueSize: cfg.QueueSize,
		Workers:   cfg.Workers,
		Timeout:   cfg.Timeout,
	})
	if err != nil {
		return nil, err
	}

	return NewManager(ManagerOptions{Dispatcher: dispatcher, DedupeTTL: cfg.DedupeTTL})
}
