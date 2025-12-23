package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"ztap/pkg/alert"

	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v3"
)

type alertConfigFile struct {
	Alerting struct {
		Enabled   *bool  `yaml:"enabled"`
		QueueSize int    `yaml:"queue_size"`
		Workers   int    `yaml:"workers"`
		Timeout   string `yaml:"timeout"`
		DedupeTTL string `yaml:"dedupe_ttl"`
		Slack     struct {
			WebhookURL string `yaml:"webhook_url"`
		} `yaml:"slack"`
		PagerDuty struct {
			RoutingKey string `yaml:"routing_key"`
			Source     string `yaml:"source"`
		} `yaml:"pagerduty"`
	} `yaml:"alerting"`
}

func loadAlertConfig() (alert.Config, error) {
	path := os.Getenv("ZTAP_CONFIG")
	if path == "" {
		path = "config.yaml"
	}

	cfg := alert.Config{
		Enabled:         false,
		QueueSize:       128,
		Workers:         2,
		Timeout:         5 * time.Second,
		DedupeTTL:       5 * time.Minute,
		PagerDutySource: "ztap",
	}

	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return cfg, fmt.Errorf("reading config file %s: %w", path, err)
	}
	if err == nil {
		var fileCfg alertConfigFile
		if err := yaml.Unmarshal(data, &fileCfg); err != nil {
			return cfg, fmt.Errorf("parsing config file %s: %w", path, err)
		}

		if fileCfg.Alerting.Enabled != nil {
			cfg.Enabled = *fileCfg.Alerting.Enabled
		}
		if fileCfg.Alerting.QueueSize > 0 {
			cfg.QueueSize = fileCfg.Alerting.QueueSize
		}
		if fileCfg.Alerting.Workers > 0 {
			cfg.Workers = fileCfg.Alerting.Workers
		}
		if strings.TrimSpace(fileCfg.Alerting.Timeout) != "" {
			dur, err := time.ParseDuration(strings.TrimSpace(fileCfg.Alerting.Timeout))
			if err != nil {
				return cfg, fmt.Errorf("parsing alerting.timeout: %w", err)
			}
			cfg.Timeout = dur
		}
		if strings.TrimSpace(fileCfg.Alerting.DedupeTTL) != "" {
			dur, err := time.ParseDuration(strings.TrimSpace(fileCfg.Alerting.DedupeTTL))
			if err != nil {
				return cfg, fmt.Errorf("parsing alerting.dedupe_ttl: %w", err)
			}
			cfg.DedupeTTL = dur
		}
		if strings.TrimSpace(fileCfg.Alerting.Slack.WebhookURL) != "" {
			cfg.SlackWebhookURL = strings.TrimSpace(fileCfg.Alerting.Slack.WebhookURL)
		}
		if strings.TrimSpace(fileCfg.Alerting.PagerDuty.RoutingKey) != "" {
			cfg.PagerDutyRoutingKey = strings.TrimSpace(fileCfg.Alerting.PagerDuty.RoutingKey)
		}
		if strings.TrimSpace(fileCfg.Alerting.PagerDuty.Source) != "" {
			cfg.PagerDutySource = strings.TrimSpace(fileCfg.Alerting.PagerDuty.Source)
		}
	}

	if v := strings.TrimSpace(os.Getenv("ZTAP_ALERT_ENABLED")); v != "" {
		if parsed, parseErr := strconv.ParseBool(v); parseErr == nil {
			cfg.Enabled = parsed
		}
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_ALERT_SLACK_WEBHOOK_URL")); v != "" {
		cfg.SlackWebhookURL = v
		cfg.Enabled = true
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_ALERT_PAGERDUTY_ROUTING_KEY")); v != "" {
		cfg.PagerDutyRoutingKey = v
		cfg.Enabled = true
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_ALERT_PAGERDUTY_SOURCE")); v != "" {
		cfg.PagerDutySource = v
	}

	return cfg, nil
}

var alertCmd = &cobra.Command{
	Use:   "alert",
	Short: "Alerting utilities",
}

var alertTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Send a test alert using configured sinks",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadAlertConfig()
		if err != nil {
			return err
		}
		if !cfg.Enabled {
			return errors.New("alerting is disabled")
		}

		manager, err := alert.NewManagerFromConfig(cfg)
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout*2)
		defer cancel()

		manager.Start(ctx)

		ok := manager.Emit(alert.Alert{
			Source:   "ztap-cli",
			Severity: alert.SeverityInfo,
			Title:    "ZTAP alert test",
			Message:  "This is a test alert from 'ztap alert test'",
			DedupKey: "ztap-cli:test",
		})
		manager.Close()

		if !ok {
			return errors.New("alert dropped before dispatch")
		}

		fmt.Println("test alert dispatched")
		return nil
	},
}

func init() {
	alertCmd.AddCommand(alertTestCmd)
	rootCmd.AddCommand(alertCmd)
}
