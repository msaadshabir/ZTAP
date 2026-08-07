package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"ztap/internal/alert"
	"ztap/internal/config"

	"github.com/spf13/cobra"
)

// alertConfig converts the central alerting section into the alert package's
// own config type.
func alertConfig(cfg *config.Config) alert.Config {
	return alert.Config{
		Enabled:             cfg.Alerting.Enabled,
		SlackWebhookURL:     string(cfg.Alerting.Slack.WebhookURL),
		PagerDutyRoutingKey: string(cfg.Alerting.PagerDuty.RoutingKey),
		PagerDutySource:     string(cfg.Alerting.PagerDuty.Source),
		QueueSize:           cfg.Alerting.QueueSize,
		Workers:             cfg.Alerting.Workers,
		Timeout:             time.Duration(cfg.Alerting.Timeout),
		DedupeTTL:           time.Duration(cfg.Alerting.DedupeTTL),
	}
}

func newAlertCmd(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "alert",
		Short: "Alerting utilities",
	}
	c.AddCommand(newAlertTestCmd(app))
	return c
}

func newAlertTestCmd(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "test",
		Short: "Send a test alert using configured sinks",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := alertConfig(app.Config())
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
	return c
}
