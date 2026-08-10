package cli

import (
	"context"
	"fmt"
	"time"

	"ztap/internal/alert"
	"ztap/internal/anomaly"
	"ztap/internal/audit"
	"ztap/internal/config"
	"ztap/internal/flow"
	"ztap/internal/logging"
	"ztap/internal/metrics"
)

// anomalyRunner owns the anomaly detection pipeline and its flow source. It
// is created by startAnomalyRunner and torn down by Stop. Detection is
// advisory: enforcement never blocks on it, and a failure to start the
// pipeline only warns.
type anomalyRunner struct {
	pipeline *anomaly.Pipeline
	monitor  *flow.Monitor
	manager  *alert.Manager
	cancel   context.CancelFunc
	done     chan struct{}
}

// startAnomalyRunner wires the anomaly detection pipeline (E.1):
//   - flow monitor over the platform flow reader as the event source,
//   - batched, async detection against the Python service,
//   - ztap_anomaly_score metric via OnScore,
//   - alert webhook + audit entry for flows above the threshold,
//   - fail-open/fail-closed handling inside the pipeline.
//
// Returns (nil, nil) when anomaly.enabled is false.
func startAnomalyRunner(parent context.Context, cfg *config.Config, auditLogger *audit.AuditLogger) (*anomalyRunner, error) {
	if !cfg.Anomaly.Enabled {
		return nil, nil
	}

	ctx, cancel := context.WithCancel(parent)
	runner := &anomalyRunner{cancel: cancel, done: make(chan struct{})}

	if alertCfg := alertConfig(cfg); alertCfg.Enabled {
		mgr, err := alert.NewManagerFromConfig(alertCfg)
		if err != nil {
			logging.Warnf("anomaly alerts disabled: %v", err)
		} else {
			runner.manager = mgr
			mgr.Start(ctx)
		}
	}

	det := anomaly.NewPythonDetector(
		string(cfg.Anomaly.Endpoint),
		anomaly.WithAuthToken(string(cfg.Anomaly.AuthToken)),
	)

	pipeline, err := anomaly.NewPipeline(anomaly.PipelineOptions{
		Detector:      det,
		BatchSize:     cfg.Anomaly.BatchSize,
		FlushInterval: time.Duration(cfg.Anomaly.FlushInterval),
		Threshold:     cfg.Anomaly.Threshold,
		FailOpen:      cfg.Anomaly.FailOpen,
		OnScore: func(score float64) {
			metrics.GetCollector().SetAnomalyScore(score)
		},
		OnAnomaly: func(rec anomaly.FlowRecord, score anomaly.AnomalyScore) {
			logging.Info("anomaly detected", logging.Fields{
				"source_ip": rec.SourceIP,
				"dest_ip":   rec.DestIP,
				"port":      rec.Port,
				"protocol":  rec.Protocol,
				"score":     score.Score,
				"reason":    score.Reason,
			})
			if runner.manager != nil {
				runner.manager.Emit(alert.Alert{
					Timestamp: time.Now(),
					Source:    "ztap-anomaly",
					Severity:  alert.SeverityWarning,
					Title:     "Network anomaly detected",
					Message: fmt.Sprintf("flow %s -> %s:%d (%s) scored %.1f: %s",
						rec.SourceIP, rec.DestIP, rec.Port, rec.Protocol, score.Score, score.Reason),
					DedupKey: fmt.Sprintf("anomaly:%s:%d", rec.SourceIP, rec.Port),
					Details: map[string]any{
						"source_ip": rec.SourceIP,
						"dest_ip":   rec.DestIP,
						"port":      rec.Port,
						"protocol":  rec.Protocol,
						"score":     score.Score,
						"reason":    score.Reason,
					},
				})
			}
			if auditLogger != nil {
				_ = auditLogger.Log(audit.EventAnomalyDetected, "anomaly", rec.SourceIP, "detected", map[string]any{
					"dest_ip":  rec.DestIP,
					"port":     rec.Port,
					"protocol": rec.Protocol,
					"score":    score.Score,
					"reason":   score.Reason,
				})
			}
		},
		OnError: func(err error) {
			if cfg.Anomaly.FailOpen {
				logging.Warnf("anomaly detection: %v", err)
			} else {
				logging.Errorf("anomaly detection failed (fail_open=false, pipeline stopped): %v", err)
			}
		},
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("creating anomaly pipeline: %w", err)
	}
	runner.pipeline = pipeline

	monitor := flow.NewMonitor(createFlowReader())
	if err := monitor.Start(ctx); err != nil {
		cancel()
		return nil, fmt.Errorf("starting flow monitor for anomaly detection: %w", err)
	}
	runner.monitor = monitor

	pipeline.Start(ctx)
	go func() {
		defer close(runner.done)
		events := monitor.Subscribe(ctx)
		for event := range events {
			pipeline.Submit(flowToAnomalyRecord(event))
		}
	}()

	logging.Info("anomaly detection pipeline started", logging.Fields{
		"endpoint":   string(cfg.Anomaly.Endpoint),
		"batch_size": cfg.Anomaly.BatchSize,
		"threshold":  cfg.Anomaly.Threshold,
		"fail_open":  cfg.Anomaly.FailOpen,
	})
	return runner, nil
}

// Stop shuts the pipeline down: cancel the context, wait for the run loop,
// stop the flow monitor, and close the alert manager.
func (r *anomalyRunner) Stop() {
	if r == nil {
		return
	}
	r.cancel()
	<-r.done
	if r.monitor != nil {
		if err := r.monitor.Stop(); err != nil {
			logging.Warnf("failed to stop anomaly flow monitor: %v", err)
		}
	}
	if r.manager != nil {
		r.manager.Close()
	}
}

// flowToAnomalyRecord converts a flow event into the anomaly service schema.
// The eBPF/WFP event does not carry byte counts, so Bytes is left at zero.
func flowToAnomalyRecord(event flow.FlowEvent) anomaly.FlowRecord {
	return anomaly.FlowRecord{
		SourceIP:  event.SourceIP.String(),
		DestIP:    event.DestIP.String(),
		Port:      int(event.DestPort),
		Protocol:  event.Protocol,
		Timestamp: event.Timestamp,
	}
}
