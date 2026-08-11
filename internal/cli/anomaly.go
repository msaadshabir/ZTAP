package cli

import (
	"context"
	"fmt"
	"sync"
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
	pipeline        *anomaly.Pipeline
	monitor         *flow.Monitor
	manager         *alert.Manager
	alertCancel     context.CancelFunc
	metricsStop     func()
	auditLogger     *audit.AuditLogger
	ownsAuditLogger bool
	cancel          context.CancelFunc
	done            chan struct{}
	stopOnce        sync.Once
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
	return startAnomalyRunnerWithReader(parent, cfg, auditLogger, nil)
}

// startAnomalyRunnerWithReader is kept injectable for tests. Production calls
// use the platform reader returned by createAnomalyFlowReader; unlike the
// interactive `ztap flows` command, anomaly detection never uses synthetic
// events as a fallback.
func startAnomalyRunnerWithReader(parent context.Context, cfg *config.Config, auditLogger *audit.AuditLogger, reader flow.FlowReader) (*anomalyRunner, error) {
	if !cfg.Anomaly.Enabled {
		return nil, nil
	}

	ctx, cancel := context.WithCancel(parent)
	runner := &anomalyRunner{cancel: cancel, done: make(chan struct{})}

	if stopMetrics, metricsErr := startMetricsServer(ctx, cfg); metricsErr != nil {
		logging.Warnf("metrics server disabled: %v", metricsErr)
	} else {
		runner.metricsStop = stopMetrics
	}
	if auditLogger == nil {
		auditLogger = newOptionalAnomalyAuditLogger(cfg)
		runner.auditLogger = auditLogger
		runner.ownsAuditLogger = auditLogger != nil
	}

	if alertCfg := alertConfig(cfg); alertCfg.Enabled {
		mgr, err := alert.NewManagerFromConfig(alertCfg)
		if err != nil {
			logging.Warnf("anomaly alerts disabled: %v", err)
		} else {
			runner.manager = mgr
			alertCtx, alertCancel := context.WithCancel(context.Background())
			runner.alertCancel = alertCancel
			mgr.Start(alertCtx)
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
		ThresholdSet:  true,
		FailOpen:      cfg.Anomaly.FailOpen,
		FailOpenSet:   true,
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
		runner.cleanupFailedStart()
		return nil, fmt.Errorf("creating anomaly pipeline: %w", err)
	}
	runner.pipeline = pipeline

	if reader == nil {
		reader, err = createAnomalyFlowReader()
		if err != nil {
			runner.cleanupFailedStart()
			return nil, fmt.Errorf("creating flow reader for anomaly detection: %w", err)
		}
	}
	monitor := flow.NewMonitor(reader)
	events := monitor.SubscribeBeforeStart(ctx)
	if err := monitor.Start(ctx); err != nil {
		_ = monitor.Stop()
		runner.cleanupFailedStart()
		return nil, fmt.Errorf("starting flow monitor for anomaly detection: %w", err)
	}
	runner.monitor = monitor

	pipeline.Start(ctx)
	go func() {
		defer close(runner.done)
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

// Stop shuts the pipeline down: cancel the context, stop the flow monitor,
// drain the pipeline and wait for every detached detection, then close the
// alert manager. This ordering keeps anomaly callbacks from using closed
// audit/alert resources.
func (r *anomalyRunner) Stop() {
	if r == nil {
		return
	}
	r.stopOnce.Do(func() {
		if r.cancel != nil {
			r.cancel()
		}
		if r.done != nil {
			<-r.done
		}
		if r.monitor != nil {
			if err := r.monitor.Stop(); err != nil {
				logging.Warnf("failed to stop anomaly flow monitor: %v", err)
			}
		}
		if r.pipeline != nil {
			r.pipeline.Wait()
		}
		if r.manager != nil {
			// Keep alert workers alive while detached detections finish so
			// callbacks can enqueue alerts. Close drains the queue before the
			// independent alert context is cancelled.
			r.manager.Close()
		}
		if r.alertCancel != nil {
			r.alertCancel()
		}
		if r.ownsAuditLogger && r.auditLogger != nil {
			_ = r.auditLogger.Close()
		}
		if r.metricsStop != nil {
			r.metricsStop()
		}
	})
}

func (r *anomalyRunner) cleanupFailedStart() {
	if r.cancel != nil {
		r.cancel()
	}
	if r.manager != nil {
		r.manager.Close()
	}
	if r.alertCancel != nil {
		r.alertCancel()
	}
	if r.ownsAuditLogger && r.auditLogger != nil {
		_ = r.auditLogger.Close()
	}
	if r.metricsStop != nil {
		r.metricsStop()
	}
}

func newOptionalAnomalyAuditLogger(cfg *config.Config) *audit.AuditLogger {
	if !cfg.Anomaly.Enabled {
		return nil
	}
	logger, err := auditLoggerFromConfig(cfg)
	if err != nil {
		logging.Warnf("anomaly audit logging disabled: %v", err)
		return nil
	}
	return logger
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
