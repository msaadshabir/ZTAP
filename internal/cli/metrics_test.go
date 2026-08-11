package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"ztap/internal/config"
	"ztap/internal/metrics"
)

func TestStartMetricsServerExportsAnomalyScore(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve metrics port: %v", err)
	}
	address := probe.Addr().String()
	_ = probe.Close()

	metrics.GetCollector().SetAnomalyScore(42.5)
	cfg := &config.Config{}
	cfg.Metrics.Enabled = true
	cfg.Metrics.Listen = address
	cfg.Metrics.Path = "/metrics"

	ctx, cancel := context.WithCancel(context.Background())
	stop, err := startMetricsServer(ctx, cfg)
	if err != nil {
		cancel()
		t.Fatalf("startMetricsServer: %v", err)
	}
	defer func() {
		cancel()
		if stop != nil {
			stop()
		}
	}()

	var body string
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		response, requestErr := http.Get(fmt.Sprintf("http://%s/metrics", address))
		if requestErr == nil {
			data, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr != nil {
				t.Fatalf("read metrics response: %v", readErr)
			}
			body = string(data)
			if strings.Contains(body, "ztap_anomaly_score 42.5") {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if body == "" {
		t.Fatal("metrics endpoint never became available")
	}
	t.Fatalf("metrics response did not contain anomaly score: %s", body)
}
