package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"ztap/internal/config"
	"ztap/internal/logging"
	"ztap/internal/metrics"

	"github.com/spf13/cobra"
)

// startMetricsServer embeds the Prometheus endpoint in a long-running
// agent/enforcement process. The standalone `ztap metrics` command remains
// available, but anomaly scores must be exported by the process that receives
// and scores the flows.
func startMetricsServer(ctx context.Context, cfg *config.Config) (func(), error) {
	if !cfg.Metrics.Enabled {
		return nil, nil
	}

	path := strings.TrimSpace(string(cfg.Metrics.Path))
	if path == "" {
		path = "/metrics"
	}
	if err := metrics.ValidatePath(path); err != nil {
		return nil, err
	}

	listen := strings.TrimSpace(cfg.Metrics.Listen)
	if listen == "" {
		port := cfg.Metrics.Port
		if port <= 0 {
			port = 9090
		}
		listen = fmt.Sprintf("127.0.0.1:%d", port)
	}

	srv, err := metrics.NewServer(listen, path)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("listen for metrics on %s: %w", listen, err)
	}

	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logging.Warnf("failed to stop metrics server: %v", err)
			}
		})
	}

	go func() {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logging.Warnf("metrics server stopped unexpectedly: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		stop()
	}()

	logging.Infof("metrics server started on %s%s", listen, path)
	return stop, nil
}

func newMetricsCmd(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "metrics",
		Short: "Start Prometheus metrics server",
		Long:  `Start HTTP server exposing ZTAP metrics in Prometheus format`,
		RunE: func(cmd *cobra.Command, args []string) error {
			central, err := app.Config()
			if err != nil {
				return err
			}

			// metrics.enabled gates the command; metrics.port/path provide the
			// defaults (flag > env ZTAP_METRICS_LISTEN > config > default).
			if !central.Metrics.Enabled {
				fmt.Println("Metrics server is disabled (metrics.enabled: false). Set it to true or remove the key to enable.")
				return nil
			}

			port := central.Metrics.Port
			if cmd.Flags().Changed("port") {
				port, _ = cmd.Flags().GetInt("port")
			}
			path := string(central.Metrics.Path)
			if path == "" {
				path = "/metrics"
			}
			if err := metrics.ValidatePath(path); err != nil {
				return err
			}

			listen := strings.TrimSpace(central.Metrics.Listen)
			if listen == "" {
				listen = fmt.Sprintf("127.0.0.1:%d", port)
			}

			fmt.Printf("Starting ZTAP metrics server on %s\n", listen)
			fmt.Printf("Access metrics at: http://%s%s\n", listen, path)
			fmt.Println("Press Ctrl+C to stop")

			if err := metrics.StartServer(listen, path); err != nil {
				return fmt.Errorf("failed to start metrics server: %w", err)
			}
			return nil
		},
	}
	c.Flags().IntP("port", "p", 9090, "Port for metrics server")
	return c
}
