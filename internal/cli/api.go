package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"ztap/internal/alert"
	"ztap/internal/apihttp"
	"ztap/internal/config"
	"ztap/internal/logging"
	"ztap/internal/metrics"

	"github.com/spf13/cobra"
)

func newApiCmd(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "api",
		Short: "Run the ZTAP API server",
	}
	c.AddCommand(newApiServeCmd(app))
	return c
}

func newApiServeCmd(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "serve",
		Short: "Start the REST API server",
		RunE: func(cmd *cobra.Command, args []string) error {
			central, err := app.Config()
			if err != nil {
				return err
			}
			cfg := apiServerConfig(central)

			// Flags take precedence over config (flag > env > config > default).
			listen, _ := cmd.Flags().GetString("listen")
			if strings.TrimSpace(listen) != "" {
				cfg.Listen = listen
			}
			if cmd.Flags().Changed("auth") {
				cfg.AuthEnabled, _ = cmd.Flags().GetBool("auth")
			}
			if cmd.Flags().Changed("tls") {
				cfg.TLS.Enabled, _ = cmd.Flags().GetBool("tls")
			}
			if v, _ := cmd.Flags().GetString("tls-cert"); strings.TrimSpace(v) != "" {
				cfg.TLS.CertFile = v
			}
			if v, _ := cmd.Flags().GetString("tls-key"); strings.TrimSpace(v) != "" {
				cfg.TLS.KeyFile = v
			}
			if cmd.Flags().Changed("rate-limit") {
				cfg.RateLimit.Enabled, _ = cmd.Flags().GetBool("rate-limit")
			}
			if cmd.Flags().Changed("rate-limit-trust-proxy") {
				cfg.RateLimit.TrustProxyHeaders, _ = cmd.Flags().GetBool("rate-limit-trust-proxy")
			}
			if cmd.Flags().Changed("rate-limit-per-ip-rps") {
				cfg.RateLimit.PerIP.RPS, _ = cmd.Flags().GetFloat64("rate-limit-per-ip-rps")
			}
			if cmd.Flags().Changed("rate-limit-per-ip-burst") {
				cfg.RateLimit.PerIP.Burst, _ = cmd.Flags().GetInt("rate-limit-per-ip-burst")
			}
			if cmd.Flags().Changed("rate-limit-per-token-rps") {
				cfg.RateLimit.PerToken.RPS, _ = cmd.Flags().GetFloat64("rate-limit-per-token-rps")
			}
			if cmd.Flags().Changed("rate-limit-per-token-burst") {
				cfg.RateLimit.PerToken.Burst, _ = cmd.Flags().GetInt("rate-limit-per-token-burst")
			}
			if cmd.Flags().Changed("rate-limit-unauth-rps") {
				cfg.RateLimit.Unauthenticated.RPS, _ = cmd.Flags().GetFloat64("rate-limit-unauth-rps")
			}
			if cmd.Flags().Changed("rate-limit-unauth-burst") {
				cfg.RateLimit.Unauthenticated.Burst, _ = cmd.Flags().GetInt("rate-limit-unauth-burst")
			}

			alertCfg := alertConfig(central)

			var alertManager *alert.Manager
			if alertCfg.Enabled {
				alertManager, err := alert.NewManagerFromConfig(alertCfg)
				if err != nil {
					return err
				}
				defer alertManager.Close()
			}

			// Initialize metrics so /metrics includes ZTAP counters.
			metrics.GetCollector()

			am, err := getAuthManagerFromConfig(central)
			if err != nil {
				return err
			}
			defer func() { _ = am.Close() }()

			clusterElection, policyManager, cleanup, err := initPolicyRuntime(context.Background(), cfg.Listen, central)
			if err != nil {
				return err
			}
			defer cleanup()

			sessionsPath, err := resolvedSessionsSQLitePath(central)
			if err != nil {
				return err
			}
			disc, err := getDiscoveryBackend(central)
			if err != nil {
				logging.Warnf("Failed to load discovery backend (podSelector targets via API will not be resolvable): %v", err)
				disc = nil
			}
			auditLogger, err := auditLoggerFromConfig(central)
			if err != nil {
				return err
			}
			srv, err := apihttp.NewServer(apihttp.ServerOptions{Config: cfg, AuthManager: am, Alerts: alertManager, AuditLogger: auditLogger, SessionsSQLitePath: sessionsPath, Discovery: disc, ResolveLabelsInterval: 5 * time.Second, PolicyManager: policyManager, ClusterElection: clusterElection})
			if err != nil {
				return err
			}

			scheme := "http"
			if cfg.TLS.Enabled {
				scheme = "https"
			}
			fmt.Printf("starting api server on %s://%s\n", scheme, srv.ListenAddr())
			fmt.Println("press Ctrl+C to stop")

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigCh := make(chan os.Signal, 1)
			notifyStopSignals(sigCh)
			go func() {
				<-sigCh
				stopStopSignals(sigCh)
				cancel()
			}()

			err = srv.Serve(ctx)
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		},
	}
	c.Flags().String("listen", "", "Listen address (host:port)")
	c.Flags().Bool("auth", true, "Require auth for API endpoints")
	c.Flags().Bool("tls", false, "Enable TLS (HTTPS)")
	c.Flags().String("tls-cert", "", "Path to TLS certificate file")
	c.Flags().String("tls-key", "", "Path to TLS private key file")
	c.Flags().Bool("rate-limit", false, "Enable API rate limiting")
	c.Flags().Bool("rate-limit-trust-proxy", false, "Trust X-Forwarded-For / X-Real-IP")
	c.Flags().Float64("rate-limit-per-ip-rps", 0, "Per-IP requests per second")
	c.Flags().Int("rate-limit-per-ip-burst", 0, "Per-IP burst")
	c.Flags().Float64("rate-limit-per-token-rps", 0, "Per-token requests per second")
	c.Flags().Int("rate-limit-per-token-burst", 0, "Per-token burst")
	c.Flags().Float64("rate-limit-unauth-rps", 0, "Unauthenticated requests per second")
	c.Flags().Int("rate-limit-unauth-burst", 0, "Unauthenticated burst")
	return c
}

// apiServerConfig converts the central api section into the API server's own
// config type.
func apiServerConfig(cfg *config.Config) apihttp.Config {
	return apihttp.Config{
		Listen:      string(cfg.API.Listen),
		AuthEnabled: cfg.API.Auth.Enabled,
		TLS: apihttp.TLSConfig{
			Enabled:      cfg.API.TLS.Enabled,
			CertFile:     cfg.API.TLS.CertFile,
			KeyFile:      cfg.API.TLS.KeyFile,
			ClientAuth:   cfg.API.TLS.ClientAuth,
			ClientCAFile: cfg.API.TLS.ClientCAFile,
		},
		RateLimit: apihttp.RateLimitConfig{
			Enabled:           cfg.API.RateLimit.Enabled,
			TrustProxyHeaders: cfg.API.RateLimit.TrustProxyHeaders,
			Unauthenticated: apihttp.RateLimitBucketConfig{
				RPS:   cfg.API.RateLimit.Unauthenticated.RPS,
				Burst: cfg.API.RateLimit.Unauthenticated.Burst,
			},
			PerIP: apihttp.RateLimitBucketConfig{
				RPS:   cfg.API.RateLimit.PerIP.RPS,
				Burst: cfg.API.RateLimit.PerIP.Burst,
			},
			PerToken: apihttp.RateLimitBucketConfig{
				RPS:   cfg.API.RateLimit.PerToken.RPS,
				Burst: cfg.API.RateLimit.PerToken.Burst,
			},
			ExemptPaths: append([]string(nil), cfg.API.RateLimit.ExemptPaths...),
		},
	}
}
