package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"ztap/internal/alert"
	"ztap/internal/apigrpc"
	"ztap/internal/config"
	"ztap/internal/logging"

	"github.com/spf13/cobra"
)

func newGrpcCmd(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "grpc",
		Short: "Run the ZTAP gRPC server",
	}
	c.AddCommand(newGrpcServeCmd(app))
	return c
}

func newGrpcServeCmd(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "serve",
		Short: "Start the gRPC API server",
		RunE: func(cmd *cobra.Command, args []string) error {
			central, err := app.Config()
			if err != nil {
				return err
			}
			cfg := grpcServerConfig(central)

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

			disc, err := getDiscoveryBackend(central)
			if err != nil {
				logging.Warnf("Failed to load discovery backend (podSelector targets via gRPC will not be resolvable): %v", err)
				disc = nil
			}
			auditLogger, err := auditLoggerFromConfig(central)
			if err != nil {
				return err
			}
			srv, err := apigrpc.NewServer(apigrpc.ServerOptions{Config: cfg, AuthManager: am, Alerts: alertManager, AuditLogger: auditLogger, Discovery: disc, ResolveLabelsInterval: 5 * time.Second, PolicyManager: policyManager, ClusterElection: clusterElection})
			if err != nil {
				return err
			}

			status := "plaintext"
			if cfg.TLS.Enabled {
				status = "TLS"
			}
			fmt.Printf("starting grpc server on %s (%s)\n", srv.ListenAddr(), status)
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
	c.Flags().Bool("auth", true, "Require auth for RPCs")
	c.Flags().Bool("tls", false, "Enable TLS")
	c.Flags().String("tls-cert", "", "Path to TLS certificate file")
	c.Flags().String("tls-key", "", "Path to TLS private key file")
	c.Flags().Bool("rate-limit", false, "Enable gRPC rate limiting")
	c.Flags().Float64("rate-limit-per-ip-rps", 0, "Per-IP requests per second")
	c.Flags().Int("rate-limit-per-ip-burst", 0, "Per-IP burst")
	c.Flags().Float64("rate-limit-per-token-rps", 0, "Per-token requests per second")
	c.Flags().Int("rate-limit-per-token-burst", 0, "Per-token burst")
	c.Flags().Float64("rate-limit-unauth-rps", 0, "Unauthenticated requests per second")
	c.Flags().Int("rate-limit-unauth-burst", 0, "Unauthenticated burst")
	return c
}

// grpcServerConfig converts the central grpc section into the gRPC server's
// own config type.
func grpcServerConfig(cfg *config.Config) apigrpc.Config {
	return apigrpc.Config{
		Listen:      string(cfg.GRPC.Listen),
		AuthEnabled: cfg.GRPC.Auth.Enabled,
		TLS: apigrpc.TLSConfig{
			Enabled:      cfg.GRPC.TLS.Enabled,
			CertFile:     cfg.GRPC.TLS.CertFile,
			KeyFile:      cfg.GRPC.TLS.KeyFile,
			ClientAuth:   cfg.GRPC.TLS.ClientAuth,
			ClientCAFile: cfg.GRPC.TLS.ClientCAFile,
		},
		RateLimit: apigrpc.RateLimitConfig{
			Enabled: cfg.GRPC.RateLimit.Enabled,
			Unauthenticated: apigrpc.RateLimitBucketConfig{
				RPS:   cfg.GRPC.RateLimit.Unauthenticated.RPS,
				Burst: cfg.GRPC.RateLimit.Unauthenticated.Burst,
			},
			PerIP: apigrpc.RateLimitBucketConfig{
				RPS:   cfg.GRPC.RateLimit.PerIP.RPS,
				Burst: cfg.GRPC.RateLimit.PerIP.Burst,
			},
			PerToken: apigrpc.RateLimitBucketConfig{
				RPS:   cfg.GRPC.RateLimit.PerToken.RPS,
				Burst: cfg.GRPC.RateLimit.PerToken.Burst,
			},
			ExemptMethods: append([]string(nil), cfg.GRPC.RateLimit.ExemptMethods...),
		},
	}
}
