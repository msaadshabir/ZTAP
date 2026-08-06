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
	"ztap/internal/logging"
	"ztap/internal/metrics"

	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v3"
)

func newApiCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "api",
		Short: "Run the ZTAP API server",
	}
	c.AddCommand(newApiServeCmd())
	return c
}

func newApiServeCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "serve",
		Short: "Start the REST API server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadAPIServerConfig()
			if err != nil {
				return err
			}

			alertCfg, err := loadAlertConfig()
			if err != nil {
				return err
			}

			var alertManager *alert.Manager
			if alertCfg.Enabled {
				alertManager, err = alert.NewManagerFromConfig(alertCfg)
				if err != nil {
					return err
				}
			}

			listen, _ := cmd.Flags().GetString("listen")
			if strings.TrimSpace(listen) != "" {
				cfg.Listen = listen
			}
			authEnabled, _ := cmd.Flags().GetBool("auth")
			cfg.AuthEnabled = authEnabled

			rlEnabled, _ := cmd.Flags().GetBool("rate-limit")
			if rlEnabled {
				cfg.RateLimit.Enabled = true
			}
			rlTrustProxy, _ := cmd.Flags().GetBool("rate-limit-trust-proxy")
			if rlTrustProxy {
				cfg.RateLimit.TrustProxyHeaders = true
			}
			rlPerIPRPS, _ := cmd.Flags().GetFloat64("rate-limit-per-ip-rps")
			if rlPerIPRPS > 0 {
				cfg.RateLimit.PerIP.RPS = rlPerIPRPS
			}
			rlPerIPBurst, _ := cmd.Flags().GetInt("rate-limit-per-ip-burst")
			if rlPerIPBurst > 0 {
				cfg.RateLimit.PerIP.Burst = rlPerIPBurst
			}
			rlPerTokenRPS, _ := cmd.Flags().GetFloat64("rate-limit-per-token-rps")
			if rlPerTokenRPS > 0 {
				cfg.RateLimit.PerToken.RPS = rlPerTokenRPS
			}
			rlPerTokenBurst, _ := cmd.Flags().GetInt("rate-limit-per-token-burst")
			if rlPerTokenBurst > 0 {
				cfg.RateLimit.PerToken.Burst = rlPerTokenBurst
			}
			rlUnauthRPS, _ := cmd.Flags().GetFloat64("rate-limit-unauth-rps")
			if rlUnauthRPS > 0 {
				cfg.RateLimit.Unauthenticated.RPS = rlUnauthRPS
			}
			rlUnauthBurst, _ := cmd.Flags().GetInt("rate-limit-unauth-burst")
			if rlUnauthBurst > 0 {
				cfg.RateLimit.Unauthenticated.Burst = rlUnauthBurst
			}

			tlsEnabled, _ := cmd.Flags().GetBool("tls")
			if tlsEnabled {
				cfg.TLS.Enabled = true
			}
			tlsCert, _ := cmd.Flags().GetString("tls-cert")
			if strings.TrimSpace(tlsCert) != "" {
				cfg.TLS.CertFile = tlsCert
			}
			tlsKey, _ := cmd.Flags().GetString("tls-key")
			if strings.TrimSpace(tlsKey) != "" {
				cfg.TLS.KeyFile = tlsKey
			}

			// Initialize metrics so /metrics includes ZTAP counters.
			metrics.GetCollector()

			am, err := getAuthManagerFromConfig()
			if err != nil {
				return err
			}
			defer func() { _ = am.Close() }()

			clusterElection, policyManager, cleanup, err := initPolicyRuntime(context.Background(), cfg.Listen)
			if err != nil {
				return err
			}
			defer cleanup()

			sessionsPath, err := resolvedSessionsSQLitePath()
			if err != nil {
				return err
			}
			disc, err := getDiscoveryBackend()
			if err != nil {
				logging.Warnf("Failed to load discovery backend (podSelector targets via API will not be resolvable): %v", err)
				disc = nil
			}
			srv, err := apihttp.NewServer(apihttp.ServerOptions{Config: cfg, AuthManager: am, Alerts: alertManager, SessionsSQLitePath: sessionsPath, Discovery: disc, ResolveLabelsInterval: 5 * time.Second, PolicyManager: policyManager, ClusterElection: clusterElection})
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

type apiConfigFile struct {
	API struct {
		Listen string `yaml:"listen"`
		Auth   struct {
			Enabled *bool `yaml:"enabled"`
		} `yaml:"auth"`
		TLS struct {
			Enabled      *bool  `yaml:"enabled"`
			CertFile     string `yaml:"cert_file"`
			KeyFile      string `yaml:"key_file"`
			ClientAuth   *bool  `yaml:"client_auth"`
			ClientCAFile string `yaml:"client_ca_file"`
		} `yaml:"tls"`
		RateLimit struct {
			Enabled           *bool `yaml:"enabled"`
			TrustProxyHeaders *bool `yaml:"trust_proxy_headers"`

			Unauthenticated struct {
				RPS   float64 `yaml:"rps"`
				Burst int     `yaml:"burst"`
			} `yaml:"unauthenticated"`
			PerIP struct {
				RPS   float64 `yaml:"rps"`
				Burst int     `yaml:"burst"`
			} `yaml:"per_ip"`
			PerToken struct {
				RPS   float64 `yaml:"rps"`
				Burst int     `yaml:"burst"`
			} `yaml:"per_token"`

			ExemptPaths []string `yaml:"exempt_paths"`
		} `yaml:"rate_limit"`
	} `yaml:"api"`
}

func loadAPIServerConfig() (apihttp.Config, error) {
	path := os.Getenv("ZTAP_CONFIG")
	if path == "" {
		path = "config.yaml"
	}

	cfg := apihttp.Config{
		Listen:      "127.0.0.1:8080",
		AuthEnabled: true,
		TLS: apihttp.TLSConfig{
			Enabled: false,
		},
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return apihttp.Config{}, fmt.Errorf("reading config file %s: %w", path, err)
	}

	var fileCfg apiConfigFile
	if err := yaml.Unmarshal(data, &fileCfg); err != nil {
		return apihttp.Config{}, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	if strings.TrimSpace(fileCfg.API.Listen) != "" {
		cfg.Listen = strings.TrimSpace(fileCfg.API.Listen)
	}
	if fileCfg.API.Auth.Enabled != nil {
		cfg.AuthEnabled = *fileCfg.API.Auth.Enabled
	}
	if fileCfg.API.TLS.Enabled != nil {
		cfg.TLS.Enabled = *fileCfg.API.TLS.Enabled
	}
	if strings.TrimSpace(fileCfg.API.TLS.CertFile) != "" {
		cfg.TLS.CertFile = fileCfg.API.TLS.CertFile
	}
	if strings.TrimSpace(fileCfg.API.TLS.KeyFile) != "" {
		cfg.TLS.KeyFile = fileCfg.API.TLS.KeyFile
	}
	if fileCfg.API.TLS.ClientAuth != nil {
		cfg.TLS.ClientAuth = *fileCfg.API.TLS.ClientAuth
	}
	if strings.TrimSpace(fileCfg.API.TLS.ClientCAFile) != "" {
		cfg.TLS.ClientCAFile = fileCfg.API.TLS.ClientCAFile
	}

	if fileCfg.API.RateLimit.Enabled != nil {
		cfg.RateLimit.Enabled = *fileCfg.API.RateLimit.Enabled
	}
	if fileCfg.API.RateLimit.TrustProxyHeaders != nil {
		cfg.RateLimit.TrustProxyHeaders = *fileCfg.API.RateLimit.TrustProxyHeaders
	}
	if fileCfg.API.RateLimit.Unauthenticated.RPS != 0 {
		cfg.RateLimit.Unauthenticated.RPS = fileCfg.API.RateLimit.Unauthenticated.RPS
	}
	if fileCfg.API.RateLimit.Unauthenticated.Burst != 0 {
		cfg.RateLimit.Unauthenticated.Burst = fileCfg.API.RateLimit.Unauthenticated.Burst
	}
	if fileCfg.API.RateLimit.PerIP.RPS != 0 {
		cfg.RateLimit.PerIP.RPS = fileCfg.API.RateLimit.PerIP.RPS
	}
	if fileCfg.API.RateLimit.PerIP.Burst != 0 {
		cfg.RateLimit.PerIP.Burst = fileCfg.API.RateLimit.PerIP.Burst
	}
	if fileCfg.API.RateLimit.PerToken.RPS != 0 {
		cfg.RateLimit.PerToken.RPS = fileCfg.API.RateLimit.PerToken.RPS
	}
	if fileCfg.API.RateLimit.PerToken.Burst != 0 {
		cfg.RateLimit.PerToken.Burst = fileCfg.API.RateLimit.PerToken.Burst
	}
	if len(fileCfg.API.RateLimit.ExemptPaths) > 0 {
		cfg.RateLimit.ExemptPaths = append([]string(nil), fileCfg.API.RateLimit.ExemptPaths...)
	}

	return cfg, nil
}
