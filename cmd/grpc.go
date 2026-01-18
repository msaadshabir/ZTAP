package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"ztap/pkg/alert"
	"ztap/pkg/apigrpc"

	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v3"
)

var grpcCmd = &cobra.Command{
	Use:   "grpc",
	Short: "Run the ZTAP gRPC server",
}

var grpcServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the gRPC API server",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := loadGRPCServerConfig()
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

		am, err := getAuthManagerFromConfig()
		if err != nil {
			return err
		}
		defer am.Close()

		srv, err := apigrpc.NewServer(apigrpc.ServerOptions{Config: cfg, AuthManager: am, Alerts: alertManager})
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

type grpcConfigFile struct {
	GRPC struct {
		Listen string `yaml:"listen"`
		Auth   struct {
			Enabled *bool `yaml:"enabled"`
		} `yaml:"auth"`
		TLS struct {
			Enabled  *bool  `yaml:"enabled"`
			CertFile string `yaml:"cert_file"`
			KeyFile  string `yaml:"key_file"`
		} `yaml:"tls"`
		RateLimit struct {
			Enabled *bool `yaml:"enabled"`

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

			ExemptMethods []string `yaml:"exempt_methods"`
		} `yaml:"rate_limit"`
	} `yaml:"grpc"`
}

func loadGRPCServerConfig() (apigrpc.Config, error) {
	path := os.Getenv("ZTAP_CONFIG")
	if path == "" {
		path = "config.yaml"
	}

	cfg := apigrpc.Config{
		Listen:      "127.0.0.1:9092",
		AuthEnabled: true,
		TLS: apigrpc.TLSConfig{
			Enabled: false,
		},
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return apigrpc.Config{}, fmt.Errorf("reading config file %s: %w", path, err)
	}

	var fileCfg grpcConfigFile
	if err := yaml.Unmarshal(data, &fileCfg); err != nil {
		return apigrpc.Config{}, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	if strings.TrimSpace(fileCfg.GRPC.Listen) != "" {
		cfg.Listen = strings.TrimSpace(fileCfg.GRPC.Listen)
	}
	if fileCfg.GRPC.Auth.Enabled != nil {
		cfg.AuthEnabled = *fileCfg.GRPC.Auth.Enabled
	}
	if fileCfg.GRPC.TLS.Enabled != nil {
		cfg.TLS.Enabled = *fileCfg.GRPC.TLS.Enabled
	}
	if strings.TrimSpace(fileCfg.GRPC.TLS.CertFile) != "" {
		cfg.TLS.CertFile = fileCfg.GRPC.TLS.CertFile
	}
	if strings.TrimSpace(fileCfg.GRPC.TLS.KeyFile) != "" {
		cfg.TLS.KeyFile = fileCfg.GRPC.TLS.KeyFile
	}

	if fileCfg.GRPC.RateLimit.Enabled != nil {
		cfg.RateLimit.Enabled = *fileCfg.GRPC.RateLimit.Enabled
	}
	if fileCfg.GRPC.RateLimit.Unauthenticated.RPS != 0 {
		cfg.RateLimit.Unauthenticated.RPS = fileCfg.GRPC.RateLimit.Unauthenticated.RPS
	}
	if fileCfg.GRPC.RateLimit.Unauthenticated.Burst != 0 {
		cfg.RateLimit.Unauthenticated.Burst = fileCfg.GRPC.RateLimit.Unauthenticated.Burst
	}
	if fileCfg.GRPC.RateLimit.PerIP.RPS != 0 {
		cfg.RateLimit.PerIP.RPS = fileCfg.GRPC.RateLimit.PerIP.RPS
	}
	if fileCfg.GRPC.RateLimit.PerIP.Burst != 0 {
		cfg.RateLimit.PerIP.Burst = fileCfg.GRPC.RateLimit.PerIP.Burst
	}
	if fileCfg.GRPC.RateLimit.PerToken.RPS != 0 {
		cfg.RateLimit.PerToken.RPS = fileCfg.GRPC.RateLimit.PerToken.RPS
	}
	if fileCfg.GRPC.RateLimit.PerToken.Burst != 0 {
		cfg.RateLimit.PerToken.Burst = fileCfg.GRPC.RateLimit.PerToken.Burst
	}
	if len(fileCfg.GRPC.RateLimit.ExemptMethods) > 0 {
		cfg.RateLimit.ExemptMethods = append([]string(nil), fileCfg.GRPC.RateLimit.ExemptMethods...)
	}

	return cfg, nil
}

func init() {
	grpcServeCmd.Flags().String("listen", "", "Listen address (host:port)")
	grpcServeCmd.Flags().Bool("auth", true, "Require auth for RPCs")
	grpcServeCmd.Flags().Bool("tls", false, "Enable TLS")
	grpcServeCmd.Flags().String("tls-cert", "", "Path to TLS certificate file")
	grpcServeCmd.Flags().String("tls-key", "", "Path to TLS private key file")

	grpcServeCmd.Flags().Bool("rate-limit", false, "Enable gRPC rate limiting")
	grpcServeCmd.Flags().Float64("rate-limit-per-ip-rps", 0, "Per-IP requests per second")
	grpcServeCmd.Flags().Int("rate-limit-per-ip-burst", 0, "Per-IP burst")
	grpcServeCmd.Flags().Float64("rate-limit-per-token-rps", 0, "Per-token requests per second")
	grpcServeCmd.Flags().Int("rate-limit-per-token-burst", 0, "Per-token burst")
	grpcServeCmd.Flags().Float64("rate-limit-unauth-rps", 0, "Unauthenticated requests per second")
	grpcServeCmd.Flags().Int("rate-limit-unauth-burst", 0, "Unauthenticated burst")

	grpcCmd.AddCommand(grpcServeCmd)
	rootCmd.AddCommand(grpcCmd)
}
