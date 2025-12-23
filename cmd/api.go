package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"ztap/pkg/alert"
	"ztap/pkg/apihttp"
	"ztap/pkg/metrics"

	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v3"
)

var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Run the ZTAP API server",
}

var apiServeCmd = &cobra.Command{
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

		// Initialize metrics so /metrics includes ZTAP counters.
		metrics.GetCollector()

		srv, err := apihttp.NewServer(apihttp.ServerOptions{Config: cfg, Alerts: alertManager})
		if err != nil {
			return err
		}

		fmt.Printf("starting api server on http://%s\n", srv.ListenAddr())
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

type apiConfigFile struct {
	API struct {
		Listen string `yaml:"listen"`
		Auth   struct {
			Enabled *bool `yaml:"enabled"`
		} `yaml:"auth"`
	} `yaml:"api"`
}

func loadAPIServerConfig() (apihttp.Config, error) {
	path := os.Getenv("ZTAP_CONFIG")
	if path == "" {
		path = "config.yaml"
	}

	cfg := apihttp.Config{Listen: "127.0.0.1:8080", AuthEnabled: true}

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

	return cfg, nil
}

func init() {
	apiServeCmd.Flags().String("listen", "", "Listen address (host:port)")
	apiServeCmd.Flags().Bool("auth", true, "Require auth for API endpoints")

	apiCmd.AddCommand(apiServeCmd)
	rootCmd.AddCommand(apiCmd)
}
