package cli

import (
	"fmt"
	"strings"

	"ztap/internal/metrics"

	"github.com/spf13/cobra"
)

func newMetricsCmd(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "metrics",
		Short: "Start Prometheus metrics server",
		Long:  `Start HTTP server exposing ZTAP metrics in Prometheus format`,
		Run: func(cmd *cobra.Command, args []string) {
			central := app.Config()

			// metrics.enabled gates the command; metrics.port/path provide the
			// defaults (flag > env ZTAP_METRICS_LISTEN > config > default).
			if !central.Metrics.Enabled {
				fmt.Println("Metrics server is disabled (metrics.enabled: false). Set it to true or remove the key to enable.")
				return
			}

			port := central.Metrics.Port
			if cmd.Flags().Changed("port") {
				port, _ = cmd.Flags().GetInt("port")
			}
			path := string(central.Metrics.Path)
			if path == "" {
				path = "/metrics"
			}

			listen := strings.TrimSpace(central.Metrics.Listen)
			if listen == "" {
				listen = fmt.Sprintf("127.0.0.1:%d", port)
			}

			fmt.Printf("Starting ZTAP metrics server on %s\n", listen)
			fmt.Printf("Access metrics at: http://%s%s\n", listen, path)
			fmt.Println("Press Ctrl+C to stop")

			if err := metrics.StartServer(listen, path); err != nil {
				fmt.Printf("Error: Failed to start metrics server: %v\n", err)
			}
		},
	}
	c.Flags().IntP("port", "p", 9090, "Port for metrics server")
	return c
}
