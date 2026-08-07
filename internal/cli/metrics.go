package cli

import (
	"fmt"
	"os"
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
			port, _ := cmd.Flags().GetInt("port")
			listen := strings.TrimSpace(os.Getenv("ZTAP_METRICS_LISTEN"))
			if listen == "" {
				listen = fmt.Sprintf("127.0.0.1:%d", port)
			}

			fmt.Printf("Starting ZTAP metrics server on %s\n", listen)
			fmt.Println("Access metrics at: http://" + listen + "/metrics")
			fmt.Println("Press Ctrl+C to stop")

			if err := metrics.StartServer(port); err != nil {
				fmt.Printf("Error: Failed to start metrics server: %v\n", err)
			}
		},
	}
	c.Flags().IntP("port", "p", 9090, "Port for metrics server")
	return c
}
