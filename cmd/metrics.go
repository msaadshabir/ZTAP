package cmd

import (
	"fmt"

	"ztap/pkg/metrics"

	"github.com/spf13/cobra"
)

var metricsCmd = &cobra.Command{
	Use:   "metrics",
	Short: "Start Prometheus metrics server",
	Long:  `Start HTTP server exposing ZTAP metrics in Prometheus format`,
	Run: func(cmd *cobra.Command, args []string) {
		port, _ := cmd.Flags().GetInt("port")

		fmt.Printf("Starting ZTAP metrics server on port %d\n", port)
		fmt.Println("Access metrics at: http://localhost:" + fmt.Sprint(port) + "/metrics")
		fmt.Println("Press Ctrl+C to stop")

		if err := metrics.StartServer(port); err != nil {
			fmt.Printf("Error: Failed to start metrics server: %v\n", err)
		}
	},
}

func init() {
	metricsCmd.Flags().IntP("port", "p", 9090, "Port for metrics server")
	rootCmd.AddCommand(metricsCmd)
}
