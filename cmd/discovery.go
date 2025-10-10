package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"

	"ztap/pkg/discovery"

	"github.com/spf13/cobra"
)

var discoveryCmd = &cobra.Command{
	Use:   "discovery",
	Short: "Manage service discovery",
	Long:  "Register, deregister, and query services for label-based resolution",
}

var registerCmd = &cobra.Command{
	Use:   "register [name] [ip]",
	Short: "Register a service",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		ip := args[1]

		labels, _ := cmd.Flags().GetStringToString("labels")

		disc := getDiscoveryBackend()
		err := disc.RegisterService(name, ip, labels)
		if err != nil {
			return fmt.Errorf("failed to register service: %w", err)
		}

		fmt.Printf("Service '%s' registered with IP %s\n", name, ip)
		return nil
	},
}

var deregisterCmd = &cobra.Command{
	Use:   "deregister [name]",
	Short: "Deregister a service",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]

		disc := getDiscoveryBackend()
		err := disc.DeregisterService(name)
		if err != nil {
			return fmt.Errorf("failed to deregister service: %w", err)
		}

		fmt.Printf("Service '%s' deregistered\n", name)
		return nil
	},
}

var resolveCmd = &cobra.Command{
	Use:   "resolve",
	Short: "Resolve IPs for given labels",
	RunE: func(cmd *cobra.Command, args []string) error {
		labels, _ := cmd.Flags().GetStringToString("labels")
		if len(labels) == 0 {
			return fmt.Errorf("no labels provided")
		}

		disc := getDiscoveryBackend()
		ips, err := disc.ResolveLabels(labels)
		if err != nil {
			return fmt.Errorf("failed to resolve labels: %w", err)
		}

		fmt.Printf("Found %d IPs matching labels %v:\n", len(ips), labels)
		for _, ip := range ips {
			fmt.Printf("  %s\n", ip)
		}

		return nil
	},
}

var listServicesCmd = &cobra.Command{
	Use:   "list",
	Short: "List all registered services",
	RunE: func(cmd *cobra.Command, args []string) error {
		disc := getDiscoveryBackend()

		// Only works with InMemoryDiscovery
		memDisc, ok := disc.(*discovery.InMemoryDiscovery)
		if !ok {
			return fmt.Errorf("list command only works with in-memory discovery")
		}

		services := memDisc.ListServices()
		if len(services) == 0 {
			fmt.Println("No services registered")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tIP\tLABELS\tUPDATED")

		for _, service := range services {
			labels := ""
			for k, v := range service.Labels {
				if labels != "" {
					labels += ","
				}
				labels += fmt.Sprintf("%s=%s", k, v)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				service.Name,
				service.IP,
				labels,
				service.UpdatedAt.Format("2006-01-02 15:04:05"))
		}

		w.Flush()
		return nil
	},
}

func init() {
	rootCmd.AddCommand(discoveryCmd)

	discoveryCmd.AddCommand(registerCmd)
	discoveryCmd.AddCommand(deregisterCmd)
	discoveryCmd.AddCommand(resolveCmd)
	discoveryCmd.AddCommand(listServicesCmd)

	// Flags
	registerCmd.Flags().StringToString("labels", map[string]string{}, "Service labels (key=value)")
	resolveCmd.Flags().StringToString("labels", map[string]string{}, "Labels to resolve (key=value)")
}

// getDiscoveryBackend returns the configured discovery backend
func getDiscoveryBackend() discovery.ServiceDiscovery {
	// TODO: Read from config.yaml to support different backends
	// For now, use in-memory
	if globalDiscovery == nil {
		globalDiscovery = discovery.NewInMemoryDiscovery()
	}
	return globalDiscovery
}

var globalDiscovery discovery.ServiceDiscovery
