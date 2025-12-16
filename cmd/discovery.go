package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v2"
	"ztap/pkg/discovery"
)

const (
	defaultDiscoveryBackend = "inmemory"
	dnsDiscoveryBackend     = "dns"
)

var supportedDiscoveryBackends = defaultDiscoveryBackend + ", " + dnsDiscoveryBackend

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
		disc, err := getDiscoveryBackend()
		if err != nil {
			return fmt.Errorf("failed to load discovery backend: %w", err)
		}

		name := args[0]
		ip := args[1]

		labels, _ := cmd.Flags().GetStringToString("labels")

		if err := disc.RegisterService(name, ip, labels); err != nil {
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
		disc, err := getDiscoveryBackend()
		if err != nil {
			return fmt.Errorf("failed to load discovery backend: %w", err)
		}

		name := args[0]

		if err := disc.DeregisterService(name); err != nil {
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

		disc, err := getDiscoveryBackend()
		if err != nil {
			return fmt.Errorf("failed to load discovery backend: %w", err)
		}

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
		disc, err := getDiscoveryBackend()
		if err != nil {
			return fmt.Errorf("failed to load discovery backend: %w", err)
		}

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
func getDiscoveryBackend() (discovery.ServiceDiscovery, error) {
	if globalDiscovery != nil {
		return globalDiscovery, nil
	}

	backend, err := loadDiscoveryFromConfig()
	if err != nil {
		return nil, err
	}
	if backend == nil {
		backend = discovery.NewInMemoryDiscovery()
	}

	globalDiscovery = backend
	return globalDiscovery, nil
}

var globalDiscovery discovery.ServiceDiscovery

func loadDiscoveryFromConfig() (discovery.ServiceDiscovery, error) {
	path := os.Getenv("ZTAP_CONFIG")
	if path == "" {
		path = "config.yaml"
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	var cfg struct {
		Discovery struct {
			Backend string `yaml:"backend"`
			DNS     struct {
				Domain string `yaml:"domain"`
			} `yaml:"dns"`
			Cache struct {
				TTL string `yaml:"ttl"`
			} `yaml:"cache"`
		} `yaml:"discovery"`
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	backendName := normalizeBackendName(cfg.Discovery.Backend)
	if backendName == "" {
		backendName = defaultDiscoveryBackend
	}

	var backend discovery.ServiceDiscovery
	switch backendName {
	case defaultDiscoveryBackend:
		backend = discovery.NewInMemoryDiscovery()
	case dnsDiscoveryBackend:
		domain := strings.TrimSpace(cfg.Discovery.DNS.Domain)
		if domain == "" {
			return nil, fmt.Errorf("discovery.dns.domain is required for dns backend")
		}
		backend = discovery.NewDNSDiscovery(domain)
	default:
		return nil, fmt.Errorf("unsupported discovery backend: %s (supported: %s)", backendName, supportedDiscoveryBackends)
	}

	if ttl := strings.TrimSpace(cfg.Discovery.Cache.TTL); ttl != "" {
		parsedTTL, err := time.ParseDuration(ttl)
		if err != nil {
			return nil, fmt.Errorf("invalid discovery.cache.ttl: %w", err)
		}
		backend = discovery.NewCacheDiscovery(backend, parsedTTL)
	}

	return backend, nil
}

func normalizeBackendName(name string) string {
	return strings.TrimSpace(strings.ToLower(name))
}
