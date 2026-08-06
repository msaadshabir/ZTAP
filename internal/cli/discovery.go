package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"ztap/internal/discovery"

	"github.com/spf13/cobra"
	yaml "gopkg.in/yaml.v3"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	defaultDiscoveryBackend = "inmemory"
	dnsDiscoveryBackend     = "dns"
	k8sDiscoveryBackend     = "k8s"
)

var supportedDiscoveryBackends = defaultDiscoveryBackend + ", " + dnsDiscoveryBackend + ", " + k8sDiscoveryBackend

func newDiscoveryCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "discovery",
		Short: "Manage service discovery",
		Long:  "Register, deregister, and query services for label-based resolution",
	}
	c.AddCommand(newRegisterCmd())
	c.AddCommand(newDeregisterCmd())
	c.AddCommand(newResolveCmd())
	c.AddCommand(newListServicesCmd())
	return c
}

func newRegisterCmd() *cobra.Command {
	c := &cobra.Command{
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
	// Flags
	c.Flags().StringToString("labels", map[string]string{}, "Service labels (key=value)")
	return c
}

func newDeregisterCmd() *cobra.Command {
	c := &cobra.Command{
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
	return c
}

func newResolveCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "resolve",
		Short: "Resolve IPs for given labels",
		RunE: func(cmd *cobra.Command, args []string) error {
			labels, _ := cmd.Flags().GetStringToString("labels")
			if len(labels) == 0 {
				return errors.New("no labels provided")
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
	c.Flags().StringToString("labels", map[string]string{}, "Labels to resolve (key=value)")
	return c
}

func newListServicesCmd() *cobra.Command {
	c := &cobra.Command{
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
				return errors.New("list command only works with in-memory discovery")
			}

			services := memDisc.ListServices()
			if len(services) == 0 {
				fmt.Println("No services registered")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "NAME\tIP\tLABELS\tUPDATED")

			for _, service := range services {
				labels := ""
				for k, v := range service.Labels {
					if labels != "" {
						labels += ","
					}
					labels += fmt.Sprintf("%s=%s", k, v)
				}
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
					service.Name,
					service.IP,
					labels,
					service.UpdatedAt.Format("2006-01-02 15:04:05"))
			}

			_ = w.Flush()
			return nil
		},
	}
	return c
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
			K8s struct {
				Namespace  string `yaml:"namespace"`
				Kubeconfig string `yaml:"kubeconfig"`
			} `yaml:"k8s"`
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
			return nil, errors.New("discovery.dns.domain is required for dns backend")
		}
		backend = discovery.NewDNSDiscovery(domain)
	case k8sDiscoveryBackend:
		kubeconfig := cfg.Discovery.K8s.Kubeconfig
		if kubeconfig == "" {
			kubeconfig = os.Getenv("KUBECONFIG")
		}
		if kubeconfig == "" {
			home, _ := os.UserHomeDir()
			kubeconfig = home + "/.kube/config"
		}

		config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to build kubeconfig: %w", err)
		}

		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
		}

		namespace := cfg.Discovery.K8s.Namespace
		if namespace == "" {
			namespace = os.Getenv("ZTAP_NAMESPACE")
		}
		if namespace == "" {
			namespace = "default"
		}

		backend, err = discovery.NewK8sDiscovery(clientset, namespace)
		if err != nil {
			return nil, fmt.Errorf("failed to create kubernetes discovery: %w", err)
		}
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
