package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"ztap/internal/audit"
	"ztap/internal/cluster"
	"ztap/internal/discovery"
	"ztap/internal/enforcer"
	"ztap/internal/logging"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func newAgentCmd(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "agent",
		Short: "Run ZTAP node agent for Kubernetes enforcement",
		Run: func(cmd *cobra.Command, args []string) {
			central, err := app.Config()
			if err != nil {
				logging.Fatalf("Failed to load config: %v", err)
			}
			namespace, _ := cmd.Flags().GetString("namespace")
			namespacesCSV, _ := cmd.Flags().GetString("namespaces")
			allNamespaces, _ := cmd.Flags().GetBool("all-namespaces")
			cgroupPath, _ := cmd.Flags().GetString("cgroup")
			dryRun, _ := cmd.Flags().GetBool("dry-run")

			var namespaces []string
			if namespacesCSV != "" {
				split := strings.SplitSeq(namespacesCSV, ",")
				for s := range split {
					s = strings.TrimSpace(s)
					if s != "" {
						namespaces = append(namespaces, s)
					}
				}
			}

			if !allNamespaces && len(namespaces) == 0 && namespace == "" {
				namespace = os.Getenv("ZTAP_NAMESPACE")
				if namespace == "" {
					namespace = "default"
				}
			}

			config, err := rest.InClusterConfig()
			if err != nil {
				logging.Fatalf("Failed to get in-cluster config: %v", err)
			}

			auditOpts, _, err := loadAuditConfig(central)
			if err != nil {
				logging.Fatalf("Failed to load audit config: %v", err)
			}
			var auditLogger *audit.AuditLogger
			if auditOpts.LogPath != "" {
				al, err := audit.NewAuditLoggerWithOptions(auditOpts)
				if err != nil {
					logging.Warnf("failed to initialize audit logger: %v", err)
				} else {
					auditLogger = al
				}
			}

			clientset, err := kubernetes.NewForConfig(config)
			if err != nil {
				logging.Fatalf("Failed to create kubernetes client: %v", err)
			}
			if (allNamespaces || len(namespaces) > 1) && !enforcer.CanUseEBPF() {
				logging.Warn("multi-tenant mode without eBPF; tenant isolation is not guaranteed", nil)
			}

			var policySync *cluster.K8sPolicySync
			discoveryNamespace := namespace
			scopeInfo := namespace
			switch {
			case allNamespaces:
				policySync = cluster.NewK8sPolicySyncAllNamespaces(clientset)
				discoveryNamespace = ""
				scopeInfo = "all namespaces"
			case len(namespaces) > 0:
				policySync = cluster.NewK8sPolicySyncNamespaces(clientset, namespaces)
				if len(namespaces) == 1 {
					discoveryNamespace = namespaces[0]
					scopeInfo = namespaces[0]
				} else {
					discoveryNamespace = ""
					scopeInfo = strings.Join(namespaces, ",")
				}
			default:
				policySync = cluster.NewK8sPolicySync(clientset, namespace)
			}

			var disc interface {
				Start(ctx context.Context) error
				Stop() error
				ResolveLabels(labels map[string]string) ([]string, error)
				RegisterService(name string, ip string, labels map[string]string) error
				DeregisterService(name string) error
				Watch(ctx context.Context, labels map[string]string) (<-chan []string, error)
			}
			if allNamespaces || len(namespaces) > 1 {
				disc, err = discovery.NewK8sDiscoveryAllNamespaces(clientset)
				if err != nil {
					logging.Fatalf("Failed to create kubernetes discovery: %v", err)
				}
			} else {
				disc, err = discovery.NewK8sDiscovery(clientset, discoveryNamespace)
				if err != nil {
					logging.Fatalf("Failed to create kubernetes discovery: %v", err)
				}
			}

			pe := enforcer.NewPolicyEnforcer(enforcer.PolicyEnforcerConfig{
				PolicySync:      policySync,
				Discovery:       disc,
				SubjectResolver: newK8sSubjectResolver(clientset, cgroupPath),
				CgroupPath:      cgroupPath,
				ResolveLabels:   true, // Enable auto-discovery in agent mode
				DryRun:          dryRun,
				AuditLogger:     auditLogger,
			})

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			if err := disc.Start(ctx); err != nil {
				logging.Fatalf("Failed to start discovery: %v", err)
			}

			if err := policySync.Start(ctx); err != nil {
				logging.Fatalf("Failed to start policy sync: %v", err)
			}

			if err := pe.Start(ctx); err != nil {
				logging.Fatalf("Failed to start policy enforcer: %v", err)
			}

			// Anomaly detection (Phase E): async batched pipeline over the
			// flow monitor, behind anomaly.enabled. Detection is advisory —
			// a failure here must not take down enforcement.
			var anomalyR *anomalyRunner
			if central.Anomaly.Enabled {
				anomalyR, err = startAnomalyRunner(ctx, central, auditLogger)
				if err != nil {
					logging.Warnf("anomaly detection disabled: %v", err)
				}
			}

			fmt.Printf("ZTAP Agent started (%s). Watching for policies...\n", scopeInfo)

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			<-sigCh

			fmt.Println("Shutting down agent...")
			cancel()
			if anomalyR != nil {
				anomalyR.Stop()
			}
			if err := disc.Stop(); err != nil {
				logging.Warnf("failed to stop discovery: %v", err)
			}
			if err := pe.Stop(); err != nil {
				logging.Warnf("failed to stop policy enforcer: %v", err)
			}
			if auditLogger != nil {
				if err := auditLogger.Close(); err != nil {
					logging.Warnf("failed to close audit logger: %v", err)
				}
			}
			if err := policySync.Stop(); err != nil {
				logging.Warnf("failed to stop policy sync: %v", err)
			}
		},
	}
	c.Flags().String("namespace", "", "Kubernetes namespace to watch for policies")
	c.Flags().String("namespaces", "", "Comma-separated list of namespaces to watch for policies")
	c.Flags().Bool("all-namespaces", false, "Watch for policies across all namespaces")
	c.Flags().String("cgroup", "/sys/fs/cgroup", "Cgroup v2 path for eBPF attachment (Linux only)")
	c.Flags().Bool("dry-run", false, "Simulate enforcement without making system changes")
	return c
}
