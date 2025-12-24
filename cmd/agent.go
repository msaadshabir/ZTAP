package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"ztap/pkg/cluster"
	"ztap/pkg/discovery"
	"ztap/pkg/enforcer"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Run ZTAP node agent for Kubernetes enforcement",
	Run: func(cmd *cobra.Command, args []string) {
		namespace, _ := cmd.Flags().GetString("namespace")
		cgroupPath, _ := cmd.Flags().GetString("cgroup")

		if namespace == "" {
			namespace = os.Getenv("ZTAP_NAMESPACE")
			if namespace == "" {
				namespace = "default"
			}
		}

		config, err := rest.InClusterConfig()
		if err != nil {
			log.Fatalf("Failed to get in-cluster config: %v", err)
		}

		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			log.Fatalf("Failed to create kubernetes client: %v", err)
		}

		// Initialize K8s-backed policy sync
		policySync := cluster.NewK8sPolicySync(clientset, namespace)

		// Initialize K8s discovery
		disc := discovery.NewK8sDiscovery(clientset, namespace)

		// Initialize policy enforcer
		pe := enforcer.NewPolicyEnforcer(enforcer.PolicyEnforcerConfig{
			PolicySync: policySync,
			Discovery:  disc,
			CgroupPath: cgroupPath,
		})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		if err := disc.Start(ctx); err != nil {
			log.Fatalf("Failed to start discovery: %v", err)
		}

		if err := policySync.Start(ctx); err != nil {
			log.Fatalf("Failed to start policy sync: %v", err)
		}

		if err := pe.Start(ctx); err != nil {
			log.Fatalf("Failed to start policy enforcer: %v", err)
		}

		fmt.Printf("ZTAP Agent started in namespace %s. Watching for policies...\n", namespace)

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		fmt.Println("Shutting down agent...")
		if err := pe.Stop(); err != nil {
			log.Printf("Warning: failed to stop policy enforcer: %v", err)
		}
		if err := policySync.Stop(); err != nil {
			log.Printf("Warning: failed to stop policy sync: %v", err)
		}
	},
}

func init() {
	agentCmd.Flags().String("namespace", "", "Kubernetes namespace to watch for policies")
	agentCmd.Flags().String("cgroup", "/sys/fs/cgroup", "Cgroup v2 path for eBPF attachment (Linux only)")
	rootCmd.AddCommand(agentCmd)
}
