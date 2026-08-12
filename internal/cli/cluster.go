package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"ztap/internal/cluster"
	"ztap/internal/config"
	"ztap/internal/logging"

	"github.com/spf13/cobra"
)

// Global cluster election instance (created with the root command and started
// only for commands that use the configured CLI cluster backend).
var clusterElection cluster.LeaderElection
var clusterBackendRunning bool
var clusterBackendCleanup func()

// Backend type flag (default: memory)
var etcdEndpoints []string

func newClusterCmdWithApp(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "cluster",
		Short: "Manage cluster coordination and distributed architecture",
		Long:  `View and manage cluster status, join clusters, and coordinate with other nodes.`,
	}
	// Add subcommands to cluster
	c.AddCommand(newClusterStatusCmd())
	c.AddCommand(newClusterJoinCmd())
	c.AddCommand(newClusterLeaveCmd())
	c.AddCommand(newClusterListCmd())
	c.AddCommand(newClusterConfigCmdWithApp(app))
	c.AddCommand(newClusterTestEtcdCmdWithApp(app))
	return c
}

func newClusterStatusCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "status",
		Short: "Show cluster status and node information",
		Long:  `Display information about the current cluster, including leader status and connected nodes.`,
		Run: func(cmd *cobra.Command, args []string) {
			if clusterElection == nil {
				fmt.Println("Cluster not initialized. Run with --init first.")
				return
			}

			fmt.Println("Cluster Status")
			fmt.Println("==============")
			fmt.Println()

			leader := clusterElection.GetLeader()
			if leader != nil {
				fmt.Printf("Leader: %s (%s)\n", leader.ID, leader.Address)
			} else {
				fmt.Println("Leader: (none elected)")
			}

			isLeader := clusterElection.IsLeader()
			fmt.Printf("This node is leader: %v\n", isLeader)
			fmt.Println()

			fmt.Println("Nodes in Cluster:")
			nodes := clusterElection.GetNodes()
			if len(nodes) == 0 {
				fmt.Println("  (no nodes)")
			} else {
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				_, _ = fmt.Fprintln(w, "  ID\tAddress\tRole\tState\tJoined")
				_, _ = fmt.Fprintln(w, "  --\t-------\t----\t-----\t------")

				for _, node := range nodes {
					joined := time.Since(node.JoinedAt).Round(time.Second)
					_, _ = fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s ago\n",
						node.ID, node.Address, node.Role, node.State, joined)
				}
				_ = w.Flush()
				fmt.Printf("\nTotal: %d node(s)\n", len(nodes))
			}
		},
	}
	return c
}

func newClusterJoinCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "join <node-id> <node-address>",
		Short: "Join a node to the cluster",
		Long:  `Register a new node in the cluster. Node ID should be unique. Address format: host:port`,
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			if clusterElection == nil {
				fmt.Println("Cluster not initialized. Run with --init first.")
				return
			}

			nodeID := args[0]
			address := args[1]

			node := &cluster.Node{
				ID:       nodeID,
				Address:  address,
				State:    cluster.StateHealthy,
				JoinedAt: time.Now(),
				LastSeen: time.Now(),
				Metadata: make(map[string]string),
			}

			if err := clusterElection.RegisterNode(node); err != nil {
				logging.Fatalf("Failed to join node: %v", err)
			}

			fmt.Printf("Node %s joined the cluster at %s\n", nodeID, address)
		},
	}
	return c
}

func newClusterLeaveCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "leave <node-id>",
		Short: "Remove a node from the cluster",
		Long:  `Deregister a node from the cluster.`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if clusterElection == nil {
				fmt.Println("Cluster not initialized. Run with --init first.")
				return
			}

			nodeID := args[0]

			if err := clusterElection.DeregisterNode(nodeID); err != nil {
				logging.Fatalf("Failed to remove node: %v", err)
			}

			fmt.Printf("Node %s left the cluster\n", nodeID)
		},
	}
	return c
}

func newClusterListCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "list",
		Short: "List all nodes in the cluster",
		Long:  `Display a detailed list of all nodes in the cluster.`,
		Run: func(cmd *cobra.Command, args []string) {
			if clusterElection == nil {
				fmt.Println("Cluster not initialized. Run with --init first.")
				return
			}

			nodes := clusterElection.GetNodes()

			if len(nodes) == 0 {
				fmt.Println("No nodes in cluster")
				return
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "ID\tAddress\tRole\tState\tJoined\tLast Seen")
			_, _ = fmt.Fprintln(w, "--\t-------\t----\t-----\t------\t---------")

			for _, node := range nodes {
				joined := time.Since(node.JoinedAt).Round(time.Second)
				lastSeen := time.Since(node.LastSeen).Round(time.Millisecond)
				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s ago\t%s ago\n",
					node.ID, node.Address, node.Role, node.State, joined, lastSeen)
			}
			_ = w.Flush()
		},
	}
	return c
}

func newClusterConfigCmdWithApp(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "config",
		Short: "Configure cluster backend",
		Long:  `Configure the cluster coordination backend (in-memory or etcd).`,
	}
	// Add config subcommands
	c.AddCommand(newClusterConfigSetCmd())
	c.AddCommand(newClusterConfigShowCmdWithApp(app))
	return c
}

func newClusterConfigSetCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "set-backend [memory|etcd]",
		Short: "Set the cluster backend type",
		Long:  `Set the cluster coordination backend to either in-memory (for testing) or etcd (for production).`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			backend := args[0]
			if backend != "memory" && backend != "etcd" {
				fmt.Println("Error: backend must be 'memory' or 'etcd'")
				os.Exit(1)
			}

			fmt.Printf("Cluster backend set to: %s\n", backend)

			if backend == "etcd" {
				if len(etcdEndpoints) == 0 {
					fmt.Println("\nNote: Using default etcd endpoint [localhost:2379]")
					fmt.Println("Use --etcd-endpoints to specify custom endpoints")
				} else {
					fmt.Printf("Etcd endpoints: %v\n", etcdEndpoints)
				}
			}
		},
	}
	// Add flags to commands that need them
	c.Flags().StringSliceVar(&etcdEndpoints, "etcd-endpoints", []string{}, "Etcd cluster endpoints (comma-separated)")
	return c
}

func newClusterConfigShowCmdWithApp(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "show",
		Short: "Show current cluster configuration",
		Long:  `Display the current cluster backend configuration.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			central, err := app.Config()
			if err != nil {
				return err
			}
			runtimeCfg := loadClusterRuntimeConfig(central)
			backend, err := resolveClusterBackend(runtimeCfg)
			if err != nil {
				return err
			}

			fmt.Println("Cluster Configuration")
			fmt.Println("=====================")
			fmt.Printf("Backend: %s\n", backend)

			if backend == clusterBackendEtcd {
				if len(runtimeCfg.Etcd.Endpoints) > 0 {
					fmt.Printf("Etcd endpoints: %v\n", runtimeCfg.Etcd.Endpoints)
				} else {
					fmt.Println("Etcd endpoints: [localhost:2379] (default)")
				}
			}

			if clusterBackendRunning && clusterElection != nil {
				nodeID := strings.TrimSpace(runtimeCfg.NodeID)
				if nodeID == "" {
					nodeID, _ = os.Hostname()
				}
				fmt.Printf("Node ID: %s\n", nodeID)
				fmt.Printf("Running: yes\n")
				fmt.Printf("Leader: %v\n", clusterElection.IsLeader())
			} else {
				fmt.Println("Status: not running")
			}
			return nil
		},
	}
	return c
}

func newClusterTestEtcdCmdWithApp(app *App) *cobra.Command {
	c := &cobra.Command{
		Use:   "test-etcd",
		Short: "Test etcd connectivity",
		Long:  `Test connection to etcd cluster and display status.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			central, err := app.Config()
			if err != nil {
				return err
			}
			runtimeCfg := loadClusterRuntimeConfig(central)
			endpoints := append([]string(nil), runtimeCfg.Etcd.Endpoints...)
			if cmd.Flags().Changed("etcd-endpoints") {
				endpoints = append([]string(nil), etcdEndpoints...)
			}
			if len(endpoints) == 0 {
				endpoints = []string{"localhost:2379"}
			}

			fmt.Printf("Testing etcd connection to: %v\n", endpoints)

			etcdConfig := &cluster.EtcdConfig{
				Endpoints:         endpoints,
				DialTimeout:       runtimeCfg.Etcd.DialTimeout,
				Username:          runtimeCfg.Etcd.Username,
				Password:          runtimeCfg.Etcd.Password,
				KeyPrefix:         runtimeCfg.Etcd.KeyPrefix,
				LeaderElectionKey: runtimeCfg.Etcd.LeaderElectionKey,
				SessionTTL:        runtimeCfg.Etcd.SessionTTL,
			}

			client, err := etcdConfig.NewEtcdClient()
			if err != nil {
				return fmt.Errorf("failed to connect to etcd: %w", err)
			}
			defer func() { _ = client.Close() }()

			baseCtx := cmd.Context()
			if baseCtx == nil {
				baseCtx = context.Background()
			}
			ctx, cancel := context.WithTimeout(baseCtx, 5*time.Second)
			defer cancel()

			// Try to get cluster status
			resp, err := client.MemberList(ctx)
			if err != nil {
				return fmt.Errorf("failed to get cluster status: %w", err)
			}

			fmt.Println("\nConnection successful!")
			fmt.Printf("Etcd cluster has %d member(s)\n", len(resp.Members))
			for i, member := range resp.Members {
				fmt.Printf("  %d. ID=%d, Name=%s, ClientURLs=%v\n",
					i+1, member.ID, member.Name, member.ClientURLs)
			}
			return nil
		},
	}
	c.Flags().StringSliceVar(&etcdEndpoints, "etcd-endpoints", []string{}, "Etcd cluster endpoints to test")
	return c
}

// commandUsesClusterBackend reports whether the command needs the CLI's
// configured election and policy-sync backends. They are intentionally started
// from PersistentPreRunE, after Cobra has installed the command context, rather
// than while the root command is being constructed.
func commandUsesClusterBackend(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}

	for current := cmd; current != nil; current = current.Parent() {
		switch current.Name() {
		case "cluster":
			switch cmd.Name() {
			case "status", "join", "leave", "list":
				return true
			}
		case "policy":
			// policy validate is local-only and does not need the cluster.
			return cmd.Name() != "validate"
		}
	}
	return false
}

// initClusterBackend resets the package-level handles used by the legacy CLI
// command implementations. The actual backend is created from the central
// configuration when a cluster or policy command is about to run.
func initClusterBackend() {
	if clusterBackendRunning {
		stopClusterBackend()
	}

	hostname, _ := os.Hostname()
	electionConfig := cluster.LeaderElectionConfig{
		NodeID:            hostname,
		NodeAddress:       "127.0.0.1:9090",
		HeartbeatInterval: 50 * time.Millisecond,
		InitialLeadership: 10 * time.Millisecond,
	}

	// Keep an unstarted in-memory backend available for direct command tests.
	// Normal root-command execution replaces it in startClusterBackendWithConfig.
	clusterElection = cluster.NewInMemoryElection(electionConfig)
	policySync = cluster.NewInMemoryPolicySync(clusterElection, hostname)
	clusterBackendCleanup = nil
	clusterBackendRunning = false
}

// startClusterBackend retains the test/helper API used by direct command
// invocations and starts the default in-memory runtime.
func startClusterBackend(ctx context.Context) error {
	return startClusterBackendWithConfig(ctx, &config.Config{}, "127.0.0.1:9090")
}

// startClusterBackendWithConfig creates and starts the configured election and
// policy manager. Keeping this lifecycle in one place ensures `cluster` and
// `policy` CLI commands use the same etcd/memory backend as API and gRPC.
func startClusterBackendWithConfig(ctx context.Context, cfg *config.Config, nodeAddress string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg == nil {
		cfg = &config.Config{}
	}
	if clusterBackendRunning {
		stopClusterBackend()
	}

	election, manager, cleanup, err := initPolicyRuntime(ctx, nodeAddress, cfg)
	if err != nil {
		return err
	}
	clusterElection = election
	policySync = manager
	clusterBackendCleanup = cleanup
	clusterBackendRunning = true
	return nil
}

func stopClusterBackend() {
	if clusterBackendCleanup != nil {
		clusterBackendCleanup()
		clusterBackendCleanup = nil
	} else {
		// Fallback for an unstarted/directly constructed backend.
		if stopper, ok := policySync.(interface{ Stop() error }); ok {
			_ = stopper.Stop()
		}
		if clusterElection != nil {
			_ = clusterElection.Stop()
		}
	}
	clusterBackendRunning = false
}
