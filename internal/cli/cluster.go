package cli

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"ztap/internal/cluster"
	"ztap/internal/logging"

	"github.com/spf13/cobra"
)

// Global cluster election instance (initialized on first use)
var clusterElection cluster.LeaderElection

// Backend type flag (default: memory)
var clusterBackend string = "memory"

// Etcd endpoints flag
var etcdEndpoints []string

func newClusterCmd() *cobra.Command {
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
	c.AddCommand(newClusterConfigCmd())
	c.AddCommand(newClusterTestEtcdCmd())
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

func newClusterConfigCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "config",
		Short: "Configure cluster backend",
		Long:  `Configure the cluster coordination backend (in-memory or etcd).`,
	}
	// Add config subcommands
	c.AddCommand(newClusterConfigSetCmd())
	c.AddCommand(newClusterConfigShowCmd())
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

			clusterBackend = backend
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

func newClusterConfigShowCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "show",
		Short: "Show current cluster configuration",
		Long:  `Display the current cluster backend configuration.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Cluster Configuration")
			fmt.Println("=====================")
			fmt.Printf("Backend: %s\n", clusterBackend)

			if clusterBackend == "etcd" {
				if len(etcdEndpoints) > 0 {
					fmt.Printf("Etcd endpoints: %v\n", etcdEndpoints)
				} else {
					fmt.Println("Etcd endpoints: [localhost:2379] (default)")
				}
			}

			if clusterElection != nil {
				hostname, _ := os.Hostname()
				fmt.Printf("Node ID: %s\n", hostname)
				fmt.Printf("Running: yes\n")
				fmt.Printf("Leader: %v\n", clusterElection.IsLeader())
			} else {
				fmt.Println("Status: not initialized")
			}
		},
	}
	return c
}

func newClusterTestEtcdCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "test-etcd",
		Short: "Test etcd connectivity",
		Long:  `Test connection to etcd cluster and display status.`,
		Run: func(cmd *cobra.Command, args []string) {
			endpoints := etcdEndpoints
			if len(endpoints) == 0 {
				endpoints = []string{"localhost:2379"}
			}

			fmt.Printf("Testing etcd connection to: %v\n", endpoints)

			etcdConfig := &cluster.EtcdConfig{
				Endpoints:   endpoints,
				DialTimeout: 5 * time.Second,
			}

			client, err := etcdConfig.NewEtcdClient()
			if err != nil {
				fmt.Printf("Error: Failed to connect to etcd: %v\n", err)
				os.Exit(1)
			}
			defer func() { _ = client.Close() }()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Try to get cluster status
			resp, err := client.MemberList(ctx)
			if err != nil {
				fmt.Printf("Error: Failed to get cluster status: %v\n", err)
				os.Exit(1)
			}

			fmt.Println("\nConnection successful!")
			fmt.Printf("Etcd cluster has %d member(s)\n", len(resp.Members))
			for i, member := range resp.Members {
				fmt.Printf("  %d. ID=%d, Name=%s, ClientURLs=%v\n",
					i+1, member.ID, member.Name, member.ClientURLs)
			}
		},
	}
	c.Flags().StringSliceVar(&etcdEndpoints, "etcd-endpoints", []string{}, "Etcd cluster endpoints to test")
	return c
}

// initClusterBackend initializes the in-memory cluster election and policy
// sync backends. It ran as package init before the CLI factory refactor; it
// is invoked once per NewRootCmd so `ztap cluster ...` behavior is unchanged.
func initClusterBackend(root *cobra.Command) {
	// Initialize cluster election based on backend type
	hostname, _ := os.Hostname()
	config := cluster.LeaderElectionConfig{
		NodeID:      hostname,
		NodeAddress: "127.0.0.1:9090", // Default; should be configurable
	}

	// Default to in-memory backend for now
	// Users can switch to etcd with "ztap cluster config set-backend etcd"
	clusterElection = cluster.NewInMemoryElection(config)

	// Initialize policy sync with the cluster election
	policySync = cluster.NewInMemoryPolicySync(clusterElection, hostname)

	// Start election and policy sync in background
	// Note: In a real daemon, this would be managed by the server lifecycle
	ctx := root.Context()
	if ctx == nil {
		// Fallback for CLI testing
		return
	}
	if err := clusterElection.Start(ctx); err != nil {
		logging.Warnf("failed to start cluster election: %v", err)
	}
	if err := policySync.(*cluster.InMemoryPolicySync).Start(ctx); err != nil {
		logging.Warnf("failed to start policy sync: %v", err)
	}
}
