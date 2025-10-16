package cmd

import (
	"fmt"
	"log"
	"os"
	"text/tabwriter"
	"time"

	"ztap/pkg/cluster"

	"github.com/spf13/cobra"
)

// Global cluster election instance (initialized on first use)
var clusterElection cluster.LeaderElection

var clusterCmd = &cobra.Command{
	Use:   "cluster",
	Short: "Manage cluster coordination and distributed architecture",
	Long:  `View and manage cluster status, join clusters, and coordinate with other nodes.`,
}

var clusterStatusCmd = &cobra.Command{
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
			fmt.Fprintln(w, "  ID\tAddress\tRole\tState\tJoined")
			fmt.Fprintln(w, "  --\t-------\t----\t-----\t------")

			for _, node := range nodes {
				joined := time.Since(node.JoinedAt).Round(time.Second)
				fmt.Fprintf(w, "  %s\t%s\t%s\t%s\t%s ago\n",
					node.ID, node.Address, node.Role, node.State, joined)
			}
			w.Flush()
			fmt.Printf("\nTotal: %d node(s)\n", len(nodes))
		}
	},
}

var clusterJoinCmd = &cobra.Command{
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
			log.Fatalf("Failed to join node: %v", err)
		}

		fmt.Printf("Node %s joined the cluster at %s\n", nodeID, address)
	},
}

var clusterLeaveCmd = &cobra.Command{
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
			log.Fatalf("Failed to remove node: %v", err)
		}

		fmt.Printf("Node %s left the cluster\n", nodeID)
	},
}

var clusterListCmd = &cobra.Command{
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
		fmt.Fprintln(w, "ID\tAddress\tRole\tState\tJoined\tLast Seen")
		fmt.Fprintln(w, "--\t-------\t----\t-----\t------\t---------")

		for _, node := range nodes {
			joined := time.Since(node.JoinedAt).Round(time.Second)
			lastSeen := time.Since(node.LastSeen).Round(time.Millisecond)
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s ago\t%s ago\n",
				node.ID, node.Address, node.Role, node.State, joined, lastSeen)
		}
		w.Flush()
	},
}

func init() {
	// Add subcommands to cluster
	clusterCmd.AddCommand(clusterStatusCmd)
	clusterCmd.AddCommand(clusterJoinCmd)
	clusterCmd.AddCommand(clusterLeaveCmd)
	clusterCmd.AddCommand(clusterListCmd)

	// Add cluster command to root
	rootCmd.AddCommand(clusterCmd)

	// Initialize in-memory election on first use
	// In production, this would be replaced with etcd or Raft backend
	hostname, _ := os.Hostname()
	config := cluster.LeaderElectionConfig{
		NodeID:      hostname,
		NodeAddress: "127.0.0.1:9090", // Default; should be configurable
	}
	clusterElection = cluster.NewInMemoryElection(config)

	// Start election in background
	// Note: In a real daemon, this would be managed by the server lifecycle
	ctx := rootCmd.Context()
	if ctx == nil {
		// Fallback for CLI testing
		return
	}
	if err := clusterElection.Start(ctx); err != nil {
		log.Printf("Warning: failed to start cluster election: %v", err)
	}
}
