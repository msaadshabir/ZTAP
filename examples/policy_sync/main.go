package main

// Example demonstrating distributed policy synchronization in ZTAP
// This example shows how to use the cluster policy sync feature

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ztap/pkg/cluster"
)

func main() {
	fmt.Println("ZTAP Policy Synchronization Example")
	fmt.Println("====================================")
	fmt.Println()

	// Create a 3-node cluster
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Node 1 (will become leader)
	node1Election := cluster.NewInMemoryElection(cluster.LeaderElectionConfig{
		NodeID:            "node-1",
		NodeAddress:       "127.0.0.1:9090",
		HeartbeatInterval: 1 * time.Second,
	})
	node1PolicySync := cluster.NewInMemoryPolicySync(node1Election, "node-1")

	// Node 2 (follower)
	node2Election := cluster.NewInMemoryElection(cluster.LeaderElectionConfig{
		NodeID:            "node-2",
		NodeAddress:       "127.0.0.1:9091",
		HeartbeatInterval: 1 * time.Second,
	})
	node2PolicySync := cluster.NewInMemoryPolicySync(node2Election, "node-2")

	// Node 3 (follower)
	node3Election := cluster.NewInMemoryElection(cluster.LeaderElectionConfig{
		NodeID:            "node-3",
		NodeAddress:       "127.0.0.1:9092",
		HeartbeatInterval: 1 * time.Second,
	})
	node3PolicySync := cluster.NewInMemoryPolicySync(node3Election, "node-3")

	// Start all nodes
	if err := node1Election.Start(ctx); err != nil {
		log.Fatalf("Failed to start node1 election: %v", err)
	}
	if err := node1PolicySync.Start(ctx); err != nil {
		log.Fatalf("Failed to start node1 policy sync: %v", err)
	}

	if err := node2Election.Start(ctx); err != nil {
		log.Fatalf("Failed to start node2 election: %v", err)
	}
	if err := node2PolicySync.Start(ctx); err != nil {
		log.Fatalf("Failed to start node2 policy sync: %v", err)
	}

	if err := node3Election.Start(ctx); err != nil {
		log.Fatalf("Failed to start node3 election: %v", err)
	}
	if err := node3PolicySync.Start(ctx); err != nil {
		log.Fatalf("Failed to start node3 policy sync: %v", err)
	}

	// Register all nodes in the cluster (simulate nodes discovering each other)
	node2Info := &cluster.Node{ID: "node-2", Address: "127.0.0.1:9091", State: cluster.StateHealthy}
	node3Info := &cluster.Node{ID: "node-3", Address: "127.0.0.1:9092", State: cluster.StateHealthy}
	node1Election.RegisterNode(node2Info)
	node1Election.RegisterNode(node3Info)

	// Wait for leader election
	time.Sleep(2 * time.Second)

	fmt.Println("Cluster initialized:")
	fmt.Printf("  Node 1: Leader=%v\n", node1Election.IsLeader())
	fmt.Printf("  Node 2: Leader=%v\n", node2Election.IsLeader())
	fmt.Printf("  Node 3: Leader=%v\n", node3Election.IsLeader())
	fmt.Println()

	// Subscribe to policy updates on node 2 and node 3
	node2Updates := node2PolicySync.SubscribePolicies(ctx)
	node3Updates := node3PolicySync.SubscribePolicies(ctx)

	// Monitor updates in background
	go func() {
		for update := range node2Updates {
			fmt.Printf("[Node 2] Received policy update: %s (version %d) from %s\n",
				update.PolicyName, update.Version, update.Source)
		}
	}()
	go func() {
		for update := range node3Updates {
			fmt.Printf("[Node 3] Received policy update: %s (version %d) from %s\n",
				update.PolicyName, update.Version, update.Source)
		}
	}()

	// Sync a policy from the leader (node 1)
	policyYAML := []byte(`apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: web-to-db
spec:
  podSelector:
    matchLabels:
      app: web
      tier: frontend
  egress:
  - to:
      podSelector:
        matchLabels:
          app: database
          tier: backend
    ports:
    - protocol: TCP
      port: 5432`)

	fmt.Println("Syncing policy 'web-to-db' from leader...")
	if err := node1PolicySync.SyncPolicy(ctx, "web-to-db", policyYAML); err != nil {
		log.Fatalf("Failed to sync policy: %v", err)
	}

	// Wait for updates to propagate
	time.Sleep(200 * time.Millisecond)

	// Verify all nodes have the policy
	fmt.Println()
	fmt.Println("Policy versions across cluster:")

	v1, _ := node1PolicySync.GetPolicyVersion("web-to-db")
	v2, _ := node2PolicySync.GetPolicyVersion("web-to-db")
	v3, _ := node3PolicySync.GetPolicyVersion("web-to-db")

	fmt.Printf("  Node 1: version %d\n", v1)
	fmt.Printf("  Node 2: version %d\n", v2)
	fmt.Printf("  Node 3: version %d\n", v3)
	fmt.Println()

	// Update the policy
	updatedPolicyYAML := []byte(`apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: web-to-db
spec:
  podSelector:
    matchLabels:
      app: web
      tier: frontend
  egress:
  - to:
      podSelector:
        matchLabels:
          app: database
          tier: backend
    ports:
    - protocol: TCP
      port: 5432
    - protocol: TCP
      port: 5433  # Added backup port`)

	fmt.Println("Updating policy 'web-to-db'...")
	if err := node1PolicySync.SyncPolicy(ctx, "web-to-db", updatedPolicyYAML); err != nil {
		log.Fatalf("Failed to update policy: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	// Check updated versions
	v1, _ = node1PolicySync.GetPolicyVersion("web-to-db")
	v2, _ = node2PolicySync.GetPolicyVersion("web-to-db")
	v3, _ = node3PolicySync.GetPolicyVersion("web-to-db")

	fmt.Println("Updated policy versions:")
	fmt.Printf("  Node 1: version %d\n", v1)
	fmt.Printf("  Node 2: version %d\n", v2)
	fmt.Printf("  Node 3: version %d\n", v3)
	fmt.Println()

	// List all policies
	fmt.Println("Policies in cluster:")
	policies := node1PolicySync.ListPolicies()
	for _, p := range policies {
		fmt.Printf("  - %s (v%d) synced by %s at %s\n",
			p.Name, p.Version, p.Source, p.Timestamp.Format("15:04:05"))
	}
	fmt.Println()

	fmt.Println("Example completed successfully!")
	fmt.Println()
	fmt.Println("Key features demonstrated:")
	fmt.Println("  ✓ Leader-initiated policy synchronization")
	fmt.Println("  ✓ Automatic version tracking")
	fmt.Println("  ✓ Real-time policy update notifications")
	fmt.Println("  ✓ Distributed policy consistency")
	fmt.Println()

	// Wait for interrupt signal to gracefully shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	fmt.Println("Press Ctrl+C to exit...")
	<-sigChan

	fmt.Println("\nShutting down...")
	cancel()
	node1Election.Stop()
	node2Election.Stop()
	node3Election.Stop()
	node1PolicySync.Stop()
	node2PolicySync.Stop()
	node3PolicySync.Stop()
}
