package main

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

// This example demonstrates how to use the etcd backend for distributed leader election.
//
// Prerequisites:
// 1. Start an etcd cluster (single node for testing):
//    docker run -d --name etcd-test \
//      -p 2379:2379 \
//      -p 2380:2380 \
//      quay.io/coreos/etcd:latest \
//      /usr/local/bin/etcd \
//      --name etcd0 \
//      --initial-advertise-peer-urls http://localhost:2380 \
//      --listen-peer-urls http://0.0.0.0:2380 \
//      --advertise-client-urls http://localhost:2379 \
//      --listen-client-urls http://0.0.0.0:2379 \
//      --initial-cluster etcd0=http://localhost:2380
//
// 2. Run multiple instances of this example in separate terminals:
//    go run ./examples/etcd_election node1
//    go run ./examples/etcd_election node2
//    go run ./examples/etcd_election node3
//
// 3. Observe that only one node becomes the leader
// 4. Kill the leader and observe automatic failover

func main() {
	// Get node ID from command line (default to hostname)
	nodeID := "node-1"
	if len(os.Args) > 1 {
		nodeID = os.Args[1]
	} else {
		hostname, err := os.Hostname()
		if err == nil {
			nodeID = hostname
		}
	}

	// Configure etcd connection
	etcdConfig := &cluster.EtcdConfig{
		Endpoints:   []string{"localhost:2379"},
		DialTimeout: 5 * time.Second,
		KeyPrefix:   "/ztap",
		SessionTTL:  10 * time.Second,
	}

	// Configure leader election
	leaderConfig := cluster.LeaderElectionConfig{
		NodeID:            nodeID,
		NodeAddress:       fmt.Sprintf("localhost:909%s", nodeID[len(nodeID)-1:]),
		HeartbeatInterval: 2 * time.Second,
		ElectionTimeout:   5 * time.Second,
	}

	// Create etcd election backend
	election, err := cluster.NewEtcdElection(leaderConfig, etcdConfig)
	if err != nil {
		log.Fatalf("Failed to create etcd election: %v", err)
	}

	// Set up context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// Start election
	log.Printf("[%s] Starting election...", nodeID)
	if err := election.Start(ctx); err != nil {
		log.Fatalf("Failed to start election: %v", err)
	}
	defer election.Stop()

	// Watch for leader changes
	leaderCh := election.LeaderChanges(ctx)

	// Watch for cluster state changes
	stateCh := election.Watch(ctx)

	log.Printf("[%s] Joined cluster, waiting for leader election...", nodeID)

	// Main loop
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case leader := <-leaderCh:
			if leader != nil {
				isMe := leader.ID == nodeID
				if isMe {
					log.Printf("[%s] *** I AM THE LEADER ***", nodeID)
				} else {
					log.Printf("[%s] Leader changed to: %s", nodeID, leader.ID)
				}
			} else {
				log.Printf("[%s] Leader lost", nodeID)
			}

		case change := <-stateCh:
			if change.Node != nil {
				log.Printf("[%s] Cluster change: %s - %s (%s)",
					nodeID, change.Type, change.Node.ID, change.Node.State)
			}

		case <-ticker.C:
			// Periodic status update
			isLeader := election.IsLeader()
			leader := election.GetLeader()
			nodes := election.GetNodes()

			status := "follower"
			if isLeader {
				status = "LEADER"
			}

			leaderID := "none"
			if leader != nil {
				leaderID = leader.ID
			}

			log.Printf("[%s] Status: %s | Leader: %s | Cluster size: %d",
				nodeID, status, leaderID, len(nodes))

			// If we're the leader, demonstrate some work
			if isLeader {
				log.Printf("[%s] Performing leader duties...", nodeID)
				// In a real application, this is where you would:
				// - Coordinate distributed tasks
				// - Sync policies across nodes
				// - Manage cluster-wide state
			}

		case <-sigCh:
			log.Printf("[%s] Received shutdown signal, exiting gracefully...", nodeID)
			return
		}
	}
}
