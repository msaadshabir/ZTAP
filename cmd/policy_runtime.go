package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"ztap/pkg/cluster"
	"ztap/pkg/logging"
)

func initPolicyRuntime(ctx context.Context, nodeAddress string) (cluster.LeaderElection, cluster.PolicyManager, func(), error) {
	nodeAddress = strings.TrimSpace(nodeAddress)
	if nodeAddress == "" {
		nodeAddress = "127.0.0.1:0"
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("getting hostname: %w", err)
	}

	runtimeCfg, err := loadClusterRuntimeConfig()
	if err != nil {
		return nil, nil, nil, err
	}

	nodeID := strings.TrimSpace(runtimeCfg.NodeID)
	if nodeID == "" {
		nodeID = hostname
	}

	address := strings.TrimSpace(runtimeCfg.NodeAddress)
	if address == "" {
		address = nodeAddress
	}

	config := cluster.LeaderElectionConfig{
		NodeID:      nodeID,
		NodeAddress: address,
	}
	if runtimeCfg.HeartbeatInterval > 0 {
		config.HeartbeatInterval = runtimeCfg.HeartbeatInterval
	}
	if runtimeCfg.ElectionTimeout > 0 {
		config.ElectionTimeout = runtimeCfg.ElectionTimeout
	}

	backend, err := resolveClusterBackend(runtimeCfg)
	if err != nil {
		return nil, nil, nil, err
	}
	if backend == clusterBackendEtcd {
		// If etcd is selected implicitly via endpoints, and both servers are run
		// on one host, it is easy to accidentally reuse the same default node_id.
		// Make the process identity stable-but-unique by default.
		if strings.TrimSpace(runtimeCfg.NodeID) == "" && strings.TrimSpace(os.Getenv("ZTAP_NODE_ID")) == "" {
			if _, port, splitErr := splitHostPortForNodeID(address); splitErr == nil && port != "" {
				nodeID = nodeID + "-" + port
			} else {
				nodeID = nodeID + "-" + strings.ReplaceAll(address, ":", "_")
			}
			config.NodeID = nodeID
		}
	}

	if backend == clusterBackendEtcd {
		if len(runtimeCfg.Etcd.Endpoints) == 0 {
			return nil, nil, nil, errors.New("etcd endpoints are required when cluster backend is etcd")
		}
		etcdCfg := &cluster.EtcdConfig{
			Endpoints:         runtimeCfg.Etcd.Endpoints,
			DialTimeout:       runtimeCfg.Etcd.DialTimeout,
			Username:          runtimeCfg.Etcd.Username,
			Password:          runtimeCfg.Etcd.Password,
			KeyPrefix:         runtimeCfg.Etcd.KeyPrefix,
			LeaderElectionKey: runtimeCfg.Etcd.LeaderElectionKey,
			SessionTTL:        runtimeCfg.Etcd.SessionTTL,
		}
		election, err := cluster.NewEtcdElection(config, etcdCfg)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("create etcd election: %w", err)
		}
		if err := election.Start(ctx); err != nil {
			return nil, nil, nil, fmt.Errorf("start cluster election: %w", err)
		}
		policySync, err := cluster.NewEtcdPolicySync(etcdCfg, nodeID)
		if err != nil {
			_ = election.Stop()
			return nil, nil, nil, fmt.Errorf("create etcd policy sync: %w", err)
		}
		if err := policySync.Start(ctx); err != nil {
			_ = election.Stop()
			return nil, nil, nil, fmt.Errorf("start policy sync: %w", err)
		}

		waitForLeader(ctx, election)

		cleanup := func() {
			_ = policySync.Stop()
			_ = election.Stop()
		}
		return election, policySync, cleanup, nil
	}

	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = 200 * time.Millisecond
	}
	// CLI runtime should elect a leader quickly on startup; the in-memory
	// backend's default InitialLeadership delay is tuned for tests.
	config.InitialLeadership = 0

	election := cluster.NewInMemoryElection(config)
	if err := election.Start(ctx); err != nil {
		return nil, nil, nil, fmt.Errorf("start cluster election: %w", err)
	}
	policySync := cluster.NewInMemoryPolicySync(election, nodeID)
	if err := policySync.Start(ctx); err != nil {
		_ = election.Stop()
		return nil, nil, nil, fmt.Errorf("start policy sync: %w", err)
	}

	waitForLeader(ctx, election)

	cleanup := func() {
		_ = policySync.Stop()
		_ = election.Stop()
	}
	return election, policySync, cleanup, nil
}

func waitForLeader(ctx context.Context, election cluster.LeaderElection) {
	if election == nil {
		return
	}
	if election.IsLeader() {
		return
	}
	deadline := time.Now().Add(1 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if election.IsLeader() {
			return
		}
		if time.Now().After(deadline) {
			logging.Warn("Cluster leader not elected yet; policy updates may be rejected briefly", nil)
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func splitHostPortForNodeID(addr string) (host, port string, err error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", "", errors.New("empty address")
	}
	host, port, err = net.SplitHostPort(addr)
	if err == nil {
		return host, port, nil
	}
	// Some callers may pass a host without a port.
	return "", "", err
}
