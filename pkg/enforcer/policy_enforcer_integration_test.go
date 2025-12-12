//go:build integration
// +build integration

package enforcer

import (
	"context"
	"fmt"
	"testing"
	"time"

	"ztap/pkg/cluster"
)

// TestPolicyEnforcerSimple tests basic policy enforcement
func TestPolicyEnforcerSimple(t *testing.T) {
	config := cluster.LeaderElectionConfig{
		NodeID:      "test-node",
		NodeAddress: "127.0.0.1:5000",
	}
	election := cluster.NewInMemoryElection(config)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := election.Start(ctx); err != nil {
		t.Fatalf("Failed to start election: %v", err)
	}
	defer election.Stop()

	// Wait for leader election (automatic, happens after InitialLeadership = 3s)
	time.Sleep(3500 * time.Millisecond)

	if !election.IsLeader() {
		t.Fatal("Node should be leader (only node in cluster)")
	}

	policySync := cluster.NewInMemoryPolicySync(election, "test-node")
	enforcer := NewPolicyEnforcer(PolicyEnforcerConfig{
		PolicySync: policySync,
	})

	if err := enforcer.Start(ctx); err != nil {
		t.Fatalf("Failed to start enforcer: %v", err)
	}
	defer enforcer.Stop()

	// Create a test policy
	testPolicy := []byte(`apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: web-policy
spec:
  podSelector:
    matchLabels:
      app: web
  egress:
  - to:
      podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432`)

	// Sync the policy
	if err := policySync.SyncPolicy(ctx, "web-policy", testPolicy); err != nil {
		t.Fatalf("Failed to sync policy: %v", err)
	}

	// Wait for enforcement
	time.Sleep(500 * time.Millisecond)

	// Verify policy was enforced
	version := enforcer.GetEnforcedVersion("web-policy")
	if version != 1 {
		t.Errorf("Expected enforced version 1, got %d", version)
	}
	t.Logf("Successfully enforced web-policy v%d", version)

	// Update the policy
	updatedPolicy := []byte(`apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: web-policy
spec:
  podSelector:
    matchLabels:
      app: web
  egress:
  - to:
      podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
  - to:
      ipBlock:
        cidr: 10.0.0.0/8
    ports:
    - protocol: TCP
      port: 443`)

	if err := policySync.SyncPolicy(ctx, "web-policy", updatedPolicy); err != nil {
		t.Fatalf("Failed to sync updated policy: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	// Verify update was enforced
	version = enforcer.GetEnforcedVersion("web-policy")
	if version != 2 {
		t.Errorf("Expected enforced version 2 after update, got %d", version)
	}
	t.Logf("Successfully enforced web-policy v%d (updated)", version)
}

// TestPolicyEnforcerMultiplePolicies tests enforcement of multiple policies
func TestPolicyEnforcerMultiplePolicies(t *testing.T) {
	config := cluster.LeaderElectionConfig{
		NodeID:      "test-node",
		NodeAddress: "127.0.0.1:5000",
	}
	election := cluster.NewInMemoryElection(config)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := election.Start(ctx); err != nil {
		t.Fatalf("Failed to start election: %v", err)
	}
	defer election.Stop()

	// Wait for leader election
	time.Sleep(3500 * time.Millisecond)

	policySync := cluster.NewInMemoryPolicySync(election, "test-node")
	enforcer := NewPolicyEnforcer(PolicyEnforcerConfig{
		PolicySync: policySync,
	})

	if err := enforcer.Start(ctx); err != nil {
		t.Fatalf("Failed to start enforcer: %v", err)
	}
	defer enforcer.Stop()

	// Sync multiple policies
	webPolicy := []byte(`apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: web-policy
spec:
  podSelector:
    matchLabels:
      app: web
  egress:
  - to:
      podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432`)

	dbPolicy := []byte(`apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: db-policy
spec:
  podSelector:
    matchLabels:
      app: database
  ingress:
  - from:
      podSelector:
        matchLabels:
          app: web
    ports:
    - protocol: TCP
      port: 5432`)

	if err := policySync.SyncPolicy(ctx, "web-policy", webPolicy); err != nil {
		t.Fatalf("Failed to sync web policy: %v", err)
	}

	if err := policySync.SyncPolicy(ctx, "db-policy", dbPolicy); err != nil {
		t.Fatalf("Failed to sync db policy: %v", err)
	}

	time.Sleep(500 * time.Millisecond)

	// Verify both policies were enforced
	versions := enforcer.GetEnforcedVersions()
	if len(versions) != 2 {
		t.Errorf("Expected 2 enforced policies, got %d", len(versions))
	}

	if versions["web-policy"] != 1 {
		t.Errorf("Expected web-policy v1, got v%d", versions["web-policy"])
	}
	if versions["db-policy"] != 1 {
		t.Errorf("Expected db-policy v1, got v%d", versions["db-policy"])
	}

	t.Logf("Successfully enforced %d policies", len(versions))
}

// TestPolicyEnforcerConcurrentUpdates tests enforcement under concurrent policy updates
func TestPolicyEnforcerConcurrentUpdates(t *testing.T) {
	config := cluster.LeaderElectionConfig{
		NodeID:      "test-node",
		NodeAddress: "127.0.0.1:5000",
	}
	election := cluster.NewInMemoryElection(config)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := election.Start(ctx); err != nil {
		t.Fatalf("Failed to start election: %v", err)
	}
	defer election.Stop()

	// Wait for leader election
	time.Sleep(3500 * time.Millisecond)

	policySync := cluster.NewInMemoryPolicySync(election, "test-node")
	enforcer := NewPolicyEnforcer(PolicyEnforcerConfig{
		PolicySync: policySync,
	})

	if err := enforcer.Start(ctx); err != nil {
		t.Fatalf("Failed to start enforcer: %v", err)
	}
	defer enforcer.Stop()

	// Sync multiple policies concurrently
	policyTemplate := `apiVersion: ztap/v1
kind: NetworkPolicy
metadata:
  name: policy-%d
spec:
  podSelector:
    matchLabels:
      app: test-%d
  egress:
  - to:
      ipBlock:
        cidr: 10.0.0.0/8
    ports:
    - protocol: TCP
      port: %d`

	numPolicies := 10
	errChan := make(chan error, numPolicies)

	for i := 0; i < numPolicies; i++ {
		go func(idx int) {
			policyYAML := []byte(fmt.Sprintf(policyTemplate, idx, idx, 30000+idx))
			policyName := fmt.Sprintf("policy-%d", idx)
			err := policySync.SyncPolicy(ctx, policyName, policyYAML)
			errChan <- err
		}(i)
	}

	// Check for errors
	for i := 0; i < numPolicies; i++ {
		if err := <-errChan; err != nil {
			t.Errorf("Failed to sync policy: %v", err)
		}
	}

	// Wait for enforcement
	time.Sleep(1 * time.Second)

	// Verify all policies were enforced
	versions := enforcer.GetEnforcedVersions()
	if len(versions) != numPolicies {
		t.Errorf("Expected %d enforced policies, got %d", numPolicies, len(versions))
	}

	for i := 0; i < numPolicies; i++ {
		policyName := fmt.Sprintf("policy-%d", i)
		if versions[policyName] != 1 {
			t.Errorf("Policy %s: expected v1, got v%d", policyName, versions[policyName])
		}
	}
	t.Logf("Successfully enforced %d concurrent policies", numPolicies)
}
