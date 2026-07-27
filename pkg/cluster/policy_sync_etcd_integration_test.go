//go:build integration
// +build integration

package cluster

import (
	"context"
	"testing"
	"time"
)

func TestEtcdPolicySyncLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	etcdServer, cleanup := startEmbeddedEtcd(t)
	defer cleanup()

	etcdConfig := &EtcdConfig{
		Endpoints:   []string{etcdServer.URL()},
		DialTimeout: 5 * time.Second,
		KeyPrefix:   "/ztap-test-policy",
		SessionTTL:  10 * time.Second,
	}

	ps, err := NewEtcdPolicySync(etcdConfig, "node-1")
	if err != nil {
		t.Fatalf("NewEtcdPolicySync: %v", err)
	}
	t.Cleanup(func() { _ = ps.Stop() })

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	policyYAML := []byte("apiVersion: ztap/v1\nkind: NetworkPolicy\nmetadata:\n  name: web\nspec:\n  podSelector:\n    matchLabels:\n      app: web\n  egress:\n  - to:\n      ipBlock:\n        cidr: 10.0.0.0/8\n    ports:\n    - protocol: TCP\n      port: 443\n")

	rev, err := ps.UpsertPolicy(ctx, "default/web", policyYAML, "initial")
	if err != nil {
		t.Fatalf("UpsertPolicy: %v", err)
	}
	if rev.Version != 1 {
		t.Fatalf("expected version 1, got %d", rev.Version)
	}

	state, err := ps.GetPolicy("default/web")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if state == nil || state.Version != 1 {
		t.Fatalf("expected policy state version 1")
	}

	revs, err := ps.ListPolicyRevisions("default/web", 0)
	if err != nil {
		t.Fatalf("ListPolicyRevisions: %v", err)
	}
	if len(revs) != 1 {
		t.Fatalf("expected 1 revision, got %d", len(revs))
	}

	rb, err := ps.RollbackPolicy(ctx, "default/web", 1, "rollback")
	if err != nil {
		t.Fatalf("RollbackPolicy: %v", err)
	}
	if rb.RollbackFromVersion == nil || *rb.RollbackFromVersion != 1 {
		t.Fatalf("expected rollback from version 1")
	}

	del, err := ps.DeletePolicy(ctx, "default/web", "cleanup")
	if err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}
	if !del.Deleted {
		t.Fatalf("expected deleted revision")
	}

	missing, err := ps.GetPolicy("default/web")
	if err != nil {
		t.Fatalf("GetPolicy after delete: %v", err)
	}
	if missing != nil {
		t.Fatalf("expected policy to be removed")
	}
}
