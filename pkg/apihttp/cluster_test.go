package apihttp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"ztap/pkg/auth"
	"ztap/pkg/cluster"
)

func TestClusterStatusRequiresAuth(t *testing.T) {
	tmp := t.TempDir()
	am, err := auth.NewAuthManager(tmp + "/users.json")
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}

	election := cluster.NewInMemoryElection(cluster.LeaderElectionConfig{NodeID: "node-1", NodeAddress: "127.0.0.1:0"})
	ctx := contextWithTimeout(t, 2*time.Second)
	if err := election.Start(ctx); err != nil {
		t.Fatalf("Start election: %v", err)
	}
	defer func() { _ = election.Stop() }()

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: true}, AuthManager: am, ClusterElection: election})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/cluster/status", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestClusterNodesLifecycle(t *testing.T) {
	ctx := contextWithTimeout(t, 5*time.Second)

	election := cluster.NewInMemoryElection(cluster.LeaderElectionConfig{NodeID: "node-1", NodeAddress: "127.0.0.1:0"})
	if err := election.Start(ctx); err != nil {
		t.Fatalf("Start election: %v", err)
	}
	defer func() { _ = election.Stop() }()

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: false}, ClusterElection: election})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Register a node.
	body, _ := json.Marshal(map[string]any{"id": "node-2", "address": "127.0.0.1:9090"})
	postReq := httptest.NewRequest(http.MethodPost, "/v1/cluster/nodes", bytes.NewReader(body))
	postRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(postRR, postReq)
	if postRR.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", postRR.Code)
	}

	// List nodes.
	listReq := httptest.NewRequest(http.MethodGet, "/v1/cluster/nodes", nil)
	listRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", listRR.Code)
	}

	// Delete node.
	delReq := httptest.NewRequest(http.MethodDelete, "/v1/cluster/nodes/node-2", nil)
	delRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(delRR, delReq)
	if delRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", delRR.Code)
	}
}

func contextWithTimeout(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, _ := context.WithTimeout(context.Background(), d)
	return ctx
}
