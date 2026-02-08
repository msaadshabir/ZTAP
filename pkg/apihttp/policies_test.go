package apihttp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"ztap/pkg/audit"
	"ztap/pkg/auth"
	"ztap/pkg/cluster"
)

func newPolicyServer(t *testing.T) (*Server, *auth.AuthManager) {
	t.Helper()

	dir := t.TempDir()
	am, err := auth.NewAuthManager(filepath.Join(dir, "users.json"))
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	if err := am.CreateUser("admin1", "password123", auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	al, err := audit.NewAuditLogger(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	election := cluster.NewInMemoryElection(cluster.LeaderElectionConfig{
		NodeID:            "node-1",
		NodeAddress:       "127.0.0.1:0",
		HeartbeatInterval: 10 * time.Millisecond,
		InitialLeadership: 10 * time.Millisecond,
		ElectionTimeout:   100 * time.Millisecond,
	})
	runCtx, runCancel := context.WithCancel(context.Background())
	t.Cleanup(runCancel)
	if err := election.Start(runCtx); err != nil {
		t.Fatalf("Start election: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if election.IsLeader() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !election.IsLeader() {
		t.Fatalf("leader not elected")
	}
	t.Cleanup(func() { _ = election.Stop() })

	pm := cluster.NewInMemoryPolicySync(election, "node-1")
	if err := pm.Start(runCtx); err != nil {
		t.Fatalf("Start policy sync: %v", err)
	}
	t.Cleanup(func() { _ = pm.Stop() })

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: true}, AuthManager: am, AuditLogger: al, PolicyManager: pm})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() {
		_ = am.Close()
		_ = al.Close()
	})
	return srv, am
}

func loginToken(t *testing.T, srv *Server) string {
	t.Helper()

	body, _ := json.Marshal(map[string]string{"username": "admin1", "password": "password123"})
	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	if resp.Token == "" {
		t.Fatalf("expected token")
	}
	return resp.Token
}

func TestPoliciesLifecycle(t *testing.T) {
	srv, _ := newPolicyServer(t)
	token := loginToken(t, srv)

	policyYAML := "apiVersion: ztap/v1\nkind: NetworkPolicy\nmetadata:\n  name: web\nspec:\n  podSelector:\n    matchLabels:\n      app: web\n  egress:\n  - to:\n      ipBlock:\n        cidr: 10.0.0.0/8\n    ports:\n    - protocol: TCP\n      port: 443\n"

	putBody, _ := json.Marshal(map[string]any{"policy_yaml": policyYAML})
	putReq := httptest.NewRequest(http.MethodPut, "/v1/policies/default/web", bytes.NewReader(putBody))
	putReq.Header.Set("Authorization", "Bearer "+token)
	putRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(putRR, putReq)
	if putRR.Code != http.StatusOK {
		t.Fatalf("put expected 200, got %d: %s", putRR.Code, putRR.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/v1/policies", nil)
	listReq.Header.Set("Authorization", "Bearer "+token)
	listRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusOK {
		t.Fatalf("list expected 200, got %d", listRR.Code)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/v1/policies/default/web", nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(getRR, getReq)
	if getRR.Code != http.StatusOK {
		t.Fatalf("get expected 200, got %d: %s", getRR.Code, getRR.Body.String())
	}

	revReq := httptest.NewRequest(http.MethodGet, "/v1/policies/default/web/revisions?include_yaml=1", nil)
	revReq.Header.Set("Authorization", "Bearer "+token)
	revRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(revRR, revReq)
	if revRR.Code != http.StatusOK {
		t.Fatalf("revisions expected 200, got %d: %s", revRR.Code, revRR.Body.String())
	}

	delReq := httptest.NewRequest(http.MethodDelete, "/v1/policies/default/web", nil)
	delReq.Header.Set("Authorization", "Bearer "+token)
	delRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(delRR, delReq)
	if delRR.Code != http.StatusOK {
		t.Fatalf("delete expected 200, got %d: %s", delRR.Code, delRR.Body.String())
	}
}

func TestPoliciesExpectedVersionConflict(t *testing.T) {
	srv, _ := newPolicyServer(t)
	token := loginToken(t, srv)

	policyYAML := "apiVersion: ztap/v1\nkind: NetworkPolicy\nmetadata:\n  name: web\nspec:\n  podSelector:\n    matchLabels:\n      app: web\n  egress:\n  - to:\n      ipBlock:\n        cidr: 10.0.0.0/8\n    ports:\n    - protocol: TCP\n      port: 443\n"
	putBody, _ := json.Marshal(map[string]any{"policy_yaml": policyYAML, "expected_version": int64(1)})
	putReq := httptest.NewRequest(http.MethodPut, "/v1/policies/default/web", bytes.NewReader(putBody))
	putReq.Header.Set("Authorization", "Bearer "+token)
	putRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(putRR, putReq)
	if putRR.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", putRR.Code, putRR.Body.String())
	}
}
