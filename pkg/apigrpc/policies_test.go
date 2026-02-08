package apigrpc

import (
	"context"
	"net"
	"testing"
	"time"

	"ztap/pkg/audit"
	"ztap/pkg/auth"
	"ztap/pkg/cluster"

	apiv1 "ztap/proto/ztap/api/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

func newPolicyGRPCServer(t *testing.T) (*grpc.ClientConn, func()) {
	t.Helper()

	tmp := t.TempDir()
	am, err := auth.NewAuthManager(tmp + "/users.json")
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	if err := am.CreateUser("admin1", "pw", auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	al, err := audit.NewAuditLogger(tmp + "/audit.log")
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
		runCancel()
		_ = election.Stop()
		_ = am.Close()
		_ = al.Close()
		t.Fatalf("leader not elected")
	}
	pm := cluster.NewInMemoryPolicySync(election, "node-1")
	if err := pm.Start(runCtx); err != nil {
		t.Fatalf("Start policy sync: %v", err)
	}

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "bufnet", AuthEnabled: true}, AuthManager: am, AuditLogger: al, PolicyManager: pm})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	lis := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer(grpc.UnaryInterceptor(srv.unaryAuthInterceptor), grpc.StreamInterceptor(srv.streamAuthInterceptor))
	srv.grpc = gs
	srv.registerServices()

	go func() { _ = gs.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	cleanup := func() {
		_ = conn.Close()
		gs.Stop()
		_ = pm.Stop()
		_ = election.Stop()
		runCancel()
		runCancel = func() {}
		_ = am.Close()
		_ = al.Close()
	}

	return conn, cleanup
}

func loginGRPCToken(t *testing.T, conn *grpc.ClientConn) string {
	t.Helper()

	authClient := apiv1.NewAuthServiceClient(conn)
	resp, err := authClient.Login(context.Background(), &apiv1.LoginRequest{Username: "admin1", Password: "pw"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if resp.GetToken() == "" {
		t.Fatalf("expected token")
	}
	return resp.GetToken()
}

func TestGRPCPoliciesLifecycle(t *testing.T) {
	conn, cleanup := newPolicyGRPCServer(t)
	t.Cleanup(cleanup)

	tok := loginGRPCToken(t, conn)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+tok))

	policyYAML := "apiVersion: ztap/v1\nkind: NetworkPolicy\nmetadata:\n  name: web\nspec:\n  podSelector:\n    matchLabels:\n      app: web\n  egress:\n  - to:\n      ipBlock:\n        cidr: 10.0.0.0/8\n    ports:\n    - protocol: TCP\n      port: 443\n"

	policyClient := apiv1.NewPolicyServiceClient(conn)
	if _, err := policyClient.PutPolicy(ctx, &apiv1.PutPolicyRequest{Tenant: "default", Name: "web", PolicyYaml: policyYAML}); err != nil {
		t.Fatalf("PutPolicy: %v", err)
	}

	listResp, err := policyClient.ListPolicies(ctx, &apiv1.ListPoliciesRequest{})
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(listResp.GetPolicies()) == 0 {
		t.Fatalf("expected policies")
	}

	getResp, err := policyClient.GetPolicy(ctx, &apiv1.GetPolicyRequest{Tenant: "default", Name: "web"})
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if getResp.GetPolicy().GetVersion() == 0 {
		t.Fatalf("expected version")
	}

	revResp, err := policyClient.ListPolicyRevisions(ctx, &apiv1.ListPolicyRevisionsRequest{Tenant: "default", Name: "web", IncludeYaml: true})
	if err != nil {
		t.Fatalf("ListPolicyRevisions: %v", err)
	}
	if len(revResp.GetRevisions()) == 0 {
		t.Fatalf("expected revisions")
	}

	if _, err := policyClient.DeletePolicy(ctx, &apiv1.DeletePolicyRequest{Tenant: "default", Name: "web"}); err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}
}

func TestGRPCGetPolicyRequiresAuth(t *testing.T) {
	conn, cleanup := newPolicyGRPCServer(t)
	t.Cleanup(cleanup)

	policyClient := apiv1.NewPolicyServiceClient(conn)
	_, err := policyClient.GetPolicy(context.Background(), &apiv1.GetPolicyRequest{Tenant: "default", Name: "web"})
	if err == nil {
		t.Fatalf("expected unauthenticated error")
	}
}
