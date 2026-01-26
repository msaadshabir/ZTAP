package apigrpc

import (
	"context"
	"net"
	"testing"
	"time"

	"ztap/pkg/audit"
	"ztap/pkg/auth"
	"ztap/pkg/flow"

	apiv1 "ztap/proto/ztap/api/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

func newGRPCHealthTestServer(t *testing.T) (*Server, *grpc.ClientConn) {
	t.Helper()

	tmp := t.TempDir()
	am, err := auth.NewAuthManager(tmp + "/users.json")
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	al, err := audit.NewAuditLogger(tmp + "/audit.log")
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "bufnet", AuthEnabled: true}, AuthManager: am, AuditLogger: al})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	lis := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer(grpc.UnaryInterceptor(srv.unaryAuthInterceptor), grpc.StreamInterceptor(srv.streamAuthInterceptor))
	srv.grpc = gs
	srv.registerServices()

	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(func() {
		gs.Stop()
		_ = am.Close()
		_ = al.Close()
	})

	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return srv, conn
}

func TestGRPCAuthLoginAndWhoAmI(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	am, err := auth.NewAuthManager(tmp + "/users.json")
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	if err := am.CreateUser("alice", "pw", auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	al, err := audit.NewAuditLogger(tmp + "/audit.log")
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "bufnet", AuthEnabled: true}, AuthManager: am, AuditLogger: al})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	lis := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer(grpc.UnaryInterceptor(srv.unaryAuthInterceptor), grpc.StreamInterceptor(srv.streamAuthInterceptor))
	srv.grpc = gs
	srv.registerServices()

	go func() {
		_ = gs.Serve(lis)
	}()
	t.Cleanup(func() {
		gs.Stop()
		_ = am.Close()
		_ = al.Close()
	})

	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	authClient := apiv1.NewAuthServiceClient(conn)
	loginResp, err := authClient.Login(context.Background(), &apiv1.LoginRequest{Username: "alice", Password: "pw"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	tok := loginResp.GetToken()
	if tok == "" {
		t.Fatalf("expected token")
	}

	mdCtx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+tok))
	whoResp, err := authClient.WhoAmI(mdCtx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("WhoAmI: %v", err)
	}
	if whoResp.GetUsername() != "alice" {
		t.Fatalf("unexpected username: %s", whoResp.GetUsername())
	}
}

func TestGRPCHealthCheck_Unauthenticated(t *testing.T) {
	t.Parallel()
	_, conn := newGRPCHealthTestServer(t)

	hc := grpc_health_v1.NewHealthClient(conn)
	resp, err := hc.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("Health Check: %v", err)
	}
	if resp.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("expected SERVING, got %v", resp.GetStatus())
	}
}

func TestGRPCHealthCheck_NotReady(t *testing.T) {
	t.Parallel()

	srv, conn := newGRPCHealthTestServer(t)
	srv.readiness.Audit = nil

	hc := grpc_health_v1.NewHealthClient(conn)
	resp, err := hc.Check(context.Background(), &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("Health Check: %v", err)
	}
	if resp.GetStatus() != grpc_health_v1.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("expected NOT_SERVING, got %v", resp.GetStatus())
	}
}

func TestGRPCHealthWatch_Unauthenticated(t *testing.T) {
	t.Parallel()

	_, conn := newGRPCHealthTestServer(t)

	hc := grpc_health_v1.NewHealthClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := hc.Watch(ctx, &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		t.Fatalf("Health Watch: %v", err)
	}
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("Health Watch recv: %v", err)
	}
	if resp.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
		t.Fatalf("expected SERVING, got %v", resp.GetStatus())
	}
}

func TestGRPCFlowsStream(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	am, err := auth.NewAuthManager(tmp + "/users.json")
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	if err := am.CreateUser("bob", "pw", auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	al, err := audit.NewAuditLogger(tmp + "/audit.log")
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	flowReaderFactory := func() flow.FlowReader {
		return flow.NewSimulatedReader(demoRawFlows(), 10*time.Millisecond)
	}
	srv, err := NewServer(ServerOptions{Config: Config{Listen: "bufnet", AuthEnabled: true}, AuthManager: am, AuditLogger: al, FlowReaderFactory: flowReaderFactory})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	lis := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer(grpc.UnaryInterceptor(srv.unaryAuthInterceptor), grpc.StreamInterceptor(srv.streamAuthInterceptor))
	srv.grpc = gs
	srv.registerServices()

	go func() {
		_ = gs.Serve(lis)
	}()
	t.Cleanup(func() {
		gs.Stop()
		_ = am.Close()
		_ = al.Close()
	})

	conn, err := grpc.NewClient("passthrough:///bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	authClient := apiv1.NewAuthServiceClient(conn)
	loginResp, err := authClient.Login(context.Background(), &apiv1.LoginRequest{Username: "bob", Password: "pw"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	tok := loginResp.GetToken()

	streamCtx, streamCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer streamCancel()
	ctx := metadata.NewOutgoingContext(streamCtx, metadata.Pairs("authorization", "Bearer "+tok))
	flowsClient := apiv1.NewFlowsServiceClient(conn)
	stream, err := flowsClient.Stream(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	ev, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	if ev.GetSourceIp() == "" {
		t.Fatalf("expected source_ip")
	}
}
