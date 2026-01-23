package apigrpc

import (
	"context"
	"net"
	"testing"
	"time"

	"ztap/pkg/audit"
	"ztap/pkg/auth"
	"ztap/pkg/flow"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
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

	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	conn, err := grpc.DialContext(dialCtx, "bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("DialContext: %v", err)
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

	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(dialCtx, "bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	loginReq, _ := structpb.NewStruct(map[string]any{"username": "alice", "password": "pw"})
	var loginResp structpb.Struct
	if err := conn.Invoke(context.Background(), "/ztap.api.v1.AuthService/Login", loginReq, &loginResp); err != nil {
		t.Fatalf("Login: %v", err)
	}
	tok := loginResp.Fields["token"].GetStringValue()
	if tok == "" {
		t.Fatalf("expected token")
	}

	mdCtx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+tok))
	var whoResp structpb.Struct
	if err := conn.Invoke(mdCtx, "/ztap.api.v1.AuthService/WhoAmI", &emptypb.Empty{}, &whoResp); err != nil {
		t.Fatalf("WhoAmI: %v", err)
	}
	if whoResp.Fields["username"].GetStringValue() != "alice" {
		t.Fatalf("unexpected username: %s", whoResp.Fields["username"].GetStringValue())
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

	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(dialCtx, "bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	loginReq, _ := structpb.NewStruct(map[string]any{"username": "bob", "password": "pw"})
	var loginResp structpb.Struct
	if err := conn.Invoke(context.Background(), "/ztap.api.v1.AuthService/Login", loginReq, &loginResp); err != nil {
		t.Fatalf("Login: %v", err)
	}
	tok := loginResp.Fields["token"].GetStringValue()

	streamCtx, streamCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer streamCancel()
	ctx := metadata.NewOutgoingContext(streamCtx, metadata.Pairs("authorization", "Bearer "+tok))
	stream, err := conn.NewStream(ctx, &flowsServiceDesc.Streams[0], "/ztap.api.v1.FlowsService/Stream")
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	if err := stream.SendMsg(&emptypb.Empty{}); err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}

	var ev structpb.Struct
	if err := stream.RecvMsg(&ev); err != nil {
		t.Fatalf("RecvMsg: %v", err)
	}
	if ev.Fields["source_ip"].GetStringValue() == "" {
		t.Fatalf("expected source_ip")
	}
}
