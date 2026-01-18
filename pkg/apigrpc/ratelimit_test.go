package apigrpc

import (
	"context"
	"net"
	"testing"
	"time"

	"ztap/pkg/audit"
	"ztap/pkg/auth"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestGRPCRateLimit_UnaryBlocksSecond(t *testing.T) {
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

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "bufnet", AuthEnabled: true, RateLimit: RateLimitConfig{
		Enabled:  true,
		PerToken: RateLimitBucketConfig{RPS: 0.1, Burst: 1},
		PerIP:    RateLimitBucketConfig{RPS: 1000, Burst: 1000},
	}}, AuthManager: am, AuditLogger: al})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	lis := bufconn.Listen(1024 * 1024)
	gs := grpc.NewServer(
		grpc.ChainUnaryInterceptor(srv.unaryRateLimitInterceptor, srv.unaryAuthInterceptor),
		grpc.ChainStreamInterceptor(srv.streamRateLimitInterceptor, srv.streamAuthInterceptor),
	)
	srv.grpc = gs
	srv.registerServices()

	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(func() { gs.Stop() })

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

	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+tok))
	// First WhoAmI (allowed)
	var whoResp structpb.Struct
	if err := conn.Invoke(ctx, "/ztap.api.v1.AuthService/WhoAmI", &emptypb.Empty{}, &whoResp); err != nil {
		t.Fatalf("WhoAmI first: %v", err)
	}

	var whoResp2 structpb.Struct
	err = conn.Invoke(ctx, "/ztap.api.v1.AuthService/WhoAmI", &emptypb.Empty{}, &whoResp2)
	if err == nil {
		t.Fatalf("expected rate limit error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.ResourceExhausted {
		t.Fatalf("expected RESOURCE_EXHAUSTED, got %v", st.Code())
	}
}
