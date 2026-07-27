package apigrpc

import (
	"context"
	"net"
	"testing"

	"ztap/pkg/audit"
	"ztap/pkg/auth"

	apiv1 "ztap/proto/ztap/api/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestGRPCRateLimit_UnauthBucketBlocks(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	am, err := auth.NewAuthManager(tmp + "/users.json")
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	al, err := audit.NewAuditLogger(tmp + "/audit.log")
	if err != nil {
		t.Fatalf("NewAuditLogger: %v", err)
	}

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "bufnet", AuthEnabled: true, RateLimit: RateLimitConfig{
		Enabled:         true,
		Unauthenticated: RateLimitBucketConfig{RPS: 0.1, Burst: 1},
		PerIP:           RateLimitBucketConfig{RPS: 1000, Burst: 1000},
		PerToken:        RateLimitBucketConfig{RPS: 1000, Burst: 1000},
		ExemptMethods:   []string{"/ztap.api.v1.AuthService/Login"},
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

	// Call a protected method without auth metadata (will fail auth, but should still be rate-limited).
	_, _ = authClient.WhoAmI(t.Context(), &emptypb.Empty{})

	_, err = authClient.WhoAmI(t.Context(), &emptypb.Empty{})
	if err == nil {
		t.Fatalf("expected error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.ResourceExhausted {
		t.Fatalf("expected RESOURCE_EXHAUSTED, got %v", st.Code())
	}
	if len(st.Details()) == 0 {
		t.Fatalf("expected RetryInfo details")
	}
}
