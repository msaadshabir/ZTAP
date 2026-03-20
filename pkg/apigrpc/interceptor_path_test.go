package apigrpc

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type noopServerStream struct {
	ctx context.Context
}

func (n *noopServerStream) SetHeader(metadata.MD) error  { return nil }
func (n *noopServerStream) SendHeader(metadata.MD) error { return nil }
func (n *noopServerStream) SetTrailer(metadata.MD)       {}
func (n *noopServerStream) Context() context.Context     { return n.ctx }
func (n *noopServerStream) SendMsg(any) error            { return nil }
func (n *noopServerStream) RecvMsg(any) error            { return nil }

func TestUnaryAuthInterceptor_RejectsMalformedMethodPath(t *testing.T) {
	t.Parallel()

	srv := &Server{cfg: Config{AuthEnabled: true}}
	called := false

	_, err := srv.unaryAuthInterceptor(
		context.Background(),
		nil,
		&grpc.UnaryServerInfo{FullMethod: "ztap.api.v1.AuthService/WhoAmI"},
		func(ctx context.Context, req any) (any, error) {
			called = true
			return nil, nil
		},
	)
	if err == nil {
		t.Fatalf("expected error")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected grpc status error")
	}
	if st.Code() != codes.Unimplemented {
		t.Fatalf("expected UNIMPLEMENTED, got %v", st.Code())
	}
	if called {
		t.Fatalf("handler should not be called for malformed method path")
	}
}

func TestStreamAuthInterceptor_RejectsMalformedMethodPath(t *testing.T) {
	t.Parallel()

	srv := &Server{cfg: Config{AuthEnabled: true}}
	called := false

	err := srv.streamAuthInterceptor(
		nil,
		&noopServerStream{ctx: context.Background()},
		&grpc.StreamServerInfo{FullMethod: "ztap.api.v1.FlowsService/Stream"},
		func(srv any, ss grpc.ServerStream) error {
			called = true
			return nil
		},
	)
	if err == nil {
		t.Fatalf("expected error")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected grpc status error")
	}
	if st.Code() != codes.Unimplemented {
		t.Fatalf("expected UNIMPLEMENTED, got %v", st.Code())
	}
	if called {
		t.Fatalf("handler should not be called for malformed method path")
	}
}
