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

func TestUnaryAuthInterceptor_RejectsBadMethodPaths(t *testing.T) {
	t.Parallel()

	authModes := []struct {
		name        string
		authEnabled bool
	}{
		{name: "auth_enabled", authEnabled: true},
		{name: "auth_disabled", authEnabled: false},
	}

	cases := []struct {
		name       string
		fullMethod string
	}{
		{name: "missing_leading_slash", fullMethod: "ztap.api.v1.AuthService/WhoAmI"},
		{name: "double_leading_slash", fullMethod: "//ztap.api.v1.AuthService/WhoAmI"},
		{name: "extra_segment", fullMethod: "/ztap.api.v1.AuthService/WhoAmI/Extra"},
		{name: "unknown_method", fullMethod: "/unknown.Service/Method"},
	}

	for _, mode := range authModes {
		t.Run(mode.name, func(t *testing.T) {
			t.Parallel()
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()

					srv := &Server{cfg: Config{AuthEnabled: mode.authEnabled}}
					called := false

					_, err := srv.unaryAuthInterceptor(
						t.Context(),
						nil,
						&grpc.UnaryServerInfo{FullMethod: tc.fullMethod},
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
						t.Fatalf("handler should not be called")
					}
				})
			}
		})
	}
}

func TestStreamAuthInterceptor_RejectsBadMethodPaths(t *testing.T) {
	t.Parallel()

	authModes := []struct {
		name        string
		authEnabled bool
	}{
		{name: "auth_enabled", authEnabled: true},
		{name: "auth_disabled", authEnabled: false},
	}

	cases := []struct {
		name       string
		fullMethod string
	}{
		{name: "missing_leading_slash", fullMethod: "ztap.api.v1.FlowsService/Stream"},
		{name: "double_leading_slash", fullMethod: "//ztap.api.v1.FlowsService/Stream"},
		{name: "extra_segment", fullMethod: "/ztap.api.v1.FlowsService/Stream/Extra"},
		{name: "unknown_method", fullMethod: "/unknown.Service/Method"},
	}

	for _, mode := range authModes {
		t.Run(mode.name, func(t *testing.T) {
			t.Parallel()
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					t.Parallel()

					srv := &Server{cfg: Config{AuthEnabled: mode.authEnabled}}
					called := false

					err := srv.streamAuthInterceptor(
						nil,
						&noopServerStream{ctx: t.Context()},
						&grpc.StreamServerInfo{FullMethod: tc.fullMethod},
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
						t.Fatalf("handler should not be called")
					}
				})
			}
		})
	}
}
