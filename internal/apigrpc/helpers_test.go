package apigrpc

import (
	"testing"

	apiv1 "ztap/proto/ztap/api/v1"

	"google.golang.org/grpc"
)

// loginGRPCToken performs a Login RPC and returns the bearer token.
func loginGRPCToken(t *testing.T, conn *grpc.ClientConn, username, password string) string {
	t.Helper()

	authClient := apiv1.NewAuthServiceClient(conn)
	resp, err := authClient.Login(t.Context(), &apiv1.LoginRequest{Username: username, Password: password})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if resp.GetToken() == "" {
		t.Fatalf("expected token")
	}
	return resp.GetToken()
}
