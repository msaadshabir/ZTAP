package apihttp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"ztap/internal/auth"
)

func TestUsersEndpointsRequireAuth(t *testing.T) {
	tmp := t.TempDir()
	am, err := auth.NewAuthManager(filepath.Join(tmp, "users.json"))
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: true}, AuthManager: am})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/users", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestUsersLifecycle(t *testing.T) {
	tmp := t.TempDir()
	am, err := auth.NewAuthManager(filepath.Join(tmp, "users.json"))
	if err != nil {
		t.Fatalf("NewAuthManager: %v", err)
	}
	if err := am.CreateUser("admin1", "password123", auth.RoleAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	srv, err := NewServer(ServerOptions{Config: Config{Listen: "127.0.0.1:0", AuthEnabled: true}, AuthManager: am})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	token := loginToken(t, srv, "admin1", "password123")

	createBody, _ := json.Marshal(map[string]string{"username": "user1", "password": "password123", "role": "viewer"})
	createReq := httptest.NewRequest(http.MethodPost, "/v1/users", bytes.NewReader(createBody))
	createReq.Header.Set("Authorization", "Bearer "+token)
	createRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(createRR, createReq)
	if createRR.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", createRR.Code, createRR.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/v1/users", nil)
	listReq.Header.Set("Authorization", "Bearer "+token)
	listRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(listRR, listReq)
	if listRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", listRR.Code)
	}

	patchBody, _ := json.Marshal(map[string]any{"enabled": false})
	patchReq := httptest.NewRequest(http.MethodPatch, "/v1/users/user1", bytes.NewReader(patchBody))
	patchReq.Header.Set("Authorization", "Bearer "+token)
	patchRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(patchRR, patchReq)
	if patchRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", patchRR.Code, patchRR.Body.String())
	}

	passBody, _ := json.Marshal(map[string]string{"new_password": "newpassword123"})
	passReq := httptest.NewRequest(http.MethodPost, "/v1/users/user1/password", bytes.NewReader(passBody))
	passReq.Header.Set("Authorization", "Bearer "+token)
	passRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(passRR, passReq)
	if passRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", passRR.Code, passRR.Body.String())
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/v1/users/user1", nil)
	deleteReq.Header.Set("Authorization", "Bearer "+token)
	deleteRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(deleteRR, deleteReq)
	if deleteRR.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", deleteRR.Code, deleteRR.Body.String())
	}
}
