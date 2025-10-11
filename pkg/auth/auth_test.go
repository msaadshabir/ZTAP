package auth

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestCreateUser(t *testing.T) {
	tmpDir := t.TempDir()
	manager, err := NewAuthManager(filepath.Join(tmpDir, "users.json"))
	if err != nil {
		t.Fatalf("Failed to create auth manager: %v", err)
	}

	err = manager.CreateUser("testuser", "password123", RoleOperator)
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	manager.mu.RLock()
	user, exists := manager.users["testuser"]
	manager.mu.RUnlock()

	if !exists {
		t.Fatal("User was not created")
	}

	if user.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", user.Username)
	}

	if user.Role != RoleOperator {
		t.Errorf("Expected role 'operator', got '%s'", user.Role)
	}

	if !user.Enabled {
		t.Error("New user should be enabled")
	}

	err = manager.CreateUser("testuser", "password456", RoleViewer)
	if err == nil {
		t.Error("Expected error when creating duplicate user")
	}
}

func TestAuthenticate(t *testing.T) {
	tmpDir := t.TempDir()
	manager, _ := NewAuthManager(filepath.Join(tmpDir, "users.json"))

	manager.CreateUser("testuser", "correctpassword", RoleOperator)

	session, err := manager.Authenticate("testuser", "correctpassword")
	if err != nil {
		t.Fatalf("Authentication failed: %v", err)
	}

	if session.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", session.Username)
	}

	if session.Token == "" {
		t.Error("Session token is empty")
	}

	_, err = manager.Authenticate("testuser", "wrongpassword")
	if err == nil {
		t.Error("Expected error for wrong password")
	}

	_, err = manager.Authenticate("nonexistent", "password")
	if err == nil {
		t.Error("Expected error for nonexistent user")
	}

	manager.DisableUser("testuser")
	_, err = manager.Authenticate("testuser", "correctpassword")
	if err == nil {
		t.Error("Expected error for disabled user")
	}
}

func TestValidateSession(t *testing.T) {
	tmpDir := t.TempDir()
	manager, _ := NewAuthManager(filepath.Join(tmpDir, "users.json"))

	manager.CreateUser("testuser", "password", RoleOperator)
	session, _ := manager.Authenticate("testuser", "password")

	validatedSession, err := manager.ValidateSession(session.Token)
	if err != nil {
		t.Fatalf("Session validation failed: %v", err)
	}

	if validatedSession.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", validatedSession.Username)
	}

	_, err = manager.ValidateSession("invalid-token")
	if err == nil {
		t.Error("Expected error for invalid token")
	}

	manager.mu.Lock()
	manager.sessions[session.Token].ExpiresAt = time.Now().Add(-1 * time.Hour)
	manager.mu.Unlock()

	_, err = manager.ValidateSession(session.Token)
	if err == nil {
		t.Error("Expected error for expired session")
	}
}

func TestHasPermission(t *testing.T) {
	tmpDir := t.TempDir()
	manager, _ := NewAuthManager(filepath.Join(tmpDir, "users.json"))

	manager.CreateUser("admin2", "pass", RoleAdmin)
	manager.CreateUser("operator", "pass", RoleOperator)
	manager.CreateUser("viewer", "pass", RoleViewer)

	// Authenticate and get tokens
	adminSession, _ := manager.Authenticate("admin2", "pass")
	operatorSession, _ := manager.Authenticate("operator", "pass")
	viewerSession, _ := manager.Authenticate("viewer", "pass")

	tests := []struct {
		token      string
		permission Permission
		expected   bool
	}{
		{adminSession.Token, PermEnforce, true},
		{adminSession.Token, PermManageUsers, true},
		{operatorSession.Token, PermEnforce, true},
		{operatorSession.Token, PermManageUsers, false},
		{viewerSession.Token, PermViewLogs, true},
		{viewerSession.Token, PermEnforce, false},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("test_%d", i), func(t *testing.T) {
			err := manager.HasPermission(tt.token, tt.permission)
			hasPermission := (err == nil)
			if hasPermission != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, hasPermission)
			}
		})
	}
}

func TestChangePassword(t *testing.T) {
	tmpDir := t.TempDir()
	manager, _ := NewAuthManager(filepath.Join(tmpDir, "users.json"))

	manager.CreateUser("testuser", "oldpassword", RoleOperator)

	err := manager.ChangePassword("testuser", "oldpassword", "newpassword")
	if err != nil {
		t.Fatalf("Failed to change password: %v", err)
	}

	_, err = manager.Authenticate("testuser", "oldpassword")
	if err == nil {
		t.Error("Old password still works")
	}

	_, err = manager.Authenticate("testuser", "newpassword")
	if err != nil {
		t.Errorf("New password doesn't work: %v", err)
	}

	err = manager.ChangePassword("testuser", "wrongoldpassword", "anotherpassword")
	if err == nil {
		t.Error("Expected error for wrong old password")
	}
}

func TestDisableEnable(t *testing.T) {
	tmpDir := t.TempDir()
	manager, _ := NewAuthManager(filepath.Join(tmpDir, "users.json"))

	manager.CreateUser("testuser", "password", RoleOperator)

	err := manager.DisableUser("testuser")
	if err != nil {
		t.Fatalf("Failed to disable user: %v", err)
	}

	manager.mu.RLock()
	enabled := manager.users["testuser"].Enabled
	manager.mu.RUnlock()

	if enabled {
		t.Error("User was not disabled")
	}

	err = manager.EnableUser("testuser")
	if err != nil {
		t.Fatalf("Failed to enable user: %v", err)
	}

	manager.mu.RLock()
	enabled = manager.users["testuser"].Enabled
	manager.mu.RUnlock()

	if !enabled {
		t.Error("User was not enabled")
	}
}

func TestDefaultAdmin(t *testing.T) {
	tmpDir := t.TempDir()
	manager, _ := NewAuthManager(filepath.Join(tmpDir, "users.json"))

	manager.mu.RLock()
	admin, exists := manager.users["admin"]
	manager.mu.RUnlock()

	if !exists {
		t.Fatal("Default admin user not created")
	}

	if admin.Role != RoleAdmin {
		t.Errorf("Expected admin role, got '%s'", admin.Role)
	}

	_, err := manager.Authenticate("admin", "ztap-admin-change-me")
	if err != nil {
		t.Errorf("Admin authentication failed: %v", err)
	}
}
