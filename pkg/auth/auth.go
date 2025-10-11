package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Role represents a user role
type Role string

const (
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
)

// Permission represents an action permission
type Permission string

const (
	PermEnforce      Permission = "enforce"
	PermViewPolicies Permission = "view_policies"
	PermViewLogs     Permission = "view_logs"
	PermViewStatus   Permission = "view_status"
	PermManageUsers  Permission = "manage_users"
	PermViewMetrics  Permission = "view_metrics"
)

// User represents an authenticated user
type User struct {
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	Role         Role      `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
	LastLogin    time.Time `json:"last_login,omitempty"`
	Enabled      bool      `json:"enabled"`
}

// Session represents an active user session
type Session struct {
	Token     string    `json:"token"`
	Username  string    `json:"username"`
	Role      Role      `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AuthManager manages authentication and authorization
type AuthManager struct {
	users    map[string]*User
	sessions map[string]*Session
	mu       sync.RWMutex
	dbPath   string
}

// Role permissions mapping
var rolePermissions = map[Role][]Permission{
	RoleAdmin: {
		PermEnforce,
		PermViewPolicies,
		PermViewLogs,
		PermViewStatus,
		PermManageUsers,
		PermViewMetrics,
	},
	RoleOperator: {
		PermEnforce,
		PermViewPolicies,
		PermViewLogs,
		PermViewStatus,
		PermViewMetrics,
	},
	RoleViewer: {
		PermViewPolicies,
		PermViewLogs,
		PermViewStatus,
		PermViewMetrics,
	},
}

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserDisabled       = errors.New("user account disabled")
	ErrSessionExpired     = errors.New("session expired")
	ErrSessionNotFound    = errors.New("session not found")
	ErrPermissionDenied   = errors.New("permission denied")
	ErrUserExists         = errors.New("user already exists")
)

// NewAuthManager creates a new authentication manager
func NewAuthManager(dbPath string) (*AuthManager, error) {
	am := &AuthManager{
		users:    make(map[string]*User),
		sessions: make(map[string]*Session),
		dbPath:   dbPath,
	}

	// Load existing users from disk
	if err := am.loadUsers(); err != nil {
		// If file doesn't exist, create default admin user
		if os.IsNotExist(err) {
			if err := am.createDefaultAdmin(); err != nil {
				return nil, fmt.Errorf("failed to create default admin: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to load users: %w", err)
		}
	}

	return am, nil
}

// createDefaultAdmin creates a default admin user
func (am *AuthManager) createDefaultAdmin() error {
	defaultPassword := "ztap-admin-change-me"

	log.Printf("WARNING: Creating default admin user with password: %s", defaultPassword)
	log.Println("WARNING: Please change the password immediately using 'ztap user change-password'")

	if err := am.CreateUser("admin", defaultPassword, RoleAdmin); err != nil {
		return err
	}

	return am.saveUsers()
}

// HashPassword creates a hash of the password
func HashPassword(password string) string {
	hash := sha256.Sum256([]byte(password))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// CreateUser creates a new user
func (am *AuthManager) CreateUser(username, password string, role Role) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if _, exists := am.users[username]; exists {
		return ErrUserExists
	}

	user := &User{
		Username:     username,
		PasswordHash: HashPassword(password),
		Role:         role,
		CreatedAt:    time.Now(),
		Enabled:      true,
	}

	am.users[username] = user
	return am.saveUsers()
}

// Authenticate validates credentials and creates a session
func (am *AuthManager) Authenticate(username, password string) (*Session, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	user, exists := am.users[username]
	if !exists {
		return nil, ErrUserNotFound
	}

	if !user.Enabled {
		return nil, ErrUserDisabled
	}

	passwordHash := HashPassword(password)
	if user.PasswordHash != passwordHash {
		return nil, ErrInvalidCredentials
	}

	// Update last login
	user.LastLogin = time.Now()

	// Create session
	token, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	session := &Session{
		Token:     token,
		Username:  username,
		Role:      user.Role,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	am.sessions[token] = session

	if err := am.saveUsers(); err != nil {
		return nil, err
	}

	return session, nil
}

// ValidateSession checks if a session is valid
func (am *AuthManager) ValidateSession(token string) (*Session, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	session, exists := am.sessions[token]
	if !exists {
		return nil, ErrSessionNotFound
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	return session, nil
}

// HasPermission checks if a user has a specific permission
func (am *AuthManager) HasPermission(token string, perm Permission) error {
	session, err := am.ValidateSession(token)
	if err != nil {
		return err
	}

	permissions, exists := rolePermissions[session.Role]
	if !exists {
		return ErrPermissionDenied
	}

	for _, p := range permissions {
		if p == perm {
			return nil
		}
	}

	return ErrPermissionDenied
}

// Logout invalidates a session
func (am *AuthManager) Logout(token string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	delete(am.sessions, token)
	return nil
}

// ChangePassword changes a user's password
func (am *AuthManager) ChangePassword(username, oldPassword, newPassword string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	user, exists := am.users[username]
	if !exists {
		return ErrUserNotFound
	}

	oldHash := HashPassword(oldPassword)
	if user.PasswordHash != oldHash {
		return ErrInvalidCredentials
	}

	user.PasswordHash = HashPassword(newPassword)
	return am.saveUsers()
}

// DisableUser disables a user account
func (am *AuthManager) DisableUser(username string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	user, exists := am.users[username]
	if !exists {
		return ErrUserNotFound
	}

	user.Enabled = false
	return am.saveUsers()
}

// EnableUser enables a user account
func (am *AuthManager) EnableUser(username string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	user, exists := am.users[username]
	if !exists {
		return ErrUserNotFound
	}

	user.Enabled = true
	return am.saveUsers()
}

// ListUsers returns all users
func (am *AuthManager) ListUsers() []*User {
	am.mu.RLock()
	defer am.mu.RUnlock()

	users := make([]*User, 0, len(am.users))
	for _, user := range am.users {
		// Don't expose password hash
		userCopy := *user
		userCopy.PasswordHash = ""
		users = append(users, &userCopy)
	}
	return users
}

// generateToken generates a random session token
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// loadUsers loads users from disk
func (am *AuthManager) loadUsers() error {
	data, err := os.ReadFile(am.dbPath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &am.users)
}

// saveUsers saves users to disk
func (am *AuthManager) saveUsers() error {
	// Ensure directory exists
	dir := filepath.Dir(am.dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(am.users, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(am.dbPath, data, 0600)
}

// CleanupExpiredSessions removes expired sessions
func (am *AuthManager) CleanupExpiredSessions() {
	am.mu.Lock()
	defer am.mu.Unlock()

	now := time.Now()
	for token, session := range am.sessions {
		if now.After(session.ExpiresAt) {
			delete(am.sessions, token)
		}
	}
}
