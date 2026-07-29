package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"ztap/pkg/logging"

	"golang.org/x/crypto/bcrypt"
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
	PermEnforce        Permission = "enforce"
	PermViewPolicies   Permission = "view_policies"
	PermViewCompliance Permission = "view_compliance"
	PermViewLogs       Permission = "view_logs"
	PermViewStatus     Permission = "view_status"
	PermManageUsers    Permission = "manage_users"
	PermManagePolicies Permission = "manage_policies"
	PermManageCluster  Permission = "manage_cluster"
	PermViewMetrics    Permission = "view_metrics"
	PermBackupRestore  Permission = "backup_restore"
)

// User represents an authenticated user
type User struct {
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	Role         Role      `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
	LastLogin    time.Time `json:"last_login"`
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
	users      map[string]*User
	store      SessionStore
	mu         sync.RWMutex
	dbPath     string
	sessionTTL time.Duration
}

func (am *AuthManager) UsersPath() string {
	if am == nil {
		return ""
	}
	return am.dbPath
}

func (am *AuthManager) SessionStore() SessionStore {
	if am == nil {
		return nil
	}
	return am.store
}

// Role permissions mapping
var rolePermissions = map[Role]map[Permission]bool{
	RoleAdmin: {
		PermEnforce:        true,
		PermViewPolicies:   true,
		PermViewCompliance: true,
		PermViewLogs:       true,
		PermViewStatus:     true,
		PermManageUsers:    true,
		PermManagePolicies: true,
		PermManageCluster:  true,
		PermViewMetrics:    true,
		PermBackupRestore:  true,
	},
	RoleOperator: {
		PermEnforce:        true,
		PermViewPolicies:   true,
		PermViewCompliance: true,
		PermViewLogs:       true,
		PermViewStatus:     true,
		PermManagePolicies: true,
		PermViewMetrics:    true,
	},
	RoleViewer: {
		PermViewPolicies: true,
		PermViewLogs:     true,
		PermViewStatus:   true,
		PermViewMetrics:  true,
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
	ErrLastAdmin          = errors.New("cannot remove last admin user")
)

// NewAuthManager creates a new authentication manager
func NewAuthManager(dbPath string) (*AuthManager, error) {
	return NewAuthManagerWithOptions(AuthManagerOptions{DBPath: dbPath})
}

type AuthManagerOptions struct {
	DBPath     string
	Store      SessionStore
	SessionTTL time.Duration
}

func NewAuthManagerWithStore(dbPath string, store SessionStore) (*AuthManager, error) {
	return NewAuthManagerWithOptions(AuthManagerOptions{DBPath: dbPath, Store: store})
}

func NewAuthManagerWithOptions(opts AuthManagerOptions) (*AuthManager, error) {
	store := opts.Store
	if store == nil {
		store = NewInMemorySessionStore()
	}
	ttl := opts.SessionTTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}

	am := &AuthManager{
		users:      make(map[string]*User),
		store:      store,
		dbPath:     opts.DBPath,
		sessionTTL: ttl,
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
	password := strings.TrimSpace(os.Getenv("ZTAP_BOOTSTRAP_ADMIN_PASSWORD"))
	fromEnv := password != ""
	if !fromEnv {
		p, err := generateBootstrapPassword()
		if err != nil {
			return fmt.Errorf("generating bootstrap password: %w", err)
		}
		password = p
	}

	if err := am.CreateUser("admin", password, RoleAdmin); err != nil {
		return err
	}

	if err := am.saveUsers(); err != nil {
		return err
	}

	if fromEnv {
		logging.Warn("Created default admin user 'admin'. Change the password immediately using 'ztap user change-password'.", nil)
		return nil
	}

	path, err := am.writeBootstrapPasswordFile(password)
	if err != nil {
		return err
	}
	logging.Warnf("Created default admin user 'admin'. Bootstrap password written to %s (delete after use).", path)
	return nil
}

func generateBootstrapPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (am *AuthManager) writeBootstrapPasswordFile(password string) (string, error) {
	dir := filepath.Dir(am.dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("creating auth directory: %w", err)
	}
	path := filepath.Join(dir, "bootstrap_admin_password.txt")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", fmt.Errorf("creating bootstrap password file: %w", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(password + "\n"); err != nil {
		return "", fmt.Errorf("writing bootstrap password file: %w", err)
	}
	return path, nil
}

// HashPassword creates a hash of the password
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func VerifyPassword(passwordHash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password))
}

// CreateUser creates a new user
func (am *AuthManager) CreateUser(username, password string, role Role) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("username cannot be empty")
	}
	if password == "" {
		return errors.New("password cannot be empty")
	}

	role = Role(strings.TrimSpace(string(role)))
	if !isValidRole(role) {
		return fmt.Errorf("invalid role: %s", role)
	}

	if _, exists := am.users[username]; exists {
		return ErrUserExists
	}

	passwordHash, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}

	user := &User{
		Username:     username,
		PasswordHash: passwordHash,
		Role:         role,
		CreatedAt:    time.Now(),
		Enabled:      true,
	}

	am.users[username] = user
	return am.saveUsers()
}

// GetUser returns a copy of a user without the password hash.
func (am *AuthManager) GetUser(username string) (*User, error) {
	am.mu.RLock()
	defer am.mu.RUnlock()

	username = strings.TrimSpace(username)
	if username == "" {
		return nil, ErrUserNotFound
	}

	user, exists := am.users[username]
	if !exists {
		return nil, ErrUserNotFound
	}
	userCopy := *user
	userCopy.PasswordHash = ""
	return &userCopy, nil
}

// Authenticate validates credentials and creates a session
func (am *AuthManager) Authenticate(ctx context.Context, username, password string) (*Session, error) {
	am.mu.Lock()
	defer am.mu.Unlock()
	username = strings.TrimSpace(username)
	if username == "" {
		return nil, ErrInvalidCredentials
	}
	if password == "" {
		return nil, ErrInvalidCredentials
	}

	user, exists := am.users[username]
	if !exists {
		return nil, ErrUserNotFound
	}

	if !user.Enabled {
		return nil, ErrUserDisabled
	}

	if err := VerifyPassword(user.PasswordHash, password); err != nil {
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
		ExpiresAt: time.Now().Add(am.sessionTTL),
	}

	if err := am.store.Put(ctx, token, session); err != nil {
		return nil, err
	}

	if err := am.saveUsers(); err != nil {
		return nil, err
	}

	return session, nil
}

// ValidateSession checks if a session is valid
func (am *AuthManager) ValidateSession(token string) (*Session, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil, ErrSessionNotFound
	}
	session, err := am.store.Get(context.Background(), token)
	if err != nil {
		return nil, err
	}
	if time.Now().After(session.ExpiresAt) {
		_ = am.store.Delete(context.Background(), token)
		return nil, ErrSessionExpired
	}
	return session, nil
}

// HasPermission checks if a user has a specific permission
func (am *AuthManager) HasPermission(token string, perm Permission) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return ErrSessionNotFound
	}
	session, err := am.ValidateSession(token)
	if err != nil {
		return err
	}

	permissions, exists := rolePermissions[session.Role]
	if !exists {
		return ErrPermissionDenied
	}

	// O(1) map lookup instead of O(n) slice iteration
	if permissions[perm] {
		return nil
	}

	return ErrPermissionDenied
}

// Logout invalidates a session
func (am *AuthManager) Logout(token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	_ = am.store.Delete(context.Background(), token)
	return nil
}

// ChangePassword changes a user's password
func (am *AuthManager) ChangePassword(username, oldPassword, newPassword string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	username = strings.TrimSpace(username)
	if username == "" {
		return ErrUserNotFound
	}
	if oldPassword == "" || newPassword == "" {
		return ErrInvalidCredentials
	}

	user, exists := am.users[username]
	if !exists {
		return ErrUserNotFound
	}

	if err := VerifyPassword(user.PasswordHash, oldPassword); err != nil {
		return ErrInvalidCredentials
	}

	newHash, err := HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hashing new password: %w", err)
	}
	user.PasswordHash = newHash
	return am.saveUsers()
}

// SetPassword resets a user's password without verifying the old password.
func (am *AuthManager) SetPassword(username, newPassword string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	username = strings.TrimSpace(username)
	if username == "" {
		return ErrUserNotFound
	}
	if newPassword == "" {
		return ErrInvalidCredentials
	}

	user, exists := am.users[username]
	if !exists {
		return ErrUserNotFound
	}

	newHash, err := HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hashing new password: %w", err)
	}
	user.PasswordHash = newHash
	return am.saveUsers()
}

// DisableUser disables a user account
func (am *AuthManager) DisableUser(username string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	username = strings.TrimSpace(username)
	if username == "" {
		return ErrUserNotFound
	}

	user, exists := am.users[username]
	if !exists {
		return ErrUserNotFound
	}
	if user.Role == RoleAdmin && am.countAdminsLocked() <= 1 {
		return ErrLastAdmin
	}

	prev := user.Enabled
	user.Enabled = false

	if revoker, ok := am.store.(SessionStoreUserRevoker); ok {
		if _, err := revoker.DeleteByUsername(context.Background(), username); err != nil {
			user.Enabled = prev
			return fmt.Errorf("revoking sessions: %w", err)
		}
	}

	return am.saveUsers()
}

// EnableUser enables a user account
func (am *AuthManager) EnableUser(username string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	username = strings.TrimSpace(username)
	if username == "" {
		return ErrUserNotFound
	}

	user, exists := am.users[username]
	if !exists {
		return ErrUserNotFound
	}

	user.Enabled = true
	return am.saveUsers()
}

// SetUserRole updates the role for an existing user.
func (am *AuthManager) SetUserRole(username string, role Role) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	username = strings.TrimSpace(username)
	if username == "" {
		return ErrUserNotFound
	}

	role = Role(strings.TrimSpace(string(role)))
	if !isValidRole(role) {
		return fmt.Errorf("invalid role: %s", role)
	}

	user, exists := am.users[username]
	if !exists {
		return ErrUserNotFound
	}
	if user.Role == RoleAdmin && role != RoleAdmin && am.countAdminsLocked() <= 1 {
		return ErrLastAdmin
	}
	user.Role = role
	return am.saveUsers()
}

// DeleteUser removes a user and revokes their sessions when possible.
func (am *AuthManager) DeleteUser(username string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	username = strings.TrimSpace(username)
	if username == "" {
		return ErrUserNotFound
	}

	user, exists := am.users[username]
	if !exists {
		return ErrUserNotFound
	}
	if user.Role == RoleAdmin && am.countAdminsLocked() <= 1 {
		return ErrLastAdmin
	}
	delete(am.users, username)

	if revoker, ok := am.store.(SessionStoreUserRevoker); ok {
		_, _ = revoker.DeleteByUsername(context.Background(), username)
	}

	return am.saveUsers()
}

func (am *AuthManager) Ready(ctx context.Context) error {
	if am == nil {
		return errors.New("auth manager is nil")
	}
	if am.store == nil {
		return errors.New("session store is nil")
	}
	if p, ok := am.store.(SessionStorePinger); ok {
		return p.Ping(ctx)
	}
	return nil
}

func (am *AuthManager) Close() error {
	if am.store == nil {
		return nil
	}
	return am.store.Close()
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

func (am *AuthManager) countAdminsLocked() int {
	count := 0
	for _, user := range am.users {
		if user.Role == RoleAdmin {
			count++
		}
	}
	return count
}

func isValidRole(role Role) bool {
	switch role {
	case RoleAdmin, RoleOperator, RoleViewer:
		return true
	default:
		return false
	}
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
	if len(data) == 0 {
		am.users = make(map[string]*User)
		return nil
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
	_, _ = am.store.DeleteExpired(context.Background(), time.Now())
}
