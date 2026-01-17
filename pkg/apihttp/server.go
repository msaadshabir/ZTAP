package apihttp

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"ztap/pkg/alert"
	"ztap/pkg/audit"
	"ztap/pkg/auth"
	"ztap/pkg/enforcer"
	"ztap/pkg/flow"
	"ztap/pkg/health"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Config struct {
	Listen      string
	AuthEnabled bool
	TLS         TLSConfig
}

type TLSConfig struct {
	Enabled  bool
	CertFile string
	KeyFile  string
}

type Server struct {
	cfg                Config
	mux                *http.ServeMux
	auth               *auth.AuthManager
	audit              *audit.AuditLogger
	readiness          *health.Checker
	startTime          time.Time
	flowReader         func() flow.FlowReader
	alerts             *alert.Manager
	sessionsSQLitePath string
}

type ServerOptions struct {
	Config Config

	AuthManager *auth.AuthManager
	AuditLogger *audit.AuditLogger
	Alerts      *alert.Manager

	SessionsSQLitePath string

	FlowReaderFactory func() flow.FlowReader
}

func NewServer(opts ServerOptions) (*Server, error) {
	if strings.TrimSpace(opts.Config.Listen) == "" {
		opts.Config.Listen = "127.0.0.1:8080"
	}
	if opts.AuthManager == nil {
		am, err := defaultAuthManager()
		if err != nil {
			return nil, err
		}
		opts.AuthManager = am
	}
	if opts.AuditLogger == nil {
		al, err := defaultAuditLogger()
		if err != nil {
			return nil, err
		}
		opts.AuditLogger = al
	}
	if opts.FlowReaderFactory == nil {
		opts.FlowReaderFactory = createFlowReader
	}

	s := &Server{
		cfg:                opts.Config,
		mux:                http.NewServeMux(),
		auth:               opts.AuthManager,
		audit:              opts.AuditLogger,
		readiness:          &health.Checker{AuthEnabled: opts.Config.AuthEnabled, Auth: opts.AuthManager, Audit: opts.AuditLogger},
		startTime:          time.Now(),
		flowReader:         opts.FlowReaderFactory,
		alerts:             opts.Alerts,
		sessionsSQLitePath: opts.SessionsSQLitePath,
	}

	s.routes()
	return s, nil
}

func (s *Server) ListenAddr() string {
	return s.cfg.Listen
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) Serve(ctx context.Context) error {
	httpServer := &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)

	if s.alerts != nil {
		s.alerts.Start(ctx)
		defer s.alerts.Close()
	}

	go func() {
		if s.cfg.TLS.Enabled {
			if s.cfg.TLS.CertFile == "" || s.cfg.TLS.KeyFile == "" {
				errCh <- fmt.Errorf("TLS is enabled but certificate or key file is missing")
				return
			}
			httpServer.TLSConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
			}
			errCh <- httpServer.ListenAndServeTLS(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
		} else {
			errCh <- httpServer.ListenAndServe()
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (s *Server) routes() {
	s.mux.HandleFunc("/healthz", s.handleHealth)
	s.mux.HandleFunc("/readyz", s.handleReady)

	s.mux.HandleFunc("/v1/auth/login", s.handleAuthLogin)
	s.mux.HandleFunc("/v1/auth/whoami", s.requireAuth(auth.PermViewStatus, s.handleAuthWhoAmI))

	s.mux.HandleFunc("/v1/status", s.requireAuth(auth.PermViewStatus, s.handleStatus))

	s.mux.HandleFunc("/v1/enforcement/status", s.requireAuth(auth.PermViewStatus, s.handleEnforcementStatus))
	s.mux.HandleFunc("/v1/enforcement/start", s.requireAuth(auth.PermEnforce, s.handleEnforcementStart))
	s.mux.HandleFunc("/v1/enforcement/stop", s.requireAuth(auth.PermEnforce, s.handleEnforcementStop))

	s.mux.HandleFunc("/v1/flows/stream", s.requireAuth(auth.PermViewStatus, s.handleFlowsStream))

	s.mux.HandleFunc("/v1/config/backup", s.requireAuth(auth.PermBackupRestore, s.handleConfigBackup))
	s.mux.HandleFunc("/v1/config/restore", s.requireAuth(auth.PermBackupRestore, s.handleConfigRestore))

	metricsHandler := promhttp.Handler()
	s.mux.HandleFunc("/metrics", s.requireAuth(auth.PermViewMetrics, metricsHandler.ServeHTTP))
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	if err == nil {
		err = errors.New("unknown error")
	}
	writeJSON(w, status, errorResponse{Error: err.Error()})
}

func (s *Server) emitAlert(a alert.Alert) {
	if s.alerts == nil {
		return
	}
	_ = s.alerts.Emit(a)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	res := s.readiness.Check(r.Context())
	if res.Ready {
		writeJSON(w, http.StatusOK, res)
		return
	}
	writeJSON(w, http.StatusServiceUnavailable, res)
}

type ctxKey int

const sessionKey ctxKey = 1

func (s *Server) requireAuth(perm auth.Permission, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.AuthEnabled {
			next(w, r)
			return
		}

		token, err := bearerToken(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err)
			return
		}

		if err := s.auth.HasPermission(token, perm); err != nil {
			writeError(w, http.StatusForbidden, err)
			return
		}

		sess, err := s.auth.ValidateSession(token)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err)
			return
		}

		ctx := context.WithValue(r.Context(), sessionKey, sess)
		next(w, r.WithContext(ctx))
	}
}

func bearerToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", errors.New("missing Authorization header")
	}
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 {
		return "", errors.New("invalid Authorization header")
	}
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(parts[0])), []byte("bearer")) != 1 {
		return "", errors.New("invalid Authorization scheme")
	}
	tok := strings.TrimSpace(parts[1])
	if tok == "" {
		return "", errors.New("empty bearer token")
	}
	return tok, nil
}

func sessionFromContext(ctx context.Context) (*auth.Session, bool) {
	sess, ok := ctx.Value(sessionKey).(*auth.Session)
	return sess, ok
}

func defaultAuthManager() (*auth.AuthManager, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}
	return auth.NewAuthManager(filepath.Join(homeDir, ".ztap", "users.json"))
}

func defaultAuditLogger() (*audit.AuditLogger, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}
	logPath := filepath.Join(homeDir, ".ztap", "audit.log")
	return audit.NewAuditLogger(logPath)
}

type statusResponse struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Hostname string `json:"hostname"`
	PID      int    `json:"pid"`
	Uptime   string `json:"uptime"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	hostname, _ := os.Hostname()
	writeJSON(w, http.StatusOK, statusResponse{
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Hostname: hostname,
		PID:      os.Getpid(),
		Uptime:   time.Since(s.startTime).Truncate(time.Second).String(),
	})
}

type authLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type authLoginResponse struct {
	Token     string    `json:"token"`
	Username  string    `json:"username"`
	Role      auth.Role `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req authLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid json: %w", err))
		return
	}
	if strings.TrimSpace(req.Username) == "" || strings.TrimSpace(req.Password) == "" {
		writeError(w, http.StatusBadRequest, errors.New("username and password are required"))
		return
	}

	sess, err := s.auth.Authenticate(req.Username, req.Password)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	writeJSON(w, http.StatusOK, authLoginResponse{Token: sess.Token, Username: sess.Username, Role: sess.Role, ExpiresAt: sess.ExpiresAt})
}

type whoAmIResponse struct {
	Username  string    `json:"username"`
	Role      auth.Role `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Server) handleAuthWhoAmI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	sess, ok := sessionFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, errors.New("missing session"))
		return
	}
	writeJSON(w, http.StatusOK, whoAmIResponse{Username: sess.Username, Role: sess.Role, ExpiresAt: sess.ExpiresAt})
}

type enforcementStatusResponse struct {
	Platform          string `json:"platform"`
	EBPFActive        bool   `json:"ebpf_active"`
	FlowEventsPinPath string `json:"flow_events_pin_path"`
}

func (s *Server) handleEnforcementStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, enforcementStatusResponse{Platform: runtime.GOOS, EBPFActive: enforcer.IsEBPFEnforcementActive(), FlowEventsPinPath: enforcer.DefaultFlowEventsPinPath})
}
