package apigrpc

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"ztap/pkg/alert"
	"ztap/pkg/audit"
	"ztap/pkg/auth"
	"ztap/pkg/cluster"
	"ztap/pkg/enforcer"
	"ztap/pkg/flow"
	"ztap/pkg/health"
	"ztap/pkg/policy"
	"ztap/pkg/ratelimit"
	apiv1 "ztap/proto/ztap/api/v1"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	grpc_health_v1 "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	errdetails "google.golang.org/genproto/googleapis/rpc/errdetails"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

type Config struct {
	Listen      string
	AuthEnabled bool
	TLS         TLSConfig
	RateLimit   RateLimitConfig
}

type RateLimitConfig struct {
	Enabled bool

	Unauthenticated RateLimitBucketConfig
	PerIP           RateLimitBucketConfig
	PerToken        RateLimitBucketConfig

	ExemptMethods []string
}

type RateLimitBucketConfig struct {
	RPS   float64
	Burst int
}

type TLSConfig struct {
	Enabled      bool
	CertFile     string
	KeyFile      string
	ClientAuth   bool
	ClientCAFile string
}

type ServerOptions struct {
	Config Config

	AuthManager *auth.AuthManager
	AuditLogger *audit.AuditLogger
	Alerts      *alert.Manager

	FlowReaderFactory func() flow.FlowReader
}

type Server struct {
	cfg       Config
	grpc      *grpc.Server
	auth      *auth.AuthManager
	audit     *audit.AuditLogger
	readiness *health.Checker
	startTime time.Time
	alerts    *alert.Manager

	flowReader func() flow.FlowReader

	rateLimiter *ratelimit.Store
	rlAllowed   *prometheus.CounterVec
	rlLimited   *prometheus.CounterVec
}

func NewServer(opts ServerOptions) (*Server, error) {
	if strings.TrimSpace(opts.Config.Listen) == "" {
		opts.Config.Listen = "127.0.0.1:9092"
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
		cfg:        opts.Config,
		auth:       opts.AuthManager,
		audit:      opts.AuditLogger,
		readiness:  &health.Checker{AuthEnabled: opts.Config.AuthEnabled, Auth: opts.AuthManager, Audit: opts.AuditLogger},
		startTime:  time.Now(),
		alerts:     opts.Alerts,
		flowReader: opts.FlowReaderFactory,
	}

	s.initRateLimiting()

	grpcOpts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(s.unaryRateLimitInterceptor, s.unaryAuthInterceptor),
		grpc.ChainStreamInterceptor(s.streamRateLimitInterceptor, s.streamAuthInterceptor),
	}

	if s.cfg.TLS.Enabled {
		if s.cfg.TLS.CertFile == "" || s.cfg.TLS.KeyFile == "" {
			return nil, fmt.Errorf("gRPC TLS is enabled but certificate or key file is missing")
		}
		// Build tls.Config to support optional client cert verification
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		cert, err := tls.LoadX509KeyPair(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load server TLS keypair: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
		if s.cfg.TLS.ClientAuth {
			if s.cfg.TLS.ClientCAFile == "" {
				return nil, fmt.Errorf("gRPC mTLS is enabled but client CA file is missing")
			}
			pem, err := os.ReadFile(s.cfg.TLS.ClientCAFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read client CA file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("no certificates found in gRPC client CA file")
			}
			tlsCfg.ClientCAs = pool
			tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		}
		creds := credentials.NewTLS(tlsCfg)
		grpcOpts = append(grpcOpts, grpc.Creds(creds))
	}

	s.grpc = grpc.NewServer(grpcOpts...)

	s.registerServices()
	return s, nil
}

func (s *Server) ListenAddr() string {
	return s.cfg.Listen
}

func (s *Server) Serve(ctx context.Context) error {
	defer func() {
		if s.rateLimiter != nil {
			s.rateLimiter.Close()
		}
	}()

	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	defer ln.Close()

	errCh := make(chan error, 1)

	if s.alerts != nil {
		s.alerts.Start(ctx)
		defer s.alerts.Close()
	}
	go func() {
		errCh <- s.grpc.Serve(ln)
	}()

	select {
	case <-ctx.Done():
		s.grpc.GracefulStop()
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

type ctxKey int

const sessionKey ctxKey = 1

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

func (s *Server) emitAlert(a alert.Alert) {
	if s.alerts == nil {
		return
	}
	_ = s.alerts.Emit(a)
}

func (s *Server) initRateLimiting() {
	rcfg := ratelimit.DefaultConfig()
	rcfg.Enabled = s.cfg.RateLimit.Enabled

	unauth := s.cfg.RateLimit.Unauthenticated
	if unauth.RPS == 0 {
		unauth.RPS = rcfg.Unauthenticated.RPS
	}
	if unauth.Burst == 0 {
		unauth.Burst = rcfg.Unauthenticated.Burst
	}
	perIP := s.cfg.RateLimit.PerIP
	if perIP.RPS == 0 {
		perIP.RPS = rcfg.PerIP.RPS
	}
	if perIP.Burst == 0 {
		perIP.Burst = rcfg.PerIP.Burst
	}
	perTok := s.cfg.RateLimit.PerToken
	if perTok.RPS == 0 {
		perTok.RPS = rcfg.PerToken.RPS
	}
	if perTok.Burst == 0 {
		perTok.Burst = rcfg.PerToken.Burst
	}

	rcfg.Unauthenticated = ratelimit.BucketConfig{RPS: unauth.RPS, Burst: unauth.Burst}
	rcfg.PerIP = ratelimit.BucketConfig{RPS: perIP.RPS, Burst: perIP.Burst}
	rcfg.PerToken = ratelimit.BucketConfig{RPS: perTok.RPS, Burst: perTok.Burst}

	rcfg.ExemptPaths = nil
	s.rateLimiter = ratelimit.NewStore(rcfg)

	if !rcfg.Enabled {
		return
	}

	s.rlAllowed = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ztap_api_rate_limit_allowed_total",
		Help: "Total number of API requests allowed by rate limiter",
	}, []string{"surface", "bucket"})
	s.rlLimited = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "ztap_api_rate_limit_limited_total",
		Help: "Total number of API requests rejected by rate limiter",
	}, []string{"surface", "bucket"})

	_ = prometheus.Register(s.rlAllowed)
	_ = prometheus.Register(s.rlLimited)
}

func (s *Server) isExemptMethod(fullMethod string) bool {
	switch fullMethod {
	case "/grpc.health.v1.Health/Check", "/grpc.health.v1.Health/Watch":
		return true
	}
	for _, m := range s.cfg.RateLimit.ExemptMethods {
		if m == fullMethod {
			return true
		}
		if strings.HasSuffix(m, "*") {
			prefix := strings.TrimSuffix(m, "*")
			if strings.HasPrefix(fullMethod, prefix) {
				return true
			}
		}
	}
	return false
}

func (s *Server) unaryRateLimitInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	if !s.cfg.RateLimit.Enabled {
		return handler(ctx, req)
	}
	if s.isExemptMethod(info.FullMethod) {
		return handler(ctx, req)
	}

	dec := s.decisionForGRPC(ctx)
	if dec.Allowed {
		if s.rlAllowed != nil {
			s.rlAllowed.WithLabelValues("grpc", dec.Bucket).Inc()
		}
		return handler(ctx, req)
	}

	if s.rlLimited != nil {
		s.rlLimited.WithLabelValues("grpc", dec.Bucket).Inc()
	}
	return nil, rateLimitStatus(dec)
}

func (s *Server) streamRateLimitInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if !s.cfg.RateLimit.Enabled {
		return handler(srv, ss)
	}
	if s.isExemptMethod(info.FullMethod) {
		return handler(srv, ss)
	}

	dec := s.decisionForGRPC(ss.Context())
	if dec.Allowed {
		if s.rlAllowed != nil {
			s.rlAllowed.WithLabelValues("grpc", dec.Bucket).Inc()
		}
		return handler(srv, ss)
	}

	if s.rlLimited != nil {
		s.rlLimited.WithLabelValues("grpc", dec.Bucket).Inc()
	}
	return rateLimitStatus(dec)
}

func rateLimitStatus(dec ratelimit.Decision) error {
	st := status.New(codes.ResourceExhausted, "rate limited")
	if dec.RetryAfter > 0 {
		d := dec.RetryAfter
		if d < 0 {
			d = 0
		}
		stWith, err := st.WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(d)})
		if err == nil {
			return stWith.Err()
		}
	}
	return st.Err()
}

func (s *Server) decisionForGRPC(ctx context.Context) ratelimit.Decision {
	if s.rateLimiter == nil {
		return ratelimit.Decision{Allowed: true, Bucket: "disabled"}
	}

	// Token bucket first (if auth header provided), then IP bucket.
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		vals := md.Get("authorization")
		if len(vals) > 0 {
			if tok, ok := ratelimitBearer(vals[0]); ok {
				if s.cfg.AuthEnabled {
					if _, err := s.auth.ValidateSession(tok); err != nil {
						// Invalid token -> unauthenticated bucket.
						ip := peerIP(ctx)
						d := s.rateLimiter.DecisionForKey(ratelimit.KeyUnauthenticated, "ip:"+ip)
						d.Bucket = "unauthenticated"
						return d
					}
				}

				d := s.rateLimiter.DecisionForKey(ratelimit.KeyToken, "token:"+ratelimit.HashToken(tok))
				d.Bucket = "per_token"
				if !d.Allowed {
					return d
				}

				ip := peerIP(ctx)
				d2 := s.rateLimiter.DecisionForKey(ratelimit.KeyIP, "ip:"+ip)
				d2.Bucket = "per_ip"
				return d2
			}
		}
	}

	// No token => use unauthenticated bucket.
	ip := peerIP(ctx)
	d := s.rateLimiter.DecisionForKey(ratelimit.KeyUnauthenticated, "ip:"+ip)
	d.Bucket = "unauthenticated"
	return d
}

func peerIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return "0.0.0.0"
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err == nil {
		if parsed := net.ParseIP(host); parsed != nil {
			return parsed.String()
		}
	}
	if parsed := net.ParseIP(p.Addr.String()); parsed != nil {
		return parsed.String()
	}
	return "0.0.0.0"
}

func ratelimitBearer(h string) (string, bool) {
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 {
		return "", false
	}
	if strings.ToLower(strings.TrimSpace(parts[0])) != "bearer" {
		return "", false
	}
	tok := strings.TrimSpace(parts[1])
	if tok == "" {
		return "", false
	}
	return tok, true
}

func (s *Server) unaryAuthInterceptor(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	perm, requiresAuth := permissionForMethod(info.FullMethod)
	if !requiresAuth || !s.cfg.AuthEnabled {
		return handler(ctx, req)
	}

	tok, err := bearerTokenFromMetadata(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	if err := s.auth.HasPermission(tok, perm); err != nil {
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	sess, err := s.auth.ValidateSession(tok)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	ctx = context.WithValue(ctx, sessionKey, sess)
	return handler(ctx, req)
}

func (s *Server) streamAuthInterceptor(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	perm, requiresAuth := permissionForMethod(info.FullMethod)
	if !requiresAuth || !s.cfg.AuthEnabled {
		return handler(srv, ss)
	}

	tok, err := bearerTokenFromMetadata(ss.Context())
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}
	if err := s.auth.HasPermission(tok, perm); err != nil {
		return status.Error(codes.PermissionDenied, err.Error())
	}
	sess, err := s.auth.ValidateSession(tok)
	if err != nil {
		return status.Error(codes.Unauthenticated, err.Error())
	}

	wrapped := &serverStreamWithContext{ServerStream: ss, ctx: context.WithValue(ss.Context(), sessionKey, sess)}
	return handler(srv, wrapped)
}

type serverStreamWithContext struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *serverStreamWithContext) Context() context.Context { return s.ctx }

func bearerTokenFromMetadata(ctx context.Context) (string, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", errors.New("missing request metadata")
	}
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return "", errors.New("missing authorization metadata")
	}

	h := vals[0]
	parts := strings.SplitN(h, " ", 2)
	if len(parts) != 2 {
		return "", errors.New("invalid authorization metadata")
	}
	if subtle.ConstantTimeCompare([]byte(strings.ToLower(parts[0])), []byte("bearer")) != 1 {
		return "", errors.New("invalid authorization scheme")
	}
	okTok := strings.TrimSpace(parts[1])
	if okTok == "" {
		return "", errors.New("empty bearer token")
	}
	return okTok, nil
}

func permissionForMethod(fullMethod string) (auth.Permission, bool) {
	switch fullMethod {
	case apiv1.AuthService_Login_FullMethodName:
		return "", false
	case "/grpc.health.v1.Health/Check":
		return "", false
	case "/grpc.health.v1.Health/Watch":
		return "", false
	case apiv1.AuthService_WhoAmI_FullMethodName:
		return auth.PermViewStatus, true
	case apiv1.StatusService_GetStatus_FullMethodName:
		return auth.PermViewStatus, true
	case apiv1.EnforcementService_GetStatus_FullMethodName:
		return auth.PermViewStatus, true
	case apiv1.EnforcementService_Start_FullMethodName:
		return auth.PermEnforce, true
	case apiv1.EnforcementService_Stop_FullMethodName:
		return auth.PermEnforce, true
	case apiv1.FlowsService_Stream_FullMethodName:
		return auth.PermViewStatus, true
	default:
		return "", false
	}
}

func (s *Server) registerServices() {
	apiv1.RegisterAuthServiceServer(s.grpc, &authService{srv: s})
	apiv1.RegisterStatusServiceServer(s.grpc, &statusService{srv: s})
	apiv1.RegisterEnforcementServiceServer(s.grpc, &enforcementService{srv: s})
	apiv1.RegisterFlowsServiceServer(s.grpc, &flowsService{srv: s})

	grpc_health_v1.RegisterHealthServer(s.grpc, &healthService{srv: s})
}

type healthService struct{ srv *Server }

func (h *healthService) Check(ctx context.Context, _ *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	res := h.srv.readiness.Check(ctx)
	st := grpc_health_v1.HealthCheckResponse_NOT_SERVING
	if res.Ready {
		st = grpc_health_v1.HealthCheckResponse_SERVING
	}
	return &grpc_health_v1.HealthCheckResponse{Status: st}, nil
}

func (h *healthService) Watch(_ *grpc_health_v1.HealthCheckRequest, srv grpc_health_v1.Health_WatchServer) error {
	res := h.srv.readiness.Check(srv.Context())
	st := grpc_health_v1.HealthCheckResponse_NOT_SERVING
	if res.Ready {
		st = grpc_health_v1.HealthCheckResponse_SERVING
	}
	return srv.Send(&grpc_health_v1.HealthCheckResponse{Status: st})
}

type authService struct {
	apiv1.UnimplementedAuthServiceServer
	srv *Server
}

type statusService struct {
	apiv1.UnimplementedStatusServiceServer
	srv *Server
}

type enforcementService struct {
	apiv1.UnimplementedEnforcementServiceServer
	srv *Server
}

type flowsService struct {
	apiv1.UnimplementedFlowsServiceServer
	srv *Server
}

func (a *authService) Login(ctx context.Context, req *apiv1.LoginRequest) (*apiv1.LoginResponse, error) {
	username := strings.TrimSpace(req.GetUsername())
	password := strings.TrimSpace(req.GetPassword())
	if username == "" || password == "" {
		return nil, status.Error(codes.InvalidArgument, "username and password are required")
	}

	sess, err := a.srv.auth.Authenticate(username, password)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	return &apiv1.LoginResponse{
		Token:     sess.Token,
		Username:  sess.Username,
		Role:      string(sess.Role),
		ExpiresAt: timestamppb.New(sess.ExpiresAt.UTC()),
	}, nil
}

func (a *authService) WhoAmI(ctx context.Context, _ *emptypb.Empty) (*apiv1.WhoAmIResponse, error) {
	sess, ok := sessionFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Internal, "missing session")
	}
	return &apiv1.WhoAmIResponse{
		Username:  sess.Username,
		Role:      string(sess.Role),
		ExpiresAt: timestamppb.New(sess.ExpiresAt.UTC()),
	}, nil
}

func (st *statusService) GetStatus(ctx context.Context, _ *emptypb.Empty) (*apiv1.StatusResponse, error) {
	hostname, _ := os.Hostname()
	return &apiv1.StatusResponse{
		Os:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Hostname: hostname,
		Pid:      int64(os.Getpid()),
		Uptime:   time.Since(st.srv.startTime).Truncate(time.Second).String(),
	}, nil
}

func (e *enforcementService) GetStatus(ctx context.Context, _ *emptypb.Empty) (*apiv1.EnforcementStatusResponse, error) {
	return &apiv1.EnforcementStatusResponse{
		Platform:          runtime.GOOS,
		EbpfActive:        enforcer.IsEBPFEnforcementActive(),
		FlowEventsPinPath: enforcer.DefaultFlowEventsPinPath,
	}, nil
}

func (e *enforcementService) Start(ctx context.Context, req *apiv1.EnforcementStartRequest) (*apiv1.EnforcementStartResponse, error) {
	policyYAML := strings.TrimSpace(req.GetPolicyYaml())
	policyName := strings.TrimSpace(req.GetPolicyName())
	cgroupPath := strings.TrimSpace(req.GetCgroup())
	bpfObject := strings.TrimSpace(req.GetBpfObject())
	debugEBPF := req.GetDebugEbpf()

	if policyYAML == "" {
		return nil, status.Error(codes.InvalidArgument, "policy_yaml is required")
	}
	if policyName == "" {
		policyName = "api"
	}
	policyTenant := cluster.DefaultTenant
	policyShortName := policyName
	policyKey := cluster.PolicyKey{Tenant: policyTenant, Name: policyShortName}.String()
	if parsed, err := cluster.ParsePolicyKey(policyName); err == nil {
		policyTenant = parsed.Tenant
		policyShortName = parsed.Name
		policyKey = parsed.String()
	}

	policies, err := policy.LoadFromBytes([]byte(policyYAML))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, fmt.Errorf("failed to parse policy yaml: %w", err).Error())
	}
	if len(policies) == 0 {
		return nil, status.Error(codes.InvalidArgument, "no policies found")
	}

	named := make([]policy.NamedPolicy, 0, len(policies))
	for _, p := range policies {
		if err := p.Validate(); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		named = append(named, policy.NamedPolicy{Tenant: policyTenant, PolicyName: policyShortName, Policy: p})
	}
	for i, np := range named {
		if err := policy.CheckConflicts(named[:i], np); err != nil {
			return nil, status.Error(codes.InvalidArgument, fmt.Errorf("policy conflict: %w", err).Error())
		}
	}

	platform := runtime.GOOS
	if enforcer.IsLinux() {
		platform = "linux"
		if os.Geteuid() != 0 {
			return nil, status.Error(codes.PermissionDenied, "eBPF enforcement requires root privileges")
		}

		const defaultCgroupPath = "/sys/fs/cgroup"
		var resolvedCgroupPath string
		if cgroupPath == "" {
			resolvedCgroupPath = defaultCgroupPath
		} else {
			if filepath.IsAbs(cgroupPath) {
				return nil, status.Error(codes.InvalidArgument, fmt.Errorf("invalid cgroup path %s", cgroupPath).Error())
			}
			cleaned := filepath.Clean(cgroupPath)
			if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(os.PathSeparator)) {
				return nil, status.Error(codes.InvalidArgument, fmt.Errorf("invalid cgroup path %s", cgroupPath).Error())
			}
			joined := filepath.Join(defaultCgroupPath, cleaned)
			absCgroupPath, err := filepath.Abs(joined)
			if err != nil {
				return nil, status.Error(codes.InvalidArgument, fmt.Errorf("invalid cgroup path %s", cgroupPath).Error())
			}
			rel, err := filepath.Rel(defaultCgroupPath, absCgroupPath)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				return nil, status.Error(codes.InvalidArgument, fmt.Errorf("invalid cgroup path %s", cgroupPath).Error())
			}
			resolvedCgroupPath = absCgroupPath
		}
		if _, err := os.Stat(resolvedCgroupPath); err != nil {
			return nil, status.Error(codes.InvalidArgument, fmt.Errorf("invalid cgroup path %s: %w", resolvedCgroupPath, err).Error())
		}

		bpfObjectPath := ""
		if bpfObject != "" {
			const safeBPFDir = "/usr/lib/ztap/bpf"
			cleaned := filepath.Clean(bpfObject)
			if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(os.PathSeparator)) {
				return nil, status.Error(codes.InvalidArgument, "bpf_object contains an invalid path")
			}
			baseDirAbs, err := filepath.Abs(safeBPFDir)
			if err != nil {
				return nil, status.Error(codes.Internal, fmt.Errorf("failed to resolve bpf directory: %w", err).Error())
			}
			absPath := cleaned
			if !filepath.IsAbs(cleaned) {
				absPath, err = filepath.Abs(filepath.Join(baseDirAbs, cleaned))
				if err != nil {
					return nil, status.Error(codes.InvalidArgument, fmt.Errorf("invalid bpf_object %s: %w", bpfObject, err).Error())
				}
			}
			rel, err := filepath.Rel(baseDirAbs, absPath)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				return nil, status.Error(codes.InvalidArgument, fmt.Errorf("bpf_object must be within %s", baseDirAbs).Error())
			}
			if _, err := os.Stat(absPath); err != nil {
				return nil, status.Error(codes.InvalidArgument, fmt.Errorf("invalid bpf_object %s: %w", bpfObject, err).Error())
			}
			bpfObjectPath = absPath
		}

		if err := enforcer.ValidatePoliciesForEBPF(policies); err != nil {
			return nil, status.Error(codes.InvalidArgument, fmt.Errorf("policy is not supported by eBPF enforcer yet: %w", err).Error())
		}
		opts := enforcer.EnforcementOptions{
			Policies:      policies,
			CgroupPath:    resolvedCgroupPath,
			BPFObjectPath: bpfObjectPath,
			DebugEBPF:     debugEBPF,
			Context:       ctx,
		}
		if err := enforcer.EnforceWithEBPFIfAvailable(opts); err != nil {
			e.srv.emitAlert(alert.Alert{
				Source:   "api-grpc",
				Severity: alert.SeverityError,
				Title:    "policy enforcement failed",
				Message:  err.Error(),
				DedupKey: fmt.Sprintf("%s:%s:error", policyKey, platform),
				Details:  map[string]any{"platform": platform, "count": len(policies)},
			})
			return nil, status.Error(codes.Internal, fmt.Errorf("failed to enforce via eBPF: %w", err).Error())
		}

		_ = e.srv.audit.Log(audit.EventPolicyEnforced, "system", policyKey, "enforce", map[string]any{"platform": "linux", "count": len(policies)})
		e.srv.emitAlert(alert.Alert{
			Source:   "api-grpc",
			Severity: alert.SeverityInfo,
			Title:    "policy enforced",
			Message:  fmt.Sprintf("%s enforced on %s", policyKey, platform),
			DedupKey: fmt.Sprintf("%s:%s:success", policyKey, platform),
			Details:  map[string]any{"platform": platform, "count": len(policies)},
		})
		return &apiv1.EnforcementStartResponse{Enforced: true, Platform: platform}, nil
	}

	enforcer.EnforceWithPF(enforcer.EnforcementOptions{Policies: policies, Context: ctx})
	_ = e.srv.audit.Log(audit.EventPolicyEnforced, "system", policyKey, "enforce", map[string]any{"platform": runtime.GOOS, "count": len(policies)})
	e.srv.emitAlert(alert.Alert{
		Source:   "api-grpc",
		Severity: alert.SeverityInfo,
		Title:    "policy enforced",
		Message:  fmt.Sprintf("%s enforced on %s", policyKey, platform),
		DedupKey: fmt.Sprintf("%s:%s:success", policyKey, platform),
		Details:  map[string]any{"platform": platform, "count": len(policies)},
	})
	return &apiv1.EnforcementStartResponse{Enforced: true, Platform: platform}, nil
}

func (e *enforcementService) Stop(ctx context.Context, _ *emptypb.Empty) (*apiv1.EnforcementStopResponse, error) {
	if !enforcer.IsLinux() {
		return nil, status.Error(codes.Unimplemented, "stop is only supported for eBPF enforcement on linux")
	}
	if os.Geteuid() != 0 {
		return nil, status.Error(codes.PermissionDenied, "eBPF enforcement requires root privileges")
	}
	if err := enforcer.StopEBPFEnforcement(); err != nil {
		return nil, status.Error(codes.Internal, fmt.Errorf("failed to stop eBPF enforcement: %w", err).Error())
	}
	return &apiv1.EnforcementStopResponse{Stopped: true}, nil
}

func (f *flowsService) Stream(_ *emptypb.Empty, stream apiv1.FlowsService_StreamServer) error {
	ctx := stream.Context()

	reader := f.srv.flowReader()
	monitor := flow.NewMonitor(reader)
	if err := monitor.Start(ctx); err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	defer func() { _ = monitor.Stop() }()

	eventCh := monitor.Subscribe(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-eventCh:
			if !ok {
				return nil
			}
			msg := flowEventToPB(ev)
			if err := stream.Send(msg); err != nil {
				return err
			}
		}
	}
}

func flowEventToPB(ev flow.FlowEvent) *apiv1.FlowEvent {
	return &apiv1.FlowEvent{
		Timestamp:  timestamppb.New(ev.Timestamp.UTC()),
		SourceIp:   ev.SourceIP.String(),
		DestIp:     ev.DestIP.String(),
		SourcePort: uint32(ev.SourcePort),
		DestPort:   uint32(ev.DestPort),
		Protocol:   ev.Protocol,
		Direction:  ev.Direction,
		Action:     ev.Action,
	}
}
