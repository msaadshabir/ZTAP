package apigrpc

import (
	"context"
	"crypto/subtle"
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
	"ztap/pkg/enforcer"
	"ztap/pkg/flow"
	"ztap/pkg/policy"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/structpb"
)

type Config struct {
	Listen      string
	AuthEnabled bool
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
	startTime time.Time
	alerts    *alert.Manager

	flowReader func() flow.FlowReader
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
		startTime:  time.Now(),
		alerts:     opts.Alerts,
		flowReader: opts.FlowReaderFactory,
	}

	s.grpc = grpc.NewServer(
		grpc.UnaryInterceptor(s.unaryAuthInterceptor),
		grpc.StreamInterceptor(s.streamAuthInterceptor),
	)

	s.registerServices()
	return s, nil
}

func (s *Server) ListenAddr() string {
	return s.cfg.Listen
}

func (s *Server) Serve(ctx context.Context) error {
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
	case "/ztap.api.v1.AuthService/Login":
		return "", false
	case "/ztap.api.v1.AuthService/WhoAmI":
		return auth.PermViewStatus, true
	case "/ztap.api.v1.StatusService/GetStatus":
		return auth.PermViewStatus, true
	case "/ztap.api.v1.EnforcementService/GetStatus":
		return auth.PermViewStatus, true
	case "/ztap.api.v1.EnforcementService/Start":
		return auth.PermEnforce, true
	case "/ztap.api.v1.EnforcementService/Stop":
		return auth.PermEnforce, true
	case "/ztap.api.v1.FlowsService/Stream":
		return auth.PermViewStatus, true
	default:
		return "", false
	}
}

type AuthServiceServer interface {
	Login(ctx context.Context, req *structpb.Struct) (*structpb.Struct, error)
	WhoAmI(ctx context.Context, req *emptypb.Empty) (*structpb.Struct, error)
}

type StatusServiceServer interface {
	GetStatus(ctx context.Context, req *emptypb.Empty) (*structpb.Struct, error)
}

type EnforcementServiceServer interface {
	GetStatus(ctx context.Context, req *emptypb.Empty) (*structpb.Struct, error)
	Start(ctx context.Context, req *structpb.Struct) (*structpb.Struct, error)
	Stop(ctx context.Context, req *emptypb.Empty) (*structpb.Struct, error)
}

type FlowsServiceServer interface {
	Stream(req *emptypb.Empty, stream grpc.ServerStream) error
}

func (s *Server) registerServices() {
	s.grpc.RegisterService(&authServiceDesc, &authService{srv: s})
	s.grpc.RegisterService(&statusServiceDesc, &statusService{srv: s})
	s.grpc.RegisterService(&enforcementServiceDesc, &enforcementService{srv: s})
	s.grpc.RegisterService(&flowsServiceDesc, &flowsService{srv: s})
}

type authService struct{ srv *Server }

type statusService struct{ srv *Server }

type enforcementService struct{ srv *Server }

type flowsService struct{ srv *Server }

func (a *authService) Login(ctx context.Context, req *structpb.Struct) (*structpb.Struct, error) {
	username := strings.TrimSpace(req.GetFields()["username"].GetStringValue())
	password := strings.TrimSpace(req.GetFields()["password"].GetStringValue())
	if username == "" || password == "" {
		return nil, status.Error(codes.InvalidArgument, "username and password are required")
	}

	sess, err := a.srv.auth.Authenticate(username, password)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	resp, err := structpb.NewStruct(map[string]any{
		"token":      sess.Token,
		"username":   sess.Username,
		"role":       string(sess.Role),
		"expires_at": sess.ExpiresAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return resp, nil
}

func (a *authService) WhoAmI(ctx context.Context, _ *emptypb.Empty) (*structpb.Struct, error) {
	sess, ok := sessionFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Internal, "missing session")
	}

	resp, err := structpb.NewStruct(map[string]any{
		"username":   sess.Username,
		"role":       string(sess.Role),
		"expires_at": sess.ExpiresAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return resp, nil
}

func (st *statusService) GetStatus(ctx context.Context, _ *emptypb.Empty) (*structpb.Struct, error) {
	hostname, _ := os.Hostname()
	resp, err := structpb.NewStruct(map[string]any{
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
		"hostname": hostname,
		"pid":      int64(os.Getpid()),
		"uptime":   time.Since(st.srv.startTime).Truncate(time.Second).String(),
	})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return resp, nil
}

func (e *enforcementService) GetStatus(ctx context.Context, _ *emptypb.Empty) (*structpb.Struct, error) {
	resp, err := structpb.NewStruct(map[string]any{
		"platform":             runtime.GOOS,
		"ebpf_active":          enforcer.IsEBPFEnforcementActive(),
		"flow_events_pin_path": enforcer.DefaultFlowEventsPinPath,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return resp, nil
}

func (e *enforcementService) Start(ctx context.Context, req *structpb.Struct) (*structpb.Struct, error) {
	policyYAML := strings.TrimSpace(req.GetFields()["policy_yaml"].GetStringValue())
	policyName := strings.TrimSpace(req.GetFields()["policy_name"].GetStringValue())
	cgroupPath := strings.TrimSpace(req.GetFields()["cgroup"].GetStringValue())
	bpfObject := strings.TrimSpace(req.GetFields()["bpf_object"].GetStringValue())
	debugEBPF := req.GetFields()["debug_ebpf"].GetBoolValue()

	if policyYAML == "" {
		return nil, status.Error(codes.InvalidArgument, "policy_yaml is required")
	}
	if policyName == "" {
		policyName = "api"
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
		named = append(named, policy.NamedPolicy{PolicyName: policyName, Policy: p})
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

		if bpfObject != "" {
			const safeBPFDir = "/usr/lib/ztap/bpf"
			if filepath.IsAbs(bpfObject) {
				return nil, status.Error(codes.InvalidArgument, "bpf_object must be a relative path")
			}
			cleaned := filepath.Clean(bpfObject)
			if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(os.PathSeparator)) {
				return nil, status.Error(codes.InvalidArgument, "bpf_object contains an invalid path")
			}
			baseDirAbs, err := filepath.Abs(safeBPFDir)
			if err != nil {
				return nil, status.Error(codes.Internal, fmt.Errorf("failed to resolve bpf directory: %w", err).Error())
			}
			absPath, err := filepath.Abs(filepath.Join(baseDirAbs, cleaned))
			if err != nil {
				return nil, status.Error(codes.InvalidArgument, fmt.Errorf("invalid bpf_object %s: %w", bpfObject, err).Error())
			}
			rel, err := filepath.Rel(baseDirAbs, absPath)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				return nil, status.Error(codes.InvalidArgument, fmt.Errorf("bpf_object must be within %s", baseDirAbs).Error())
			}
			if _, err := os.Stat(absPath); err != nil {
				return nil, status.Error(codes.InvalidArgument, fmt.Errorf("invalid bpf_object %s: %w", bpfObject, err).Error())
			}
			_ = os.Setenv("ZTAP_BPF_OBJECT", absPath)
		}
		if debugEBPF {
			_ = os.Setenv("ZTAP_DEBUG_EBPF", "1")
		}

		if err := enforcer.ValidatePoliciesForEBPF(policies); err != nil {
			return nil, status.Error(codes.InvalidArgument, fmt.Errorf("policy is not supported by eBPF enforcer yet: %w", err).Error())
		}
		if err := enforcer.EnforceWithEBPFIfAvailable(policies, resolvedCgroupPath); err != nil {
			e.srv.emitAlert(alert.Alert{
				Source:   "api-grpc",
				Severity: alert.SeverityError,
				Title:    "policy enforcement failed",
				Message:  err.Error(),
				DedupKey: fmt.Sprintf("%s:%s:error", policyName, platform),
				Details:  map[string]any{"platform": platform, "count": len(policies)},
			})
			return nil, status.Error(codes.Internal, fmt.Errorf("failed to enforce via eBPF: %w", err).Error())
		}

		_ = e.srv.audit.Log(audit.EventPolicyEnforced, "system", policyName, "enforce", map[string]any{"platform": "linux", "count": len(policies)})
		e.srv.emitAlert(alert.Alert{
			Source:   "api-grpc",
			Severity: alert.SeverityInfo,
			Title:    "policy enforced",
			Message:  fmt.Sprintf("%s enforced on %s", policyName, platform),
			DedupKey: fmt.Sprintf("%s:%s:success", policyName, platform),
			Details:  map[string]any{"platform": platform, "count": len(policies)},
		})
		resp, err := structpb.NewStruct(map[string]any{"enforced": true, "platform": platform})
		if err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
		return resp, nil
	}

	enforcer.EnforceWithPF(policies)
	_ = e.srv.audit.Log(audit.EventPolicyEnforced, "system", policyName, "enforce", map[string]any{"platform": runtime.GOOS, "count": len(policies)})
	e.srv.emitAlert(alert.Alert{
		Source:   "api-grpc",
		Severity: alert.SeverityInfo,
		Title:    "policy enforced",
		Message:  fmt.Sprintf("%s enforced on %s", policyName, platform),
		DedupKey: fmt.Sprintf("%s:%s:success", policyName, platform),
		Details:  map[string]any{"platform": platform, "count": len(policies)},
	})
	resp, err := structpb.NewStruct(map[string]any{"enforced": true, "platform": platform})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return resp, nil
}

func (e *enforcementService) Stop(ctx context.Context, _ *emptypb.Empty) (*structpb.Struct, error) {
	if !enforcer.IsLinux() {
		return nil, status.Error(codes.Unimplemented, "stop is only supported for eBPF enforcement on linux")
	}
	if os.Geteuid() != 0 {
		return nil, status.Error(codes.PermissionDenied, "eBPF enforcement requires root privileges")
	}
	if err := enforcer.StopEBPFEnforcement(); err != nil {
		return nil, status.Error(codes.Internal, fmt.Errorf("failed to stop eBPF enforcement: %w", err).Error())
	}
	resp, err := structpb.NewStruct(map[string]any{"stopped": true})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return resp, nil
}

func (f *flowsService) Stream(_ *emptypb.Empty, stream grpc.ServerStream) error {
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
			msg, err := flowEventToStruct(ev)
			if err != nil {
				continue
			}
			if err := stream.SendMsg(msg); err != nil {
				return err
			}
		}
	}
}

func flowEventToStruct(ev flow.FlowEvent) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{
		"timestamp":   ev.Timestamp.UTC().Format(time.RFC3339Nano),
		"source_ip":   ev.SourceIP.String(),
		"dest_ip":     ev.DestIP.String(),
		"source_port": int64(ev.SourcePort),
		"dest_port":   int64(ev.DestPort),
		"protocol":    ev.Protocol,
		"direction":   ev.Direction,
		"action":      ev.Action,
	})
}

var authServiceDesc = grpc.ServiceDesc{
	ServiceName: "ztap.api.v1.AuthService",
	HandlerType: (*AuthServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "Login", Handler: authServiceLoginHandler},
		{MethodName: "WhoAmI", Handler: authServiceWhoAmIHandler},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/ztap/api/v1/api.proto",
}

var statusServiceDesc = grpc.ServiceDesc{
	ServiceName: "ztap.api.v1.StatusService",
	HandlerType: (*StatusServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "GetStatus", Handler: statusServiceGetStatusHandler},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/ztap/api/v1/api.proto",
}

var enforcementServiceDesc = grpc.ServiceDesc{
	ServiceName: "ztap.api.v1.EnforcementService",
	HandlerType: (*EnforcementServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{MethodName: "GetStatus", Handler: enforcementServiceGetStatusHandler},
		{MethodName: "Start", Handler: enforcementServiceStartHandler},
		{MethodName: "Stop", Handler: enforcementServiceStopHandler},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/ztap/api/v1/api.proto",
}

var flowsServiceDesc = grpc.ServiceDesc{
	ServiceName: "ztap.api.v1.FlowsService",
	HandlerType: (*FlowsServiceServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{StreamName: "Stream", Handler: flowsServiceStreamHandler, ServerStreams: true},
	},
	Metadata: "proto/ztap/api/v1/api.proto",
}

func authServiceLoginHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(structpb.Struct)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).Login(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/ztap.api.v1.AuthService/Login"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(AuthServiceServer).Login(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, in, info, handler)
}

func authServiceWhoAmIHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServiceServer).WhoAmI(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/ztap.api.v1.AuthService/WhoAmI"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(AuthServiceServer).WhoAmI(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func statusServiceGetStatusHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(StatusServiceServer).GetStatus(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/ztap.api.v1.StatusService/GetStatus"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(StatusServiceServer).GetStatus(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func enforcementServiceGetStatusHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EnforcementServiceServer).GetStatus(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/ztap.api.v1.EnforcementService/GetStatus"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(EnforcementServiceServer).GetStatus(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func enforcementServiceStartHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(structpb.Struct)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EnforcementServiceServer).Start(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/ztap.api.v1.EnforcementService/Start"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(EnforcementServiceServer).Start(ctx, req.(*structpb.Struct))
	}
	return interceptor(ctx, in, info, handler)
}

func enforcementServiceStopHandler(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	in := new(emptypb.Empty)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(EnforcementServiceServer).Stop(ctx, in)
	}
	info := &grpc.UnaryServerInfo{Server: srv, FullMethod: "/ztap.api.v1.EnforcementService/Stop"}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(EnforcementServiceServer).Stop(ctx, req.(*emptypb.Empty))
	}
	return interceptor(ctx, in, info, handler)
}

func flowsServiceStreamHandler(srv any, stream grpc.ServerStream) error {
	in := new(emptypb.Empty)
	if err := stream.RecvMsg(in); err != nil {
		return err
	}
	return srv.(FlowsServiceServer).Stream(in, stream)
}
