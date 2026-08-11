// Package config is the single typed representation of config.yaml.
//
// Every ZTAP command loads configuration through this package exactly once;
// the ad-hoc per-command YAML parsers that existed before are gone. Precedence
// is flag > env (ZTAP_*) > file > default.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	yaml "gopkg.in/yaml.v3"
)

// Config mirrors config.yaml.example. All sections are optional; absent keys
// keep the defaults populated by Load.
type Config struct {
	API         API         `yaml:"api"`
	GRPC        GRPC        `yaml:"grpc"`
	Auth        Auth        `yaml:"auth"`
	Cluster     Cluster     `yaml:"cluster"`
	Discovery   Discovery   `yaml:"discovery"`
	Logging     Logging     `yaml:"logging"`
	Alerting    Alerting    `yaml:"alerting"`
	AWS         AWS         `yaml:"aws"`
	Azure       Azure       `yaml:"azure"`
	GCP         GCP         `yaml:"gcp"`
	Audit       Audit       `yaml:"audit"`
	Metrics     Metrics     `yaml:"metrics"`
	Enforcement Enforcement `yaml:"enforcement"`
	Policy      Policy      `yaml:"policy"`
	Anomaly     Anomaly     `yaml:"anomaly"`
}

// API is the REST API server section.
type API struct {
	Listen    String       `yaml:"listen"`
	Auth      APIAuth      `yaml:"auth"`
	TLS       TLS          `yaml:"tls"`
	RateLimit APIRateLimit `yaml:"rate_limit"`
}

// APIAuth is the auth sub-section shared by the api and grpc sections.
type APIAuth struct {
	Enabled bool `yaml:"enabled"`
}

// TLS is the TLS sub-section shared by the api and grpc sections.
type TLS struct {
	Enabled      bool   `yaml:"enabled"`
	CertFile     string `yaml:"cert_file"`
	KeyFile      string `yaml:"key_file"`
	ClientAuth   bool   `yaml:"client_auth"`
	ClientCAFile string `yaml:"client_ca_file"`
}

// RateLimitBucket is a per-scope rate limit (rps + burst).
type RateLimitBucket struct {
	RPS   float64 `yaml:"rps"`
	Burst int     `yaml:"burst"`
}

// APIRateLimit is the REST API rate limiting sub-section.
type APIRateLimit struct {
	Enabled           bool            `yaml:"enabled"`
	TrustProxyHeaders bool            `yaml:"trust_proxy_headers"`
	Unauthenticated   RateLimitBucket `yaml:"unauthenticated"`
	PerIP             RateLimitBucket `yaml:"per_ip"`
	PerToken          RateLimitBucket `yaml:"per_token"`
	ExemptPaths       []string        `yaml:"exempt_paths"`
}

// GRPC is the gRPC API server section.
type GRPC struct {
	Listen    String        `yaml:"listen"`
	Auth      APIAuth       `yaml:"auth"`
	TLS       TLS           `yaml:"tls"`
	RateLimit GRPCRateLimit `yaml:"rate_limit"`
}

// GRPCRateLimit is the gRPC rate limiting sub-section.
type GRPCRateLimit struct {
	Enabled         bool            `yaml:"enabled"`
	Unauthenticated RateLimitBucket `yaml:"unauthenticated"`
	PerIP           RateLimitBucket `yaml:"per_ip"`
	PerToken        RateLimitBucket `yaml:"per_token"`
	ExemptMethods   []string        `yaml:"exempt_methods"`
}

// Auth is the authentication section.
type Auth struct {
	Sessions AuthSessions `yaml:"sessions"`
}

// AuthSessions is the auth.sessions sub-section.
type AuthSessions struct {
	Backend String             `yaml:"backend"`
	TTL     Duration           `yaml:"ttl"`
	SQLite  AuthSessionsSQLite `yaml:"sqlite"`
}

// AuthSessionsSQLite is the auth.sessions.sqlite sub-section.
type AuthSessionsSQLite struct {
	Path String `yaml:"path"`
}

// Cluster is the cluster coordination section (policy sync + leader election).
type Cluster struct {
	Backend     String          `yaml:"backend"`
	NodeID      String          `yaml:"node_id"`
	NodeAddress String          `yaml:"node_address"`
	Election    ClusterElection `yaml:"election"`
	Etcd        Etcd            `yaml:"etcd"`
}

// ClusterElection is the cluster.election sub-section.
type ClusterElection struct {
	HeartbeatInterval Duration `yaml:"heartbeat_interval"`
	ElectionTimeout   Duration `yaml:"election_timeout"`
}

// Etcd is the cluster.etcd sub-section.
type Etcd struct {
	Endpoints         []string `yaml:"endpoints"`
	DialTimeout       Duration `yaml:"dial_timeout"`
	Username          String   `yaml:"username"`
	Password          String   `yaml:"password"`
	KeyPrefix         String   `yaml:"key_prefix"`
	LeaderElectionKey String   `yaml:"leader_election_key"`
	SessionTTL        Duration `yaml:"session_ttl"`
}

// Discovery is the service discovery section.
type Discovery struct {
	Backend String         `yaml:"backend"`
	DNS     DiscoveryDNS   `yaml:"dns"`
	K8s     DiscoveryK8s   `yaml:"k8s"`
	Cache   DiscoveryCache `yaml:"cache"`
}

// DiscoveryDNS is the discovery.dns sub-section.
type DiscoveryDNS struct {
	Domain String `yaml:"domain"`
}

// DiscoveryK8s is the discovery.k8s sub-section.
type DiscoveryK8s struct {
	Namespace  String `yaml:"namespace"`
	Kubeconfig String `yaml:"kubeconfig"`
}

// DiscoveryCache is the discovery.cache sub-section.
type DiscoveryCache struct {
	TTL Duration `yaml:"ttl"`
}

// Logging is the logging section.
type Logging struct {
	Level  String `yaml:"level"`
	File   string `yaml:"file"`
	Format String `yaml:"format"`
}

// Alerting is the alerting section.
type Alerting struct {
	Enabled   bool      `yaml:"enabled"`
	QueueSize int       `yaml:"queue_size"`
	Workers   int       `yaml:"workers"`
	Timeout   Duration  `yaml:"timeout"`
	DedupeTTL Duration  `yaml:"dedupe_ttl"`
	Slack     Slack     `yaml:"slack"`
	PagerDuty PagerDuty `yaml:"pagerduty"`
}

// Slack is the alerting.slack sub-section.
type Slack struct {
	WebhookURL String `yaml:"webhook_url"`
}

// PagerDuty is the alerting.pagerduty sub-section.
type PagerDuty struct {
	RoutingKey String `yaml:"routing_key"`
	Source     String `yaml:"source"`
}

// AWS is the AWS cloud integration section.
type AWS struct {
	Enabled         bool   `yaml:"enabled"`
	Region          String `yaml:"region"`
	Profile         String `yaml:"profile"`
	SecurityGroupID String `yaml:"security_group_id"`
}

// Azure is the Azure cloud integration section.
type Azure struct {
	Enabled        bool   `yaml:"enabled"`
	SubscriptionID String `yaml:"subscription_id"`
	ResourceGroup  String `yaml:"resource_group"`
	NSG            String `yaml:"nsg"`
	RulePrefix     String `yaml:"rule_prefix"`
	PriorityBase   int32  `yaml:"priority_base"`
}

// GCP is the GCP cloud integration section.
type GCP struct {
	Enabled      bool   `yaml:"enabled"`
	ProjectID    String `yaml:"project_id"`
	Network      String `yaml:"network"`
	RulePrefix   String `yaml:"rule_prefix"`
	PriorityBase int32  `yaml:"priority_base"`
}

// Audit is the audit logging section.
type Audit struct {
	LogPath            String   `yaml:"log_path"`
	IntegrityMode      String   `yaml:"integrity_mode"`
	KeyID              String   `yaml:"key_id"`
	HMACKeyFile        String   `yaml:"hmac_key_file"`
	Ed25519PrivateKey  String   `yaml:"ed25519_private_key_file"`
	CheckpointPath     String   `yaml:"checkpoint_path"`
	CheckpointInterval Duration `yaml:"checkpoint_interval"`
}

// Metrics is the metrics server section.
type Metrics struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Path    String `yaml:"path"`
	// Listen overrides the bind address (host:port). Only set via the
	// ZTAP_METRICS_LISTEN environment variable.
	Listen string `yaml:"-"`
}

// Enforcement is the enforcement section.
type Enforcement struct {
	// DryRun defaults `ztap enforce --dry-run`.
	DryRun bool `yaml:"dry_run"`
	// DefaultAction (block or allow) defaults `ztap enforce --default-action`.
	DefaultAction String `yaml:"default_action"`
}

// Policy is the policy validation section.
type Policy struct {
	Strict           bool `yaml:"strict"`
	AllowEmptyEgress bool `yaml:"allow_empty_egress"`
	ResolveLabels    bool `yaml:"resolve_labels"`
}

// Anomaly is the anomaly detection section (consumed by the agent pipeline).
type Anomaly struct {
	Enabled       bool     `yaml:"enabled"`
	Endpoint      String   `yaml:"endpoint"`
	Threshold     float64  `yaml:"threshold"`
	AlertEmail    String   `yaml:"alert_email"`
	BatchSize     int      `yaml:"batch_size"`
	FlushInterval Duration `yaml:"flush_interval"`
	AuthToken     String   `yaml:"auth_token"`
	FailOpen      bool     `yaml:"fail_open"`
}

// Load resolves the config file path (ZTAP_CONFIG env > path > ./config.yaml),
// parses it with defaults pre-populated, applies ZTAP_* environment overrides,
// and returns the merged configuration.
//
// Unknown keys are ignored with a warning on stderr; set ZTAP_CONFIG_STRICT=1
// to fail on unknown keys instead.
func Load(path string) (*Config, error) {
	if env := strings.TrimSpace(os.Getenv("ZTAP_CONFIG")); env != "" {
		path = env
	}
	if strings.TrimSpace(path) == "" {
		path = "config.yaml"
	}

	cfg := defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if err := applyEnvOverrides(cfg); err != nil {
				return nil, err
			}
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	if err := decode(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %s: %w", path, err)
	}
	if err := applyEnvOverrides(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// decode parses data into cfg. In default (non-strict) mode, a strict probe
// decode detects unknown keys for a warning while the lenient decode still
// applies every known key; with ZTAP_CONFIG_STRICT=1 unknown keys are fatal.
func decode(data []byte, cfg *Config) error {
	strict := strings.TrimSpace(os.Getenv("ZTAP_CONFIG_STRICT")) == "1"

	if strict {
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		return nil
	}

	// Probe: strict decode into a scratch copy so type errors on known keys
	// surface as real errors, while unknown keys only produce a warning.
	probe := defaults()
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(probe); err != nil && !errors.Is(err, io.EOF) {
		var typeErr *yaml.TypeError
		if !errors.As(err, &typeErr) {
			// Syntax errors and the like are not TypeError; fail loudly.
			return err
		}
		// yaml.v3 reports every problem as one TypeError entry, e.g.
		// "line 3: field bogus not found in type config.Config". Split
		// unknown-field entries (warn) from real type errors (fail).
		var unknown []string
		var realErrs []string
		for _, entry := range typeErr.Errors {
			if strings.Contains(entry, "not found in type") {
				unknown = append(unknown, entry)
			} else {
				realErrs = append(realErrs, entry)
			}
		}
		if len(realErrs) > 0 {
			return errors.New(strings.Join(realErrs, "; "))
		}
		_, _ = fmt.Fprintf(os.Stderr,
			"ztap: warning: config contains unknown keys (set ZTAP_CONFIG_STRICT=1 to fail on them): %s\n",
			strings.Join(unknown, "; "))
	}

	return yaml.Unmarshal(data, cfg)
}

// defaults returns a Config populated with the documented defaults. Behavior
// without any config file must remain identical to the pre-centralization
// loaders, so defaults mirror what those loaders returned for a missing file.
func defaults() *Config {
	home, _ := os.UserHomeDir()
	sessionsDB := ""
	auditLog := ""
	if home != "" {
		sessionsDB = filepath.Join(home, ".ztap", "sessions.db")
		auditLog = filepath.Join(home, ".ztap", "audit.log")
	}

	return &Config{
		API: API{
			Listen: "127.0.0.1:8080",
			Auth:   APIAuth{Enabled: true},
		},
		GRPC: GRPC{
			Listen: "127.0.0.1:9092",
			Auth:   APIAuth{Enabled: true},
		},
		Auth: Auth{
			Sessions: AuthSessions{
				Backend: "sqlite",
				TTL:     Duration(24 * time.Hour),
				SQLite:  AuthSessionsSQLite{Path: String(sessionsDB)},
			},
		},
		Logging: Logging{
			Level:  "info",
			Format: "json",
		},
		Alerting: Alerting{
			QueueSize: 128,
			Workers:   2,
			Timeout:   Duration(5 * time.Second),
			DedupeTTL: Duration(5 * time.Minute),
			PagerDuty: PagerDuty{Source: "ztap"},
		},
		Metrics: Metrics{
			Enabled: true,
			Port:    9090,
			Path:    "/metrics",
		},
		Audit: Audit{
			LogPath:       String(auditLog),
			IntegrityMode: "none",
		},
		Enforcement: Enforcement{
			DefaultAction: "block",
		},
		Policy: Policy{
			Strict: true,
		},
		Anomaly: Anomaly{
			Endpoint:      "http://localhost:5000",
			Threshold:     50.0,
			BatchSize:     50,
			FlushInterval: Duration(10 * time.Second),
			FailOpen:      true,
		},
	}
}

// applyEnvOverrides applies ZTAP_* environment overrides on top of the file
// values (env > file > default).
func applyEnvOverrides(cfg *Config) error {
	// Logging.
	if v := strings.TrimSpace(os.Getenv("ZTAP_LOG_LEVEL")); v != "" {
		cfg.Logging.Level = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_LOG_FORMAT")); v != "" {
		cfg.Logging.Format = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_LOG_FILE")); v != "" {
		cfg.Logging.File = v
	}

	// Alerting.
	if v := strings.TrimSpace(os.Getenv("ZTAP_ALERT_ENABLED")); v != "" {
		parsed, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("parsing ZTAP_ALERT_ENABLED: %w", err)
		}
		cfg.Alerting.Enabled = parsed
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_ALERT_SLACK_WEBHOOK_URL")); v != "" {
		cfg.Alerting.Slack.WebhookURL = String(v)
		cfg.Alerting.Enabled = true
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_ALERT_PAGERDUTY_ROUTING_KEY")); v != "" {
		cfg.Alerting.PagerDuty.RoutingKey = String(v)
		cfg.Alerting.Enabled = true
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_ALERT_PAGERDUTY_SOURCE")); v != "" {
		cfg.Alerting.PagerDuty.Source = String(v)
	}

	// Auth sessions.
	if v := strings.TrimSpace(os.Getenv("ZTAP_AUTH_SESSIONS_BACKEND")); v != "" {
		cfg.Auth.Sessions.Backend = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_AUTH_SESSIONS_TTL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("parsing ZTAP_AUTH_SESSIONS_TTL: %w", err)
		}
		cfg.Auth.Sessions.TTL = Duration(d)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_AUTH_SESSIONS_SQLITE_PATH")); v != "" {
		cfg.Auth.Sessions.SQLite.Path = String(v)
	}

	// Cluster.
	if v := strings.TrimSpace(os.Getenv("ZTAP_CLUSTER_BACKEND")); v != "" {
		cfg.Cluster.Backend = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_NODE_ID")); v != "" {
		cfg.Cluster.NodeID = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_NODE_ADDRESS")); v != "" {
		cfg.Cluster.NodeAddress = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_CLUSTER_HEARTBEAT_INTERVAL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("parsing ZTAP_CLUSTER_HEARTBEAT_INTERVAL: %w", err)
		}
		cfg.Cluster.Election.HeartbeatInterval = Duration(d)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_CLUSTER_ELECTION_TIMEOUT")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("parsing ZTAP_CLUSTER_ELECTION_TIMEOUT: %w", err)
		}
		cfg.Cluster.Election.ElectionTimeout = Duration(d)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_ETCD_ENDPOINTS")); v != "" {
		cfg.Cluster.Etcd.Endpoints = splitCommaSeparated(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_ETCD_DIAL_TIMEOUT")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("parsing ZTAP_ETCD_DIAL_TIMEOUT: %w", err)
		}
		cfg.Cluster.Etcd.DialTimeout = Duration(d)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_ETCD_USERNAME")); v != "" {
		cfg.Cluster.Etcd.Username = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_ETCD_PASSWORD")); v != "" {
		cfg.Cluster.Etcd.Password = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_ETCD_KEY_PREFIX")); v != "" {
		cfg.Cluster.Etcd.KeyPrefix = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_ETCD_LEADER_ELECTION_KEY")); v != "" {
		cfg.Cluster.Etcd.LeaderElectionKey = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_ETCD_SESSION_TTL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("parsing ZTAP_ETCD_SESSION_TTL: %w", err)
		}
		cfg.Cluster.Etcd.SessionTTL = Duration(d)
	}

	// AWS.
	if v := strings.TrimSpace(os.Getenv("ZTAP_AWS_REGION")); v != "" {
		cfg.AWS.Region = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_AWS_PROFILE")); v != "" {
		cfg.AWS.Profile = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_AWS_SECURITY_GROUP_ID")); v != "" {
		cfg.AWS.SecurityGroupID = String(v)
	}

	// Azure.
	if v := strings.TrimSpace(os.Getenv("ZTAP_AZURE_SUBSCRIPTION_ID")); v != "" {
		cfg.Azure.SubscriptionID = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_AZURE_RESOURCE_GROUP")); v != "" {
		cfg.Azure.ResourceGroup = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_AZURE_NSG")); v != "" {
		cfg.Azure.NSG = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_AZURE_RULE_PREFIX")); v != "" {
		cfg.Azure.RulePrefix = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_AZURE_PRIORITY_BASE")); v != "" {
		parsed, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return fmt.Errorf("parsing ZTAP_AZURE_PRIORITY_BASE: %w", err)
		}
		cfg.Azure.PriorityBase = int32(parsed)
	}

	// GCP.
	if v := strings.TrimSpace(os.Getenv("ZTAP_GCP_PROJECT_ID")); v != "" {
		cfg.GCP.ProjectID = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_GCP_NETWORK")); v != "" {
		cfg.GCP.Network = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_GCP_RULE_PREFIX")); v != "" {
		cfg.GCP.RulePrefix = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_GCP_PRIORITY_BASE")); v != "" {
		parsed, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return fmt.Errorf("parsing ZTAP_GCP_PRIORITY_BASE: %w", err)
		}
		cfg.GCP.PriorityBase = int32(parsed)
	}

	// Audit.
	if v := strings.TrimSpace(os.Getenv("ZTAP_AUDIT_LOG_PATH")); v != "" {
		cfg.Audit.LogPath = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_AUDIT_INTEGRITY_MODE")); v != "" {
		cfg.Audit.IntegrityMode = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_AUDIT_KEY_ID")); v != "" {
		cfg.Audit.KeyID = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_AUDIT_HMAC_KEY_FILE")); v != "" {
		cfg.Audit.HMACKeyFile = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_AUDIT_ED25519_PRIVATE_KEY_FILE")); v != "" {
		cfg.Audit.Ed25519PrivateKey = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_AUDIT_CHECKPOINT_PATH")); v != "" {
		cfg.Audit.CheckpointPath = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_AUDIT_CHECKPOINT_INTERVAL")); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("parsing ZTAP_AUDIT_CHECKPOINT_INTERVAL: %w", err)
		}
		cfg.Audit.CheckpointInterval = Duration(d)
	}

	// Anomaly detection.
	if v := strings.TrimSpace(os.Getenv("ZTAP_ANOMALY_ENDPOINT")); v != "" {
		cfg.Anomaly.Endpoint = String(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_ANOMALY_AUTH_TOKEN")); v != "" {
		cfg.Anomaly.AuthToken = String(v)
	}

	// Metrics.
	if v := strings.TrimSpace(os.Getenv("ZTAP_METRICS_LISTEN")); v != "" {
		cfg.Metrics.Listen = v
	}

	return nil
}

func splitCommaSeparated(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == ',' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// Duration is a time.Duration that marshals to/from a Go duration string
// (e.g. "5s", "24h"). An explicitly empty value keeps the current (default)
// value, matching the pre-centralization loaders.
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		if value.Kind == yaml.ScalarNode {
			s = value.Value
		} else {
			return fmt.Errorf("invalid duration value: %w", err)
		}
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return nil // keep the current value (e.g. a default)
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (d Duration) MarshalYAML() (any, error) {
	if d == 0 {
		return "", nil
	}
	return time.Duration(d).String(), nil
}

// String is a string field that keeps its current (default) value when the
// YAML document sets it to an empty string, matching the pre-centralization
// loaders' "non-empty wins" semantics. Values are stored trimmed, as the old
// ad-hoc loaders did (they applied strings.TrimSpace before assigning).
type String string

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *String) UnmarshalYAML(value *yaml.Node) error {
	var v string
	if err := value.Decode(&v); err != nil {
		if value.Kind == yaml.ScalarNode {
			v = value.Value
		} else {
			return fmt.Errorf("invalid string value: %w", err)
		}
	}
	v = strings.TrimSpace(v)
	if v == "" && *s != "" {
		return nil // keep the current value (e.g. a default)
	}
	*s = String(v)
	return nil
}

// MarshalYAML implements yaml.Marshaler.
func (s String) MarshalYAML() (any, error) { return string(s), nil }
