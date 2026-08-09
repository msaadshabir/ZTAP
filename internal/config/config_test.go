package config

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadEmptyFileUsesDefaults(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
	}{
		{name: "empty", content: ""},
		{name: "comments-only", content: "# defaults\n"},
	} {
		for _, strict := range []string{"", "1"} {
			name := tc.name + "/" + map[string]string{"": "lenient", "1": "strict"}[strict]
			t.Run(name, func(t *testing.T) {
				path := writeConfig(t, tc.content)
				t.Setenv("ZTAP_CONFIG", path)
				t.Setenv("ZTAP_CONFIG_STRICT", strict)

				cfg, err := Load("")
				if err != nil {
					t.Fatalf("Load returned error for empty config: %v", err)
				}
				if got := string(cfg.API.Listen); got != "127.0.0.1:8080" {
					t.Errorf("api.listen = %q, want default", got)
				}
			})
		}
	}
}

func TestLoadDefaultsWhenFileMissing(t *testing.T) {
	t.Setenv("ZTAP_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	t.Setenv("ZTAP_LOG_LEVEL", "") // ensure no env leakage

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if got := string(cfg.API.Listen); got != "127.0.0.1:8080" {
		t.Errorf("api.listen = %q, want 127.0.0.1:8080", got)
	}
	if !cfg.API.Auth.Enabled {
		t.Error("api.auth.enabled = false, want true")
	}
	if got := string(cfg.GRPC.Listen); got != "127.0.0.1:9092" {
		t.Errorf("grpc.listen = %q, want 127.0.0.1:9092", got)
	}
	if got := string(cfg.Logging.Level); got != "info" {
		t.Errorf("logging.level = %q, want info", got)
	}
	if got := string(cfg.Logging.Format); got != "json" {
		t.Errorf("logging.format = %q, want json", got)
	}
	if got := time.Duration(cfg.Alerting.Timeout); got != 5*time.Second {
		t.Errorf("alerting.timeout = %v, want 5s", got)
	}
	if got := time.Duration(cfg.Auth.Sessions.TTL); got != 24*time.Hour {
		t.Errorf("auth.sessions.ttl = %v, want 24h", got)
	}
	if !cfg.Metrics.Enabled || cfg.Metrics.Port != 9090 || string(cfg.Metrics.Path) != "/metrics" {
		t.Errorf("metrics defaults = %+v", cfg.Metrics)
	}
	if !cfg.Policy.Strict {
		t.Error("policy.strict = false, want true")
	}
	if got := string(cfg.Enforcement.DefaultAction); got != "block" {
		t.Errorf("enforcement.default_action = %q, want block", got)
	}
	if got := string(cfg.Anomaly.Endpoint); got != "http://localhost:5000" {
		t.Errorf("anomaly.endpoint = %q, want http://localhost:5000", got)
	}
	if !cfg.Anomaly.FailOpen || cfg.Anomaly.BatchSize != 50 || time.Duration(cfg.Anomaly.FlushInterval) != 10*time.Second {
		t.Errorf("anomaly defaults = %+v", cfg.Anomaly)
	}
	if got := string(cfg.Audit.IntegrityMode); got != "none" {
		t.Errorf("audit.integrity_mode = %q, want none", got)
	}
	if got := string(cfg.Audit.LogPath); got == "" {
		t.Error("audit.log_path default should be non-empty (~/.ztap/audit.log)")
	}
	if got := string(cfg.Auth.Sessions.SQLite.Path); got == "" {
		t.Error("auth.sessions.sqlite.path default should be non-empty (~/.ztap/sessions.db)")
	}
}

func TestLoadFromFileOverridesDefaults(t *testing.T) {
	path := writeConfig(t, `
api:
  listen: 0.0.0.0:8443
  auth:
    enabled: false
  rate_limit:
    enabled: true
    per_ip:
      rps: 50
      burst: 100
    exempt_paths: [/healthz, /readyz]
alerting:
  timeout: 30s
  dedupe_ttl: 1h
policy:
  strict: false
  allow_empty_egress: true
metrics:
  port: 9999
cluster:
  etcd:
    endpoints: ["a:2379", "b:2379"]
    dial_timeout: 3s
`)
	t.Setenv("ZTAP_CONFIG", path)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if got := string(cfg.API.Listen); got != "0.0.0.0:8443" {
		t.Errorf("api.listen = %q", got)
	}
	if cfg.API.Auth.Enabled {
		t.Error("api.auth.enabled = true, want false")
	}
	if !cfg.API.RateLimit.Enabled || cfg.API.RateLimit.PerIP.RPS != 50 || cfg.API.RateLimit.PerIP.Burst != 100 {
		t.Errorf("api.rate_limit = %+v", cfg.API.RateLimit)
	}
	if len(cfg.API.RateLimit.ExemptPaths) != 2 || cfg.API.RateLimit.ExemptPaths[0] != "/healthz" {
		t.Errorf("api.rate_limit.exempt_paths = %v", cfg.API.RateLimit.ExemptPaths)
	}
	if got := time.Duration(cfg.Alerting.Timeout); got != 30*time.Second {
		t.Errorf("alerting.timeout = %v, want 30s", got)
	}
	if got := time.Duration(cfg.Alerting.DedupeTTL); got != time.Hour {
		t.Errorf("alerting.dedupe_ttl = %v, want 1h", got)
	}
	if cfg.Policy.Strict || !cfg.Policy.AllowEmptyEgress {
		t.Errorf("policy = %+v, want strict=false allow_empty_egress=true", cfg.Policy)
	}
	if cfg.Metrics.Port != 9999 {
		t.Errorf("metrics.port = %d, want 9999", cfg.Metrics.Port)
	}
	if len(cfg.Cluster.Etcd.Endpoints) != 2 || time.Duration(cfg.Cluster.Etcd.DialTimeout) != 3*time.Second {
		t.Errorf("cluster.etcd = %+v", cfg.Cluster.Etcd)
	}
}

func TestLoadExplicitEmptyKeepsDefault(t *testing.T) {
	// Pre-centralization loaders treated an explicit empty value like an
	// absent key ("non-empty wins"); preserve that behavior.
	path := writeConfig(t, `
logging:
  level: ""
  format: ""
audit:
  log_path: ""
api:
  listen: ""
alerting:
  timeout: ""
  dedupe_ttl: ""
`)
	t.Setenv("ZTAP_CONFIG", path)

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if got := string(cfg.Logging.Level); got != "info" {
		t.Errorf("logging.level = %q, want info (default kept)", got)
	}
	if got := string(cfg.Logging.Format); got != "json" {
		t.Errorf("logging.format = %q, want json (default kept)", got)
	}
	if got := string(cfg.Audit.LogPath); got == "" {
		t.Error("audit.log_path should keep default when explicitly empty")
	}
	if got := string(cfg.API.Listen); got != "127.0.0.1:8080" {
		t.Errorf("api.listen = %q, want default kept", got)
	}
	if got := time.Duration(cfg.Alerting.Timeout); got != 5*time.Second {
		t.Errorf("alerting.timeout = %v, want 5s (default kept)", got)
	}
	if got := time.Duration(cfg.Alerting.DedupeTTL); got != 5*time.Minute {
		t.Errorf("alerting.dedupe_ttl = %v, want 5m (default kept)", got)
	}
}

func TestEnvOverridesFile(t *testing.T) {
	path := writeConfig(t, `
logging:
  level: error
aws:
  region: eu-west-1
`)
	t.Setenv("ZTAP_CONFIG", path)
	t.Setenv("ZTAP_LOG_LEVEL", "debug")
	t.Setenv("ZTAP_AWS_REGION", "ap-south-1")
	t.Setenv("ZTAP_METRICS_LISTEN", "0.0.0.0:9999")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if got := string(cfg.Logging.Level); got != "debug" {
		t.Errorf("logging.level = %q, want debug (env wins)", got)
	}
	if got := string(cfg.AWS.Region); got != "ap-south-1" {
		t.Errorf("aws.region = %q, want ap-south-1 (env wins)", got)
	}
	if got := cfg.Metrics.Listen; got != "0.0.0.0:9999" {
		t.Errorf("metrics.listen = %q, want 0.0.0.0:9999", got)
	}
}

func TestEnvAlertWebhookEnablesAlerting(t *testing.T) {
	t.Setenv("ZTAP_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	t.Setenv("ZTAP_ALERT_SLACK_WEBHOOK_URL", "https://hooks.slack.com/xyz")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if !cfg.Alerting.Enabled {
		t.Error("alerting.enabled = false, want true when webhook env is set")
	}
	if got := string(cfg.Alerting.Slack.WebhookURL); got != "https://hooks.slack.com/xyz" {
		t.Errorf("alerting.slack.webhook_url = %q", got)
	}
}

func TestLoadEnvDurationParseError(t *testing.T) {
	t.Setenv("ZTAP_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))
	t.Setenv("ZTAP_AUTH_SESSIONS_TTL", "not-a-duration")

	if _, err := Load(""); err == nil {
		t.Fatal("expected error for invalid ZTAP_AUTH_SESSIONS_TTL")
	}
}

func TestUnknownKeysWarnAndIgnore(t *testing.T) {
	path := writeConfig(t, `
api:
  listen: 127.0.0.1:8080
bogus_section:
  whatever: true
logging:
  nope: 1
`)
	t.Setenv("ZTAP_CONFIG", path)
	t.Setenv("ZTAP_CONFIG_STRICT", "")

	// Capture stderr for the warning.
	orig := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w
	defer func() { os.Stderr = orig }()
	cfg, err := Load("")
	_ = w.Close()
	stderr, _ := io.ReadAll(r)
	_ = r.Close()

	if err != nil {
		t.Fatalf("Load returned error in lenient mode: %v", err)
	}
	if !strings.Contains(string(stderr), "unknown keys") {
		t.Errorf("expected unknown-keys warning on stderr, got %q", string(stderr))
	}
	if got := string(cfg.API.Listen); got != "127.0.0.1:8080" {
		t.Errorf("api.listen = %q, want value from file", got)
	}
}

func TestStrictModeRejectsUnknownKeys(t *testing.T) {
	path := writeConfig(t, `
logging:
  level: debug
stale_section:
  key: value
`)
	t.Setenv("ZTAP_CONFIG", path)
	t.Setenv("ZTAP_CONFIG_STRICT", "1")

	if _, err := Load(""); err == nil {
		t.Fatal("expected error in strict mode with unknown key")
	}
}

func TestInvalidDurationValue(t *testing.T) {
	path := writeConfig(t, `
alerting:
  timeout: not-a-duration
`)
	t.Setenv("ZTAP_CONFIG", path)
	t.Setenv("ZTAP_CONFIG_STRICT", "")

	if _, err := Load(""); err == nil {
		t.Fatal("expected error for invalid duration value")
	}
}

func TestUnknownKeyWithTypeErrorFails(t *testing.T) {
	// An unknown key must not mask a real type error on a known key: the
	// lenient mode warns about unknown keys but still fails on bad values.
	path := writeConfig(t, `
api:
  listen: 127.0.0.1:8080
bogus_section:
  whatever: true
alerting:
  timeout: 30
`)
	t.Setenv("ZTAP_CONFIG", path)
	t.Setenv("ZTAP_CONFIG_STRICT", "")

	if _, err := Load(""); err == nil {
		t.Fatal("expected error when a known key has a bad type alongside unknown keys")
	}
}

func TestStringFieldsAreTrimmed(t *testing.T) {
	// Pre-centralization loaders applied strings.TrimSpace to every string
	// value before storing it; the typed loader must preserve that (e.g. a
	// padded webhook URL would otherwise break outbound HTTP).
	path := writeConfig(t, `
logging:
  level: " debug "
alerting:
  slack:
    webhook_url: " https://hooks.slack.com/xyz "
cluster:
  etcd:
    username: " root "
    password: " secret "
`)
	t.Setenv("ZTAP_CONFIG", path)
	t.Setenv("ZTAP_CONFIG_STRICT", "")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if got := string(cfg.Logging.Level); got != "debug" {
		t.Errorf("logging.level = %q, want debug", got)
	}
	if got := string(cfg.Alerting.Slack.WebhookURL); got != "https://hooks.slack.com/xyz" {
		t.Errorf("alerting.slack.webhook_url = %q, want trimmed", got)
	}
	if got := string(cfg.Cluster.Etcd.Username); got != "root" {
		t.Errorf("cluster.etcd.username = %q, want root", got)
	}
	if got := string(cfg.Cluster.Etcd.Password); got != "secret" {
		t.Errorf("cluster.etcd.password = %q, want secret", got)
	}
}

func TestExampleConfigRoundTrip(t *testing.T) {
	// config.yaml.example must stay in sync with the struct: every key in the
	// example must be a known field (strict mode must succeed).
	path := filepath.Join("..", "..", "config.yaml.example")
	t.Setenv("ZTAP_CONFIG", path)
	t.Setenv("ZTAP_CONFIG_STRICT", "1")
	t.Setenv("ZTAP_LOG_LEVEL", "") // example sets level explicitly; env could leak

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("example config failed strict parse: %v", err)
	}

	if got := string(cfg.Metrics.Path); got != "/metrics" {
		t.Errorf("metrics.path = %q", got)
	}
	if got := string(cfg.Enforcement.DefaultAction); got != "block" {
		t.Errorf("enforcement.default_action = %q", got)
	}
	if got := string(cfg.Anomaly.Endpoint); got != "http://localhost:5000" {
		t.Errorf("anomaly.endpoint = %q", got)
	}
}
