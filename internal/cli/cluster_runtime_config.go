package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	yaml "gopkg.in/yaml.v3"
)

const (
	clusterBackendMemory = "memory"
	clusterBackendEtcd   = "etcd"
)

type clusterRuntimeConfig struct {
	Backend           string
	NodeID            string
	NodeAddress       string
	HeartbeatInterval time.Duration
	ElectionTimeout   time.Duration
	Etcd              etcdRuntimeConfig
}

type etcdRuntimeConfig struct {
	Endpoints         []string
	DialTimeout       time.Duration
	Username          string
	Password          string
	KeyPrefix         string
	LeaderElectionKey string
	SessionTTL        time.Duration
}

type clusterConfigFile struct {
	Cluster struct {
		Backend     string `yaml:"backend"`
		NodeID      string `yaml:"node_id"`
		NodeAddress string `yaml:"node_address"`
		Election    struct {
			HeartbeatInterval string `yaml:"heartbeat_interval"`
			ElectionTimeout   string `yaml:"election_timeout"`
		} `yaml:"election"`
		Etcd struct {
			Endpoints         []string `yaml:"endpoints"`
			DialTimeout       string   `yaml:"dial_timeout"`
			Username          string   `yaml:"username"`
			Password          string   `yaml:"password"`
			KeyPrefix         string   `yaml:"key_prefix"`
			LeaderElectionKey string   `yaml:"leader_election_key"`
			SessionTTL        string   `yaml:"session_ttl"`
		} `yaml:"etcd"`
	} `yaml:"cluster"`
}

func loadClusterRuntimeConfig() (clusterRuntimeConfig, error) {
	path := os.Getenv("ZTAP_CONFIG")
	if path == "" {
		path = "config.yaml"
	}

	cfg := clusterRuntimeConfig{}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return applyClusterRuntimeEnv(cfg)
		}
		return clusterRuntimeConfig{}, fmt.Errorf("reading config file %s: %w", path, err)
	}

	var fileCfg clusterConfigFile
	if err := yaml.Unmarshal(data, &fileCfg); err != nil {
		return clusterRuntimeConfig{}, fmt.Errorf("parsing config file %s: %w", path, err)
	}

	if v := strings.TrimSpace(fileCfg.Cluster.Backend); v != "" {
		cfg.Backend = v
	}
	if v := strings.TrimSpace(fileCfg.Cluster.NodeID); v != "" {
		cfg.NodeID = v
	}
	if v := strings.TrimSpace(fileCfg.Cluster.NodeAddress); v != "" {
		cfg.NodeAddress = v
	}
	if v := strings.TrimSpace(fileCfg.Cluster.Election.HeartbeatInterval); v != "" {
		parsed, err := parseDurationField(v, "cluster.election.heartbeat_interval")
		if err != nil {
			return clusterRuntimeConfig{}, err
		}
		cfg.HeartbeatInterval = parsed
	}
	if v := strings.TrimSpace(fileCfg.Cluster.Election.ElectionTimeout); v != "" {
		parsed, err := parseDurationField(v, "cluster.election.election_timeout")
		if err != nil {
			return clusterRuntimeConfig{}, err
		}
		cfg.ElectionTimeout = parsed
	}

	cfg.Etcd.Endpoints = normalizeEndpoints(fileCfg.Cluster.Etcd.Endpoints)
	if v := strings.TrimSpace(fileCfg.Cluster.Etcd.DialTimeout); v != "" {
		parsed, err := parseDurationField(v, "cluster.etcd.dial_timeout")
		if err != nil {
			return clusterRuntimeConfig{}, err
		}
		cfg.Etcd.DialTimeout = parsed
	}
	if v := strings.TrimSpace(fileCfg.Cluster.Etcd.Username); v != "" {
		cfg.Etcd.Username = v
	}
	if v := strings.TrimSpace(fileCfg.Cluster.Etcd.Password); v != "" {
		cfg.Etcd.Password = v
	}
	if v := strings.TrimSpace(fileCfg.Cluster.Etcd.KeyPrefix); v != "" {
		cfg.Etcd.KeyPrefix = v
	}
	if v := strings.TrimSpace(fileCfg.Cluster.Etcd.LeaderElectionKey); v != "" {
		cfg.Etcd.LeaderElectionKey = v
	}
	if v := strings.TrimSpace(fileCfg.Cluster.Etcd.SessionTTL); v != "" {
		parsed, err := parseDurationField(v, "cluster.etcd.session_ttl")
		if err != nil {
			return clusterRuntimeConfig{}, err
		}
		cfg.Etcd.SessionTTL = parsed
	}

	return applyClusterRuntimeEnv(cfg)
}

func applyClusterRuntimeEnv(cfg clusterRuntimeConfig) (clusterRuntimeConfig, error) {
	if v := strings.TrimSpace(os.Getenv("ZTAP_CLUSTER_BACKEND")); v != "" {
		cfg.Backend = v
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_NODE_ID")); v != "" {
		cfg.NodeID = v
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_NODE_ADDRESS")); v != "" {
		cfg.NodeAddress = v
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_CLUSTER_HEARTBEAT_INTERVAL")); v != "" {
		parsed, err := parseDurationField(v, "ZTAP_CLUSTER_HEARTBEAT_INTERVAL")
		if err != nil {
			return clusterRuntimeConfig{}, err
		}
		cfg.HeartbeatInterval = parsed
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_CLUSTER_ELECTION_TIMEOUT")); v != "" {
		parsed, err := parseDurationField(v, "ZTAP_CLUSTER_ELECTION_TIMEOUT")
		if err != nil {
			return clusterRuntimeConfig{}, err
		}
		cfg.ElectionTimeout = parsed
	}

	if v := strings.TrimSpace(os.Getenv("ZTAP_ETCD_ENDPOINTS")); v != "" {
		cfg.Etcd.Endpoints = splitCommaSeparated(v)
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_ETCD_DIAL_TIMEOUT")); v != "" {
		parsed, err := parseDurationField(v, "ZTAP_ETCD_DIAL_TIMEOUT")
		if err != nil {
			return clusterRuntimeConfig{}, err
		}
		cfg.Etcd.DialTimeout = parsed
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_ETCD_USERNAME")); v != "" {
		cfg.Etcd.Username = v
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_ETCD_PASSWORD")); v != "" {
		cfg.Etcd.Password = v
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_ETCD_KEY_PREFIX")); v != "" {
		cfg.Etcd.KeyPrefix = v
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_ETCD_LEADER_ELECTION_KEY")); v != "" {
		cfg.Etcd.LeaderElectionKey = v
	}
	if v := strings.TrimSpace(os.Getenv("ZTAP_ETCD_SESSION_TTL")); v != "" {
		parsed, err := parseDurationField(v, "ZTAP_ETCD_SESSION_TTL")
		if err != nil {
			return clusterRuntimeConfig{}, err
		}
		cfg.Etcd.SessionTTL = parsed
	}

	return cfg, nil
}

func resolveClusterBackend(cfg clusterRuntimeConfig) (string, error) {
	backend := normalizeClusterBackend(cfg.Backend)
	if backend == "" {
		if len(cfg.Etcd.Endpoints) > 0 {
			return clusterBackendEtcd, nil
		}
		return clusterBackendMemory, nil
	}
	if backend == clusterBackendEtcd || backend == clusterBackendMemory {
		return backend, nil
	}
	return "", fmt.Errorf("unsupported cluster backend: %s", backend)
}

func normalizeClusterBackend(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "inmemory", "in-memory":
		return clusterBackendMemory
	default:
		return value
	}
}

func parseDurationField(value, field string) (time.Duration, error) {
	parsed, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("parsing %s: %w", field, err)
	}
	return parsed, nil
}

func splitCommaSeparated(value string) []string {
	return normalizeEndpoints(strings.FieldsFunc(value, func(r rune) bool {
		return r == ','
	}))
}

func normalizeEndpoints(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if v := strings.TrimSpace(item); v != "" {
			out = append(out, v)
		}
	}
	return out
}
