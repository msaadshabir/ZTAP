package cli

import (
	"fmt"
	"strings"
	"time"

	"ztap/internal/config"
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

// loadClusterRuntimeConfig derives the cluster runtime settings from the
// central config (file + ZTAP_CLUSTER_*/ZTAP_ETCD_* env overrides applied).
func loadClusterRuntimeConfig(cfg *config.Config) clusterRuntimeConfig {
	return clusterRuntimeConfig{
		Backend:           string(cfg.Cluster.Backend),
		NodeID:            string(cfg.Cluster.NodeID),
		NodeAddress:       string(cfg.Cluster.NodeAddress),
		HeartbeatInterval: time.Duration(cfg.Cluster.Election.HeartbeatInterval),
		ElectionTimeout:   time.Duration(cfg.Cluster.Election.ElectionTimeout),
		Etcd: etcdRuntimeConfig{
			Endpoints:         append([]string(nil), cfg.Cluster.Etcd.Endpoints...),
			DialTimeout:       time.Duration(cfg.Cluster.Etcd.DialTimeout),
			Username:          string(cfg.Cluster.Etcd.Username),
			Password:          string(cfg.Cluster.Etcd.Password),
			KeyPrefix:         string(cfg.Cluster.Etcd.KeyPrefix),
			LeaderElectionKey: string(cfg.Cluster.Etcd.LeaderElectionKey),
			SessionTTL:        time.Duration(cfg.Cluster.Etcd.SessionTTL),
		},
	}
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
