package cluster

import (
	"crypto/tls"
	"fmt"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// EtcdConfig holds configuration for etcd backend.
type EtcdConfig struct {
	// Endpoints is the list of etcd cluster endpoints
	Endpoints []string

	// DialTimeout is the timeout for establishing initial connection
	DialTimeout time.Duration

	// Username for etcd authentication (optional)
	Username string

	// Password for etcd authentication (optional)
	Password string

	// TLSConfig for secure connections (optional)
	TLSConfig *tls.Config

	// KeyPrefix is the namespace for all ZTAP keys in etcd
	// Default: "/ztap"
	KeyPrefix string

	// LeaderElectionKey is the key used for leader election
	// Default: "{KeyPrefix}/election"
	LeaderElectionKey string

	// SessionTTL is the time-to-live for etcd session (lease)
	// Default: 60 seconds
	SessionTTL time.Duration
}

// Validate checks if the configuration is valid.
func (c *EtcdConfig) Validate() error {
	if len(c.Endpoints) == 0 {
		return fmt.Errorf("etcd endpoints cannot be empty")
	}

	if c.DialTimeout <= 0 {
		c.DialTimeout = 5 * time.Second
	}

	if c.KeyPrefix == "" {
		c.KeyPrefix = "/ztap"
	}

	if c.LeaderElectionKey == "" {
		c.LeaderElectionKey = c.KeyPrefix + "/election"
	}

	if c.SessionTTL <= 0 {
		c.SessionTTL = 60 * time.Second
	}

	return nil
}

// NewEtcdClient creates a new etcd client from the configuration.
func (c *EtcdConfig) NewEtcdClient() (*clientv3.Client, error) {
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("invalid etcd config: %w", err)
	}

	config := clientv3.Config{
		Endpoints:   c.Endpoints,
		DialTimeout: c.DialTimeout,
		Username:    c.Username,
		Password:    c.Password,
		TLS:         c.TLSConfig,
	}

	client, err := clientv3.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create etcd client: %w", err)
	}

	return client, nil
}

// DefaultEtcdConfig returns a default configuration for local development.
func DefaultEtcdConfig() *EtcdConfig {
	return &EtcdConfig{
		Endpoints:   []string{"localhost:2379"},
		DialTimeout: 5 * time.Second,
		KeyPrefix:   "/ztap",
		SessionTTL:  60 * time.Second,
	}
}
