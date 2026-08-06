package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"ztap/internal/logging"
	"ztap/internal/policy"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// EtcdPolicySync stores policy state and revisions in etcd.
// It is intended for production clusters alongside EtcdElection.
type EtcdPolicySync struct {
	client etcdPolicySyncClient
	config *EtcdConfig
	nodeID string
}

type etcdPolicySyncClient interface {
	Get(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.GetResponse, error)
	Put(ctx context.Context, key, val string, opts ...clientv3.OpOption) (*clientv3.PutResponse, error)
	Delete(ctx context.Context, key string, opts ...clientv3.OpOption) (*clientv3.DeleteResponse, error)
	Watch(ctx context.Context, key string, opts ...clientv3.OpOption) clientv3.WatchChan
	Txn(ctx context.Context) clientv3.Txn
	Close() error
}

// NewEtcdPolicySync creates a new etcd-backed policy sync.
func NewEtcdPolicySync(config *EtcdConfig, nodeID string) (*EtcdPolicySync, error) {
	if config == nil {
		return nil, errors.New("etcd config cannot be nil")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	client, err := config.NewEtcdClient()
	if err != nil {
		return nil, err
	}
	return &EtcdPolicySync{client: client, config: config, nodeID: nodeID}, nil
}

// NewEtcdPolicySyncWithClient creates a new etcd-backed policy sync with an injected client.
// This is intended for unit tests with in-memory fakes.
func NewEtcdPolicySyncWithClient(config *EtcdConfig, nodeID string, client etcdPolicySyncClient) (*EtcdPolicySync, error) {
	if config == nil {
		return nil, errors.New("etcd config cannot be nil")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("etcd client cannot be nil")
	}
	return &EtcdPolicySync{client: client, config: config, nodeID: nodeID}, nil
}

// Start is a no-op for EtcdPolicySync (client created on init).
func (ps *EtcdPolicySync) Start(ctx context.Context) error {
	_ = ctx
	return nil
}

// Stop closes the etcd client.
func (ps *EtcdPolicySync) Stop() error {
	if ps.client == nil {
		return nil
	}
	return ps.client.Close()
}

// SyncPolicy broadcasts a policy update to the cluster (leader-only enforced by caller).
func (ps *EtcdPolicySync) SyncPolicy(ctx context.Context, policyName string, policyYAML []byte) error {
	if ps.client == nil {
		return errors.New("etcd client not initialized")
	}
	_, err := ps.applyPolicy(ctx, policyName, policyYAML, nil, "", false)
	return err
}

// UpsertPolicy creates a new revision with an optional reason.
func (ps *EtcdPolicySync) UpsertPolicy(ctx context.Context, policyName string, policyYAML []byte, reason string) (*PolicyRevision, error) {
	return ps.applyPolicy(ctx, policyName, policyYAML, nil, reason, false)
}

// DeletePolicy creates a tombstone revision and removes current state.
func (ps *EtcdPolicySync) DeletePolicy(ctx context.Context, policyName string, reason string) (*PolicyRevision, error) {
	if strings.TrimSpace(policyName) == "" {
		return nil, errors.New("policy name cannot be empty")
	}
	key, err := ParsePolicyKey(policyName)
	if err != nil {
		return nil, fmt.Errorf("invalid policy name %q: %w", policyName, err)
	}
	key = key.Normalized()
	stateKey := ps.stateKey(key)
	resp, err := ps.client.Get(ctx, stateKey)
	if err != nil {
		return nil, err
	}
	if len(resp.Kvs) == 0 {
		return nil, ErrPolicyNotFound
	}
	return ps.applyPolicy(ctx, key.String(), nil, nil, reason, true)
}

// GetPolicyVersion returns the current version or 0 if missing.
func (ps *EtcdPolicySync) GetPolicyVersion(policyName string) (int64, error) {
	if strings.TrimSpace(policyName) == "" {
		return 0, errors.New("policy name cannot be empty")
	}
	key, err := ParsePolicyKey(policyName)
	if err != nil {
		return 0, fmt.Errorf("invalid policy name %q: %w", policyName, err)
	}
	key = key.Normalized()
	resp, err := ps.client.Get(context.Background(), ps.stateKey(key))
	if err != nil {
		return 0, err
	}
	if len(resp.Kvs) == 0 {
		return 0, nil
	}
	var state PolicyState
	if err := json.Unmarshal(resp.Kvs[0].Value, &state); err != nil {
		return 0, err
	}
	return state.Version, nil
}

// SubscribePolicies watches policy updates using etcd watch and returns a channel of updates.
func (ps *EtcdPolicySync) SubscribePolicies(ctx context.Context) <-chan PolicyUpdate {
	ch := make(chan PolicyUpdate, 100)
	prefix := ps.watchPrefix()
	watch := ps.client.Watch(ctx, prefix, clientv3.WithPrefix())
	go func() {
		defer close(ch)
		for resp := range watch {
			for _, ev := range resp.Events {
				if ev.Type != clientv3.EventTypePut {
					continue
				}
				var update PolicyUpdate
				if err := json.Unmarshal(ev.Kv.Value, &update); err != nil {
					continue
				}
				select {
				case ch <- update:
				case <-ctx.Done():
					return
				default:
					logging.Warnf("policy update channel full, dropping event for policy %s", sanitizeForLog(update.PolicyKeyString()))
				}
			}
		}
	}()
	return ch
}

// ListPolicies returns current policy states.
func (ps *EtcdPolicySync) ListPolicies() []*PolicyState {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := ps.client.Get(ctx, ps.statesPrefix(), clientv3.WithPrefix())
	if err != nil {
		return []*PolicyState{}
	}
	out := make([]*PolicyState, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		var state PolicyState
		if err := json.Unmarshal(kv.Value, &state); err != nil {
			continue
		}
		copy := state
		copy.YAML = append([]byte(nil), state.YAML...)
		out = append(out, &copy)
	}
	return out
}

// GetPolicy returns the current policy state.
func (ps *EtcdPolicySync) GetPolicy(policyName string) (*PolicyState, error) {
	if strings.TrimSpace(policyName) == "" {
		return nil, errors.New("policy name cannot be empty")
	}
	key, err := ParsePolicyKey(policyName)
	if err != nil {
		return nil, fmt.Errorf("invalid policy name %q: %w", policyName, err)
	}
	key = key.Normalized()
	resp, err := ps.client.Get(context.Background(), ps.stateKey(key))
	if err != nil {
		return nil, err
	}
	if len(resp.Kvs) == 0 {
		return nil, nil
	}
	var state PolicyState
	if err := json.Unmarshal(resp.Kvs[0].Value, &state); err != nil {
		return nil, err
	}
	state.YAML = append([]byte(nil), state.YAML...)
	return &state, nil
}

// ListPolicyRevisions returns revisions in descending order.
func (ps *EtcdPolicySync) ListPolicyRevisions(policyName string, limit int) ([]PolicyRevision, error) {
	if strings.TrimSpace(policyName) == "" {
		return nil, errors.New("policy name cannot be empty")
	}
	key, err := ParsePolicyKey(policyName)
	if err != nil {
		return nil, fmt.Errorf("invalid policy name %q: %w", policyName, err)
	}
	key = key.Normalized()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := ps.client.Get(ctx, ps.revisionsPrefix(key), clientv3.WithPrefix(), clientv3.WithSort(clientv3.SortByKey, clientv3.SortDescend))
	if err != nil {
		return nil, err
	}
	out := make([]PolicyRevision, 0, len(resp.Kvs))
	for _, kv := range resp.Kvs {
		var rev PolicyRevision
		if err := json.Unmarshal(kv.Value, &rev); err != nil {
			continue
		}
		rev.YAML = append([]byte(nil), rev.YAML...)
		rev.RollbackFromVersion = copyRollbackVersion(rev.RollbackFromVersion)
		out = append(out, rev)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

// GetPolicyRevision fetches a specific revision.
func (ps *EtcdPolicySync) GetPolicyRevision(policyName string, version int64) (*PolicyRevision, error) {
	if strings.TrimSpace(policyName) == "" {
		return nil, errors.New("policy name cannot be empty")
	}
	if version <= 0 {
		return nil, errors.New("version must be positive")
	}
	key, err := ParsePolicyKey(policyName)
	if err != nil {
		return nil, fmt.Errorf("invalid policy name %q: %w", policyName, err)
	}
	key = key.Normalized()
	resp, err := ps.client.Get(context.Background(), ps.revisionKey(key, version))
	if err != nil {
		return nil, err
	}
	if len(resp.Kvs) == 0 {
		return nil, nil
	}
	var rev PolicyRevision
	if err := json.Unmarshal(resp.Kvs[0].Value, &rev); err != nil {
		return nil, err
	}
	rev.YAML = append([]byte(nil), rev.YAML...)
	rev.RollbackFromVersion = copyRollbackVersion(rev.RollbackFromVersion)
	return &rev, nil
}

// RollbackPolicy creates a new revision from a prior version.
func (ps *EtcdPolicySync) RollbackPolicy(ctx context.Context, policyName string, targetVersion int64, reason string) (*PolicyRevision, error) {
	if strings.TrimSpace(policyName) == "" {
		return nil, errors.New("policy name cannot be empty")
	}
	if targetVersion <= 0 {
		return nil, errors.New("target version must be positive")
	}
	key, err := ParsePolicyKey(policyName)
	if err != nil {
		return nil, fmt.Errorf("invalid policy name %q: %w", policyName, err)
	}
	key = key.Normalized()
	rev, err := ps.GetPolicyRevision(policyName, targetVersion)
	if err != nil {
		return nil, err
	}
	if rev == nil {
		return nil, fmt.Errorf("policy %s version %d not found", policyName, targetVersion)
	}
	rollbackFrom := rev.Version
	return ps.applyPolicy(ctx, key.String(), rev.YAML, &rollbackFrom, reason, false)
}

func (ps *EtcdPolicySync) applyPolicy(ctx context.Context, policyName string, policyYAML []byte, rollbackFrom *int64, reason string, deleted bool) (*PolicyRevision, error) {
	startTime := time.Now()
	if strings.TrimSpace(policyName) == "" {
		recordPolicySyncError("empty_name", "")
		return nil, errors.New("policy name cannot be empty")
	}
	key, err := ParsePolicyKey(policyName)
	if err != nil {
		recordPolicySyncError("invalid_name", policyName)
		return nil, fmt.Errorf("invalid policy name %q: %w", policyName, err)
	}
	key = key.Normalized()
	policyKeyLabel := key.String()
	if !deleted {
		if len(policyYAML) == 0 {
			recordPolicySyncError("empty_yaml", policyKeyLabel)
			return nil, errors.New("policy YAML cannot be empty")
		}
		if _, err := parseAndValidateEtcdPolicy(key, policyYAML); err != nil {
			recordPolicySyncError("invalid_policy", policyKeyLabel)
			return nil, err
		}
	}

	stateKey := ps.stateKey(key)
	resp, err := ps.client.Get(ctx, stateKey)
	if err != nil {
		return nil, err
	}
	var current PolicyState
	if len(resp.Kvs) > 0 {
		if err := json.Unmarshal(resp.Kvs[0].Value, &current); err != nil {
			return nil, err
		}
	}
	if len(resp.Kvs) == 0 && deleted {
		recordPolicySyncError("not_found", policyKeyLabel)
		return nil, ErrPolicyNotFound
	}

	newVersion := int64(1)
	if len(resp.Kvs) > 0 {
		newVersion = current.Version + 1
	}

	timestamp := time.Now().UTC()
	rollbackPtr := copyRollbackVersion(rollbackFrom)
	revision := PolicyRevision{
		Tenant:              key.Tenant,
		PolicyName:          key.Name,
		Version:             newVersion,
		YAML:                append([]byte(nil), policyYAML...),
		Source:              ps.nodeID,
		Timestamp:           timestamp,
		Reason:              reason,
		Deleted:             deleted,
		RollbackFromVersion: rollbackPtr,
	}

	update := PolicyUpdate{
		Tenant:     key.Tenant,
		PolicyName: key.Name,
		YAML:       policyYAML,
		Version:    newVersion,
		Source:     ps.nodeID,
		Timestamp:  timestamp,
		Deleted:    deleted,
	}

	revKey := ps.revisionKey(key, newVersion)
	updateKey := ps.updateKey(key, newVersion)

	revBytes, err := json.Marshal(revision)
	if err != nil {
		return nil, err
	}
	updateBytes, err := json.Marshal(update)
	if err != nil {
		return nil, err
	}

	if deleted {
		_, err = ps.client.Txn(ctx).
			Then(
				clientv3.OpDelete(stateKey),
				clientv3.OpPut(revKey, string(revBytes)),
				clientv3.OpPut(updateKey, string(updateBytes)),
			).
			Commit()
		if err != nil {
			return nil, err
		}
	} else {
		state := PolicyState{
			Tenant:    key.Tenant,
			Name:      key.Name,
			YAML:      policyYAML,
			Version:   newVersion,
			Source:    ps.nodeID,
			Timestamp: timestamp,
			Deleted:   false,
		}
		stateBytes, err := json.Marshal(state)
		if err != nil {
			return nil, err
		}
		_, err = ps.client.Txn(ctx).
			Then(
				clientv3.OpPut(stateKey, string(stateBytes)),
				clientv3.OpPut(revKey, string(revBytes)),
				clientv3.OpPut(updateKey, string(updateBytes)),
			).
			Commit()
		if err != nil {
			return nil, err
		}
	}

	duration := time.Since(startTime).Seconds()
	recordPolicySynced(policyKeyLabel, newVersion)
	policySyncDuration.WithLabelValues(policyKeyLabel).Observe(duration)

	if deleted {
		logging.Infof("Policy %s deleted from cluster (version %d) by leader %s", sanitizeForLog(key.Name), newVersion, sanitizeForLog(ps.nodeID))
	} else {
		logging.Infof("Policy %s synced to cluster (version %d) by leader %s", sanitizeForLog(key.Name), newVersion, sanitizeForLog(ps.nodeID))
	}
	return &revision, nil
}

func (ps *EtcdPolicySync) statesPrefix() string {
	return ps.config.KeyPrefix + "/policies/state/"
}

func (ps *EtcdPolicySync) revisionsPrefix(key PolicyKey) string {
	key = key.Normalized()
	return fmt.Sprintf("%s/policies/revisions/%s/%s/", ps.config.KeyPrefix, key.Tenant, key.Name)
}

func (ps *EtcdPolicySync) revisionKey(key PolicyKey, version int64) string {
	key = key.Normalized()
	return fmt.Sprintf("%s/policies/revisions/%s/%s/%020d", ps.config.KeyPrefix, key.Tenant, key.Name, version)
}

func (ps *EtcdPolicySync) stateKey(key PolicyKey) string {
	key = key.Normalized()
	return fmt.Sprintf("%s/policies/state/%s/%s", ps.config.KeyPrefix, key.Tenant, key.Name)
}

func (ps *EtcdPolicySync) watchPrefix() string {
	return ps.config.KeyPrefix + "/policies/updates/"
}

func (ps *EtcdPolicySync) updateKey(key PolicyKey, version int64) string {
	key = key.Normalized()
	return fmt.Sprintf("%s/policies/updates/%s/%s/%020d", ps.config.KeyPrefix, key.Tenant, key.Name, version)
}

func parseAndValidateEtcdPolicy(key PolicyKey, policyYAML []byte) ([]policy.NetworkPolicy, error) {
	policies, err := policy.LoadFromBytes(policyYAML)
	if err != nil {
		return nil, err
	}
	if len(policies) == 0 {
		return nil, errors.New("policy YAML contains no NetworkPolicy objects")
	}
	for _, p := range policies {
		if err := p.Validate(); err != nil {
			return nil, err
		}
	}
	_ = key
	return policies, nil
}

// Ensure EtcdPolicySync implements the required interfaces.
var _ PolicyManager = (*EtcdPolicySync)(nil)
var _ PolicySync = (*EtcdPolicySync)(nil)
var _ PolicyRevisionStore = (*EtcdPolicySync)(nil)
var _ interface{ Start(context.Context) error } = (*EtcdPolicySync)(nil)
var _ interface{ Stop() error } = (*EtcdPolicySync)(nil)
