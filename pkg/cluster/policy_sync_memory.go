package cluster

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"ztap/pkg/logging"
	"ztap/pkg/policy"
)

// InMemoryPolicySync implements distributed policy synchronization using in-memory storage.
// It is NOT suitable for production distributed deployments; use etcd or Raft for production.
type InMemoryPolicySync struct {
	mu          sync.RWMutex
	policies    map[PolicyKey]*PolicyState // (tenant,name) -> PolicyState
	revisions   map[PolicyKey][]PolicyRevision
	subscribers []chan PolicyUpdate // Channels for policy update notifications
	election    LeaderElection      // Cluster coordination backend
	nodeID      string              // This node's identifier
	running     bool
	stopCh      chan struct{}
}

// PolicyState holds the state of a single policy in the cluster.
type PolicyState struct {
	Tenant    string    // Tenant scope (defaults to "default")
	Name      string    // Policy name
	YAML      []byte    // Policy YAML content
	Version   int64     // Monotonically increasing version number
	Source    string    // Node ID that last updated this policy
	Timestamp time.Time // Last update timestamp
}

// NewInMemoryPolicySync creates a new in-memory policy synchronization backend.
// It requires an active LeaderElection instance for cluster coordination.
func NewInMemoryPolicySync(election LeaderElection, nodeID string) *InMemoryPolicySync {
	return &InMemoryPolicySync{
		policies:    make(map[PolicyKey]*PolicyState),
		revisions:   make(map[PolicyKey][]PolicyRevision),
		subscribers: make([]chan PolicyUpdate, 0),
		election:    election,
		nodeID:      nodeID,
		stopCh:      make(chan struct{}),
	}
}

// Start begins the policy synchronization process.
// It watches for cluster state changes and coordinates policy updates.
func (ps *InMemoryPolicySync) Start(ctx context.Context) error {
	ps.mu.Lock()
	if ps.running {
		ps.mu.Unlock()
		return fmt.Errorf("policy sync already running")
	}
	ps.running = true
	ps.mu.Unlock()

	safeNodeID := strings.ReplaceAll(ps.nodeID, "\n", "")
	safeNodeID = strings.ReplaceAll(safeNodeID, "\r", "")
	logging.Infof("Policy synchronization started for node %s", safeNodeID)

	// Watch for cluster state changes to handle node joins/leaves
	go ps.watchClusterChanges(ctx)

	return nil
}

// Stop gracefully shuts down the policy synchronization.
func (ps *InMemoryPolicySync) Stop() error {
	ps.mu.Lock()
	if !ps.running {
		ps.mu.Unlock()
		return fmt.Errorf("policy sync not running")
	}
	ps.running = false

	close(ps.stopCh)

	// Close all subscriber channels
	for _, ch := range ps.subscribers {
		close(ch)
	}
	ps.subscribers = make([]chan PolicyUpdate, 0)
	ps.mu.Unlock()

	return nil
}

// SyncPolicy broadcasts a policy update to all nodes in the cluster.
// Only the leader can initiate policy updates; followers will return an error.
func (ps *InMemoryPolicySync) SyncPolicy(ctx context.Context, policyName string, policyYAML []byte) error {
	_, err := ps.applyPolicy(ctx, policyName, policyYAML, nil, "")
	return err
}

func (ps *InMemoryPolicySync) applyPolicy(ctx context.Context, policyName string, policyYAML []byte, rollbackFrom *int64, reason string) (*PolicyRevision, error) {
	startTime := time.Now()
	if strings.TrimSpace(policyName) == "" {
		recordPolicySyncError("empty_name", "")
		return nil, fmt.Errorf("policy name cannot be empty")
	}

	key, err := ParsePolicyKey(policyName)
	if err != nil {
		recordPolicySyncError("invalid_name", policyName)
		return nil, fmt.Errorf("invalid policy name %q: %w", policyName, err)
	}
	key = key.Normalized()
	policyKeyLabel := key.String()

	policyName = key.Name
	if len(policyYAML) == 0 {
		recordPolicySyncError("empty_yaml", policyKeyLabel)
		return nil, fmt.Errorf("policy YAML cannot be empty")
	}

	if _, err := ps.parseAndValidate(key, policyYAML); err != nil {
		recordPolicySyncError("invalid_policy", policyKeyLabel)
		return nil, err
	}

	if !ps.election.IsLeader() {
		leader := ps.election.GetLeader()
		if leader == nil {
			recordPolicySyncError("no_leader", policyKeyLabel)
			return nil, fmt.Errorf("no leader elected; cannot sync policy")
		}
		recordPolicySyncError("not_leader", policyKeyLabel)
		return nil, fmt.Errorf("only leader can sync policies; current leader is %s", leader.ID)
	}

	ps.mu.Lock()
	defer ps.mu.Unlock()

	newVersion := int64(1)
	if existingPolicy, exists := ps.policies[key]; exists {
		newVersion = existingPolicy.Version + 1
	}

	timestamp := time.Now()
	policyState := &PolicyState{
		Tenant:    key.Tenant,
		Name:      policyName,
		YAML:      policyYAML,
		Version:   newVersion,
		Source:    ps.nodeID,
		Timestamp: timestamp,
	}
	ps.policies[key] = policyState

	rollbackPtr := copyRollbackVersion(rollbackFrom)
	revision := PolicyRevision{
		Tenant:              key.Tenant,
		PolicyName:          policyName,
		Version:             newVersion,
		YAML:                append([]byte(nil), policyYAML...),
		Source:              ps.nodeID,
		Timestamp:           timestamp,
		Reason:              reason,
		RollbackFromVersion: rollbackPtr,
	}
	ps.revisions[key] = append(ps.revisions[key], revision)

	update := PolicyUpdate{
		Tenant:     key.Tenant,
		PolicyName: policyName,
		YAML:       policyYAML,
		Version:    newVersion,
		Source:     ps.nodeID,
		Timestamp:  policyState.Timestamp,
	}

	ps.broadcastUpdate(update)

	duration := time.Since(startTime).Seconds()
	policySyncDuration.WithLabelValues(policyKeyLabel).Observe(duration)
	recordPolicySynced(policyKeyLabel, newVersion)

	safePolicyName := strings.ReplaceAll(policyName, "\n", "")
	safePolicyName = strings.ReplaceAll(safePolicyName, "\r", "")
	safeNodeID := strings.ReplaceAll(ps.nodeID, "\n", "")
	safeNodeID = strings.ReplaceAll(safeNodeID, "\r", "")
	logging.Infof("Policy %s synced to cluster (version %d) by leader %s", safePolicyName, newVersion, safeNodeID)

	return &revision, nil
}

// GetPolicyVersion returns the current version of a policy across the cluster.
// Returns 0 if the policy doesn't exist.
func (ps *InMemoryPolicySync) GetPolicyVersion(policyName string) (int64, error) {
	if strings.TrimSpace(policyName) == "" {
		return 0, fmt.Errorf("policy name cannot be empty")
	}
	key, err := ParsePolicyKey(policyName)
	if err != nil {
		return 0, fmt.Errorf("invalid policy name %q: %w", policyName, err)
	}
	key = key.Normalized()

	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if policyState, exists := ps.policies[key]; exists {
		return policyState.Version, nil
	}

	return 0, nil // Policy doesn't exist yet
}

// GetPolicy returns the full policy state for a given policy name.
// Returns nil if the policy doesn't exist.
func (ps *InMemoryPolicySync) GetPolicy(policyName string) (*PolicyState, error) {
	if strings.TrimSpace(policyName) == "" {
		return nil, fmt.Errorf("policy name cannot be empty")
	}
	key, err := ParsePolicyKey(policyName)
	if err != nil {
		return nil, fmt.Errorf("invalid policy name %q: %w", policyName, err)
	}
	key = key.Normalized()

	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if policyState, exists := ps.policies[key]; exists {
		// Return a copy to prevent external modifications
		return &PolicyState{
			Tenant:    policyState.Tenant,
			Name:      policyState.Name,
			YAML:      append([]byte(nil), policyState.YAML...),
			Version:   policyState.Version,
			Source:    policyState.Source,
			Timestamp: policyState.Timestamp,
		}, nil
	}

	return nil, nil // Policy doesn't exist
}

// ListPolicies returns all policies currently stored in the cluster.
func (ps *InMemoryPolicySync) ListPolicies() []*PolicyState {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	policies := make([]*PolicyState, 0, len(ps.policies))
	for _, policyState := range ps.policies {
		// Return copies to prevent external modifications
		policies = append(policies, &PolicyState{
			Tenant:    policyState.Tenant,
			Name:      policyState.Name,
			YAML:      append([]byte(nil), policyState.YAML...),
			Version:   policyState.Version,
			Source:    policyState.Source,
			Timestamp: policyState.Timestamp,
		})
	}

	return policies
}

// SubscribePolicies returns a channel for policy update notifications.
// The channel is closed when the context is cancelled or when Stop() is called.
func (ps *InMemoryPolicySync) SubscribePolicies(ctx context.Context) <-chan PolicyUpdate {
	ch := make(chan PolicyUpdate, 10)

	// Increment subscriber count
	incrementPolicySubscribers()

	go func() {
		<-ctx.Done()
		ps.mu.Lock()
		// Remove this channel from subscribers
		for i, subscriber := range ps.subscribers {
			if subscriber == ch {
				ps.subscribers = append(ps.subscribers[:i], ps.subscribers[i+1:]...)
				break
			}
		}
		ps.mu.Unlock()

		// Decrement subscriber count
		decrementPolicySubscribers()

		// Close channel after removal to avoid double-close
		select {
		case <-ch:
			// Channel already closed
		default:
			close(ch)
		}
	}()

	ps.mu.Lock()
	ps.subscribers = append(ps.subscribers, ch)
	ps.mu.Unlock()

	return ch
}

// watchClusterChanges monitors cluster state for leader changes and node events.
func (ps *InMemoryPolicySync) watchClusterChanges(ctx context.Context) {
	leaderChanges := ps.election.LeaderChanges(ctx)

	for {
		select {
		case <-ps.stopCh:
			return
		case <-ctx.Done():
			return
		case leader := <-leaderChanges:
			if leader != nil {
				safeLeaderID := strings.ReplaceAll(leader.ID, "\n", "")
				safeLeaderID = strings.ReplaceAll(safeLeaderID, "\r", "")
				logging.Infof("Leader changed to %s; policy sync adapting", safeLeaderID)
				// In a real distributed system, we would:
				// 1. If we're the new leader: start accepting policy sync requests
				// 2. If we're a follower: fetch latest policies from new leader
				// For this in-memory implementation, policies are already shared
			}
		}
	}
}

// broadcastUpdate sends a policy update to all subscribers (requires holding mu lock).
func (ps *InMemoryPolicySync) broadcastUpdate(update PolicyUpdate) {
	for _, ch := range ps.subscribers {
		select {
		case ch <- update:
		default:
			safePolicyKey := strings.ReplaceAll(update.PolicyKeyString(), "\n", "")
			safePolicyKey = strings.ReplaceAll(safePolicyKey, "\r", "")
			logging.Warnf("policy update channel full, dropping event for policy %s", safePolicyKey)
		}
	}
}

// ApplyRemoteUpdate applies a policy update received from another node.
// This is used in distributed scenarios where followers receive updates from the leader.
// It does NOT require the caller to be the leader.
func (ps *InMemoryPolicySync) ApplyRemoteUpdate(ctx context.Context, update PolicyUpdate) error {
	if update.PolicyName == "" {
		return fmt.Errorf("policy name cannot be empty")
	}
	if len(update.YAML) == 0 {
		return fmt.Errorf("policy YAML cannot be empty")
	}

	key := PolicyKey{Tenant: update.Tenant, Name: update.PolicyName}.Normalized()
	if strings.Contains(update.PolicyName, "/") && strings.TrimSpace(update.Tenant) == "" {
		if parsed, err := ParsePolicyKey(update.PolicyName); err == nil {
			key = parsed.Normalized()
		}
	}

	if _, err := ps.parseAndValidate(key, update.YAML); err != nil {
		return err
	}
	policyKeyLabel := key.String()

	ps.mu.Lock()
	defer ps.mu.Unlock()

	// Check if we already have this version or newer
	if existingPolicy, exists := ps.policies[key]; exists {
		if existingPolicy.Version >= update.Version {
			safePolicyName := strings.ReplaceAll(update.PolicyName, "\n", "")
			safePolicyName = strings.ReplaceAll(safePolicyName, "\r", "")
			logging.Debugf("Skipping policy %s update (existing version %d >= received version %d)",
				safePolicyName, existingPolicy.Version, update.Version)

			return nil
		}
	}

	// Store the updated policy state
	policyState := &PolicyState{
		Tenant:    key.Tenant,
		Name:      key.Name,
		YAML:      update.YAML,
		Version:   update.Version,
		Source:    update.Source,
		Timestamp: update.Timestamp,
	}
	ps.policies[key] = policyState
	revision := PolicyRevision{
		Tenant:     key.Tenant,
		PolicyName: key.Name,
		Version:    update.Version,
		YAML:       append([]byte(nil), update.YAML...),
		Source:     update.Source,
		Timestamp:  update.Timestamp,
	}
	ps.revisions[key] = append(ps.revisions[key], revision)

	// Broadcast to local subscribers
	ps.broadcastUpdate(update)

	safeSource := strings.ReplaceAll(update.Source, "\n", "")
	safeSource = strings.ReplaceAll(safeSource, "\r", "")
	logging.Infof("Applied remote policy update for %s (version %d) from %s",
		strings.ReplaceAll(strings.ReplaceAll(policyKeyLabel, "\n", ""), "\r", ""), update.Version, safeSource)

	return nil
}

// ListPolicyRevisions returns policy revisions in descending version order.
func (ps *InMemoryPolicySync) ListPolicyRevisions(policyName string, limit int) ([]PolicyRevision, error) {
	if strings.TrimSpace(policyName) == "" {
		return nil, fmt.Errorf("policy name cannot be empty")
	}
	key, err := ParsePolicyKey(policyName)
	if err != nil {
		return nil, fmt.Errorf("invalid policy name %q: %w", policyName, err)
	}
	key = key.Normalized()

	ps.mu.RLock()
	revs := ps.revisions[key]
	ps.mu.RUnlock()

	if len(revs) == 0 {
		return []PolicyRevision{}, nil
	}

	if limit > 0 && limit < len(revs) {
		revs = revs[len(revs)-limit:]
	}

	result := make([]PolicyRevision, 0, len(revs))
	for i := len(revs) - 1; i >= 0; i-- {
		result = append(result, copyPolicyRevision(revs[i]))
	}

	return result, nil
}

// GetPolicyRevision fetches a specific revision by version.
func (ps *InMemoryPolicySync) GetPolicyRevision(policyName string, version int64) (*PolicyRevision, error) {
	if strings.TrimSpace(policyName) == "" {
		return nil, fmt.Errorf("policy name cannot be empty")
	}
	if version <= 0 {
		return nil, fmt.Errorf("version must be positive")
	}
	key, err := ParsePolicyKey(policyName)
	if err != nil {
		return nil, fmt.Errorf("invalid policy name %q: %w", policyName, err)
	}
	key = key.Normalized()

	ps.mu.RLock()
	revs := ps.revisions[key]
	ps.mu.RUnlock()

	for _, rev := range revs {
		if rev.Version == version {
			copy := copyPolicyRevision(rev)
			return &copy, nil
		}
	}

	return nil, nil
}

// RollbackPolicy creates a new revision using the YAML from a previous version.
func (ps *InMemoryPolicySync) RollbackPolicy(ctx context.Context, policyName string, targetVersion int64, reason string) (*PolicyRevision, error) {
	if strings.TrimSpace(policyName) == "" {
		return nil, fmt.Errorf("policy name cannot be empty")
	}
	if targetVersion <= 0 {
		return nil, fmt.Errorf("target version must be positive")
	}
	key, err := ParsePolicyKey(policyName)
	if err != nil {
		return nil, fmt.Errorf("invalid policy name %q: %w", policyName, err)
	}
	key = key.Normalized()

	revision, err := ps.GetPolicyRevision(policyName, targetVersion)
	if err != nil {
		return nil, err
	}
	if revision == nil {
		return nil, fmt.Errorf("policy %s version %d not found", policyName, targetVersion)
	}

	rollbackFrom := revision.Version

	return ps.applyPolicy(ctx, key.String(), revision.YAML, &rollbackFrom, reason)
}

func (ps *InMemoryPolicySync) parseAndValidate(key PolicyKey, policyYAML []byte) ([]policy.NetworkPolicy, error) {
	policies, err := policy.LoadFromBytes(policyYAML)
	if err != nil {
		return nil, err
	}
	if len(policies) == 0 {
		return nil, fmt.Errorf("policy YAML contains no NetworkPolicy objects")
	}

	for _, p := range policies {
		if err := p.Validate(); err != nil {
			return nil, err
		}
	}

	existing, err := ps.currentPolicies()
	if err != nil {
		return nil, err
	}

	combined := append([]policy.NamedPolicy{}, existing...)
	for _, p := range policies {
		candidate := policy.NamedPolicy{Tenant: key.Tenant, PolicyName: key.Name, Policy: p}
		if err := policy.CheckConflicts(combined, candidate); err != nil {
			return nil, err
		}
		combined = append(combined, candidate)
	}

	return policies, nil
}

func (ps *InMemoryPolicySync) currentPolicies() ([]policy.NamedPolicy, error) {
	ps.mu.RLock()
	items := make([]struct {
		key  PolicyKey
		yaml []byte
	}, 0, len(ps.policies))
	for k, state := range ps.policies {
		items = append(items, struct {
			key  PolicyKey
			yaml []byte
		}{key: k, yaml: append([]byte(nil), state.YAML...)})
	}
	ps.mu.RUnlock()

	policies := make([]policy.NamedPolicy, 0, len(items))
	for _, item := range items {
		yamlBytes := item.yaml
		loaded, err := policy.LoadFromBytes(yamlBytes)
		if err != nil {
			return nil, err
		}
		for _, p := range loaded {
			policies = append(policies, policy.NamedPolicy{Tenant: item.key.Tenant, PolicyName: item.key.Name, Policy: p})
		}
	}

	return policies, nil
}

func copyPolicyRevision(revision PolicyRevision) PolicyRevision {
	copy := revision
	copy.YAML = append([]byte(nil), revision.YAML...)
	copy.RollbackFromVersion = copyRollbackVersion(revision.RollbackFromVersion)
	return copy
}

func copyRollbackVersion(version *int64) *int64 {
	if version == nil {
		return nil
	}
	copied := *version
	return &copied
}
