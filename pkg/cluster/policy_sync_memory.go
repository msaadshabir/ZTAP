package cluster

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"ztap/pkg/policy"
)

// InMemoryPolicySync implements distributed policy synchronization using in-memory storage.
// It is NOT suitable for production distributed deployments; use etcd or Raft for production.
type InMemoryPolicySync struct {
	mu          sync.RWMutex
	policies    map[string]*PolicyState // policyName -> PolicyState
	subscribers []chan PolicyUpdate     // Channels for policy update notifications
	election    LeaderElection          // Cluster coordination backend
	nodeID      string                  // This node's identifier
	running     bool
	stopCh      chan struct{}
}

// PolicyState holds the state of a single policy in the cluster.
type PolicyState struct {
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
		policies:    make(map[string]*PolicyState),
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

	log.Printf("Policy synchronization started for node %s", ps.nodeID)

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
	startTime := time.Now()

	if policyName == "" {
		recordPolicySyncError("empty_name", policyName)
		return fmt.Errorf("policy name cannot be empty")
	}
	if len(policyYAML) == 0 {
		recordPolicySyncError("empty_yaml", policyName)
		return fmt.Errorf("policy YAML cannot be empty")
	}

	if _, err := ps.parseAndValidate(policyName, policyYAML); err != nil {
		recordPolicySyncError("invalid_policy", policyName)
		return err
	}

	// Verify this node is the leader
	if !ps.election.IsLeader() {
		leader := ps.election.GetLeader()
		if leader == nil {
			recordPolicySyncError("no_leader", policyName)
			return fmt.Errorf("no leader elected; cannot sync policy")
		}
		recordPolicySyncError("not_leader", policyName)
		return fmt.Errorf("only leader can sync policies; current leader is %s", leader.ID)
	}

	ps.mu.Lock()
	defer ps.mu.Unlock()

	// Get current version and increment
	var newVersion int64 = 1
	if existingPolicy, exists := ps.policies[policyName]; exists {
		newVersion = existingPolicy.Version + 1
	}

	// Store policy state
	policyState := &PolicyState{
		Name:      policyName,
		YAML:      policyYAML,
		Version:   newVersion,
		Source:    ps.nodeID,
		Timestamp: time.Now(),
	}
	ps.policies[policyName] = policyState

	// Create update notification
	update := PolicyUpdate{
		PolicyName: policyName,
		YAML:       policyYAML,
		Version:    newVersion,
		Source:     ps.nodeID,
		Timestamp:  policyState.Timestamp,
	}

	// Broadcast to all subscribers
	ps.broadcastUpdate(update)

	// Record metrics
	duration := time.Since(startTime).Seconds()
	policySyncDuration.WithLabelValues(policyName).Observe(duration)
	recordPolicySynced(policyName, newVersion)

	log.Printf("Policy %s synced to cluster (version %d) by leader %s", policyName, newVersion, ps.nodeID)

	return nil
}

// GetPolicyVersion returns the current version of a policy across the cluster.
// Returns 0 if the policy doesn't exist.
func (ps *InMemoryPolicySync) GetPolicyVersion(policyName string) (int64, error) {
	if policyName == "" {
		return 0, fmt.Errorf("policy name cannot be empty")
	}

	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if policyState, exists := ps.policies[policyName]; exists {
		return policyState.Version, nil
	}

	return 0, nil // Policy doesn't exist yet
}

// GetPolicy returns the full policy state for a given policy name.
// Returns nil if the policy doesn't exist.
func (ps *InMemoryPolicySync) GetPolicy(policyName string) (*PolicyState, error) {
	if policyName == "" {
		return nil, fmt.Errorf("policy name cannot be empty")
	}

	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if policyState, exists := ps.policies[policyName]; exists {
		// Return a copy to prevent external modifications
		return &PolicyState{
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
				log.Printf("Leader changed to %s; policy sync adapting", leader.ID)
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
			log.Printf("Warning: policy update channel full, dropping event for policy %s", update.PolicyName)
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

	if _, err := ps.parseAndValidate(update.PolicyName, update.YAML); err != nil {
		return err
	}

	ps.mu.Lock()
	defer ps.mu.Unlock()

	// Check if we already have this version or newer
	if existingPolicy, exists := ps.policies[update.PolicyName]; exists {
		if existingPolicy.Version >= update.Version {
			log.Printf("Skipping policy %s update (existing version %d >= received version %d)",
				update.PolicyName, existingPolicy.Version, update.Version)
			return nil
		}
	}

	// Store the updated policy state
	policyState := &PolicyState{
		Name:      update.PolicyName,
		YAML:      update.YAML,
		Version:   update.Version,
		Source:    update.Source,
		Timestamp: update.Timestamp,
	}
	ps.policies[update.PolicyName] = policyState

	// Broadcast to local subscribers
	ps.broadcastUpdate(update)

	log.Printf("Applied remote policy update for %s (version %d) from %s",
		update.PolicyName, update.Version, update.Source)

	return nil
}

func (ps *InMemoryPolicySync) parseAndValidate(policyName string, policyYAML []byte) ([]policy.NetworkPolicy, error) {
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
		candidate := policy.NamedPolicy{PolicyName: policyName, Policy: p}
		if err := policy.CheckConflicts(combined, candidate); err != nil {
			return nil, err
		}
		combined = append(combined, candidate)
	}

	return policies, nil
}

func (ps *InMemoryPolicySync) currentPolicies() ([]policy.NamedPolicy, error) {
	ps.mu.RLock()
	data := make([][]byte, 0, len(ps.policies))
	names := make([]string, 0, len(ps.policies))
	for name, state := range ps.policies {
		data = append(data, append([]byte(nil), state.YAML...))
		names = append(names, name)
	}
	ps.mu.RUnlock()

	policies := make([]policy.NamedPolicy, 0, len(data))
	for i, yamlBytes := range data {
		loaded, err := policy.LoadFromBytes(yamlBytes)
		if err != nil {
			return nil, err
		}
		for _, p := range loaded {
			policies = append(policies, policy.NamedPolicy{PolicyName: names[i], Policy: p})
		}
	}

	return policies, nil
}
