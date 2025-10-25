package enforcer

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"ztap/pkg/audit"
	"ztap/pkg/cluster"
	"ztap/pkg/policy"
)

// PolicyEnforcer manages automatic policy enforcement from cluster synchronization.
type PolicyEnforcer struct {
	mu              sync.RWMutex
	policySync      cluster.PolicySync
	discovery       policy.ServiceDiscovery
	enforcedVersion map[string]int64 // Track which version of each policy is enforced
	running         bool
	stopCh          chan struct{}
	cgroupPath      string             // For eBPF enforcement
	auditLogger     *audit.AuditLogger // Audit logging for policy operations
}

// PolicyEnforcerConfig holds configuration for the policy enforcer.
type PolicyEnforcerConfig struct {
	PolicySync cluster.PolicySync      // Policy synchronization backend
	Discovery  policy.ServiceDiscovery // Service discovery for label resolution
	CgroupPath string                  // Cgroup path for eBPF attachment (Linux only)
}

// NewPolicyEnforcer creates a new policy enforcer that watches for policy updates.
func NewPolicyEnforcer(config PolicyEnforcerConfig) *PolicyEnforcer {
	// Initialize audit logger
	homeDir, _ := os.UserHomeDir()
	logPath := filepath.Join(homeDir, ".ztap", "audit.log")
	auditLogger, err := audit.NewAuditLogger(logPath)
	if err != nil {
		log.Printf("Warning: failed to initialize audit logger: %v", err)
	}

	return &PolicyEnforcer{
		policySync:      config.PolicySync,
		discovery:       config.Discovery,
		enforcedVersion: make(map[string]int64),
		stopCh:          make(chan struct{}),
		cgroupPath:      config.CgroupPath,
		auditLogger:     auditLogger,
	}
}

// Start begins watching for policy updates and enforcing them automatically.
func (pe *PolicyEnforcer) Start(ctx context.Context) error {
	pe.mu.Lock()
	if pe.running {
		pe.mu.Unlock()
		return nil
	}
	pe.running = true
	pe.mu.Unlock()

	log.Println("Policy enforcer started, watching for policy updates...")

	// Subscribe to policy updates
	policyUpdates := pe.policySync.SubscribePolicies(ctx)

	// Start enforcement loop
	go pe.enforcementLoop(ctx, policyUpdates)

	return nil
}

// Stop gracefully shuts down the policy enforcer.
func (pe *PolicyEnforcer) Stop() error {
	pe.mu.Lock()
	if !pe.running {
		pe.mu.Unlock()
		return nil
	}
	pe.running = false
	close(pe.stopCh)
	pe.mu.Unlock()

	log.Println("Policy enforcer stopped")
	return nil
}

// enforcementLoop watches for policy updates and applies them.
func (pe *PolicyEnforcer) enforcementLoop(ctx context.Context, updates <-chan cluster.PolicyUpdate) {
	for {
		select {
		case <-pe.stopCh:
			return
		case <-ctx.Done():
			return
		case update, ok := <-updates:
			if !ok {
				log.Println("Policy update channel closed, stopping enforcement loop")
				return
			}

			// Check if we've already enforced this version
			pe.mu.RLock()
			currentVersion := pe.enforcedVersion[update.PolicyName]
			pe.mu.RUnlock()

			if update.Version <= currentVersion {
				log.Printf("Skipping policy %s v%d (already enforced v%d)",
					update.PolicyName, update.Version, currentVersion)
				continue
			}

			// Apply the policy
			startTime := time.Now()
			if err := pe.applyPolicy(update); err != nil {
				log.Printf("Failed to enforce policy %s v%d: %v",
					update.PolicyName, update.Version, err)
				cluster.RecordPolicyEnforcementError(update.PolicyName, "local-node")

				// Log failure to audit log
				if pe.auditLogger != nil {
					details := map[string]interface{}{
						"version": update.Version,
						"source":  update.Source,
					}
					_ = pe.auditLogger.LogFailure(audit.EventPolicyEnforced, "system",
						update.PolicyName, "enforce", err.Error(), details)
				}
				continue
			}

			// Update enforced version
			pe.mu.Lock()
			pe.enforcedVersion[update.PolicyName] = update.Version
			pe.mu.Unlock()

			// Record metrics
			duration := time.Since(startTime).Seconds()
			cluster.RecordPolicyEnforcementDuration(update.PolicyName, duration)
			cluster.RecordPolicyEnforced(update.PolicyName, "local-node")

			// Log success to audit log
			if pe.auditLogger != nil {
				details := map[string]interface{}{
					"version":     update.Version,
					"source":      update.Source,
					"duration_ms": duration * 1000,
				}
				_ = pe.auditLogger.Log(audit.EventPolicyEnforced, "system",
					update.PolicyName, "enforce", details)
			}

			log.Printf("Successfully enforced policy %s v%d from %s",
				update.PolicyName, update.Version, update.Source)
		}
	}
}

// applyPolicy parses and enforces a single policy update.
func (pe *PolicyEnforcer) applyPolicy(update cluster.PolicyUpdate) error {
	// Parse the policy YAML
	policies, err := policy.LoadFromBytes(update.YAML)
	if err != nil {
		return err
	}

	if len(policies) == 0 {
		log.Printf("Warning: policy %s contains no NetworkPolicy objects", update.PolicyName)
		return nil
	}

	// Validate all policies
	for _, p := range policies {
		if err := p.Validate(); err != nil {
			return err
		}
	}

	// Enforce based on platform
	if IsLinux() {
		return pe.enforceLinux(policies)
	}
	return pe.enforceMacOS(policies)
}

// enforceLinux applies policies using eBPF on Linux.
func (pe *PolicyEnforcer) enforceLinux(policies []policy.NetworkPolicy) error {
	// Use the real eBPF enforcer if available and on Linux
	if pe.cgroupPath != "" && IsLinux() {
		// EnforceWithEBPFReal is only available on Linux (ebpf_linux.go)
		// Call it through the generic enforcement function
		return enforceWithEBPFIfAvailable(policies, pe.cgroupPath)
	}

	// Fallback to simulation
	EnforceWithEBPF(policies)
	return nil
}

// enforceMacOS applies policies using pf on macOS.
func (pe *PolicyEnforcer) enforceMacOS(policies []policy.NetworkPolicy) error {
	EnforceWithPF(policies)
	return nil
}

// GetEnforcedVersions returns a map of policy names to their enforced versions.
func (pe *PolicyEnforcer) GetEnforcedVersions() map[string]int64 {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	versions := make(map[string]int64, len(pe.enforcedVersion))
	for k, v := range pe.enforcedVersion {
		versions[k] = v
	}
	return versions
}

// GetEnforcedVersion returns the enforced version for a specific policy.
func (pe *PolicyEnforcer) GetEnforcedVersion(policyName string) int64 {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	return pe.enforcedVersion[policyName]
}
