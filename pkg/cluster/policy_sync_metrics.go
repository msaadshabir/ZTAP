package cluster

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// policiesSyncedTotal tracks the total number of policy sync operations
	policiesSyncedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ztap_policies_synced_total",
			Help: "Total number of policy sync operations",
		},
		[]string{"status", "policy_name"},
	)

	// policySyncDuration tracks the duration of policy sync operations
	policySyncDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ztap_policy_sync_duration_seconds",
			Help:    "Duration of policy sync operations in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"policy_name"},
	)

	// policyVersionCurrent tracks the current version of each policy
	policyVersionCurrent = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ztap_policy_version_current",
			Help: "Current version of each policy",
		},
		[]string{"policy_name"},
	)

	// policySyncErrorsTotal tracks the total number of policy sync errors
	policySyncErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ztap_policy_sync_errors_total",
			Help: "Total number of policy sync errors",
		},
		[]string{"error_type", "policy_name"},
	)

	// policySubscribersActive tracks the number of active policy subscribers
	policySubscribersActive = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "ztap_policy_subscribers_active",
			Help: "Number of active policy subscribers",
		},
	)

	// policiesEnforcedTotal tracks the total number of policies enforced
	policiesEnforcedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ztap_policies_enforced_total",
			Help: "Total number of policies enforced",
		},
		[]string{"status", "policy_name", "node_id"},
	)

	// policyEnforcementDuration tracks the duration of policy enforcement operations
	policyEnforcementDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "ztap_policy_enforcement_duration_seconds",
			Help:    "Duration of policy enforcement operations in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"policy_name"},
	)
)

// recordPolicySynced records a successful policy sync
func recordPolicySynced(policyName string, version int64) {
	policiesSyncedTotal.WithLabelValues("success", policyName).Inc()
	policyVersionCurrent.WithLabelValues(policyName).Set(float64(version))
}

// recordPolicySyncError records a policy sync error
func recordPolicySyncError(errorType, policyName string) {
	policiesSyncedTotal.WithLabelValues("error", policyName).Inc()
	policySyncErrorsTotal.WithLabelValues(errorType, policyName).Inc()
}

// RecordPolicyEnforced records a successful policy enforcement
func RecordPolicyEnforced(policyName, nodeID string) {
	policiesEnforcedTotal.WithLabelValues("success", policyName, nodeID).Inc()
}

// RecordPolicyEnforcementError records a policy enforcement error
func RecordPolicyEnforcementError(policyName, nodeID string) {
	policiesEnforcedTotal.WithLabelValues("error", policyName, nodeID).Inc()
}

// RecordPolicyEnforcementDuration records the duration of a policy enforcement
func RecordPolicyEnforcementDuration(policyName string, durationSeconds float64) {
	policyEnforcementDuration.WithLabelValues(policyName).Observe(durationSeconds)
}

// incrementPolicySubscribers increments the active subscribers count
func incrementPolicySubscribers() {
	policySubscribersActive.Inc()
}

// decrementPolicySubscribers decrements the active subscribers count
func decrementPolicySubscribers() {
	policySubscribersActive.Dec()
}
