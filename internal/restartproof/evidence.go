package restartproof

import (
	"fmt"
	"math"
)

const (
	EvidenceVersion = 2
	ContinuityScope = "native agent with synthetic synchronized Kubernetes facts and verified containerd-shaped cgroups; continuous UDP sockets inside the protected cgroup and peers outside; deployed DaemonSet scheduling is excluded"
)

type Counts struct {
	IngressAllowed    uint64 `json:"ingress_allowed"`
	EgressAllowed     uint64 `json:"egress_allowed"`
	Replies           uint64 `json:"established_replies"`
	IngressProhibited uint64 `json:"ingress_prohibited"`
	EgressProhibited  uint64 `json:"egress_prohibited"`
	IngressBlocked    uint64 `json:"ingress_blocked"`
	EgressBlocked     uint64 `json:"egress_blocked"`
}

type Sample struct {
	Mode              string  `json:"mode"`
	OutageMS          float64 `json:"outage_ms"`
	CgroupID          uint64  `json:"cgroup_id"`
	PolicyEpochBefore uint64  `json:"policy_epoch_before"`
	PolicyEpochAfter  uint64  `json:"policy_epoch_after"`
	AgentEpochBefore  uint64  `json:"agent_epoch_before"`
	AgentEpochAfter   uint64  `json:"agent_epoch_after"`
	Before            Counts  `json:"before"`
	During            Counts  `json:"during"`
	After             Counts  `json:"after"`
}

func ValidateSamples(samples []Sample, want int, mode string) error {
	if len(samples) != want {
		return fmt.Errorf("continuity samples = %d, want %d", len(samples), want)
	}
	for index, s := range samples {
		if s.Mode != mode || math.IsNaN(s.OutageMS) || math.IsInf(s.OutageMS, 0) || s.OutageMS < 1500 {
			return fmt.Errorf("continuity sample %d has an invalid mode or insufficient outage duration", index)
		}
		if s.CgroupID == 0 || s.PolicyEpochBefore == 0 || s.PolicyEpochBefore != s.PolicyEpochAfter || s.AgentEpochBefore == 0 || s.AgentEpochAfter == 0 || s.AgentEpochBefore == s.AgentEpochAfter {
			return fmt.Errorf("continuity sample %d has invalid cgroup or recovery epochs", index)
		}
		for phase, c := range []Counts{s.Before, s.During, s.After} {
			if c.IngressProhibited != 0 || c.EgressProhibited != 0 {
				return fmt.Errorf("continuity sample %d phase %d received prohibited traffic", index, phase)
			}
			if c.IngressAllowed == 0 || c.EgressAllowed == 0 || c.Replies == 0 || c.IngressBlocked == 0 || c.EgressBlocked == 0 {
				return fmt.Errorf("continuity sample %d phase %d lacks working directional controls and replies", index, phase)
			}
		}
		if !controlsAdvance(s.Before, s.During) || !controlsAdvance(s.During, s.After) {
			return fmt.Errorf("continuity sample %d controls stopped across the outage or recovery", index)
		}
	}
	return nil
}

func controlsAdvance(a, b Counts) bool {
	return b.IngressAllowed > a.IngressAllowed && b.EgressAllowed > a.EgressAllowed && b.Replies > a.Replies && b.IngressBlocked > a.IngressBlocked && b.EgressBlocked > a.EgressBlocked
}
