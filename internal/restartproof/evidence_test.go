package restartproof

import (
	"math"
	"testing"
)

func TestContinuityEvidenceRejectsLeaksAndIdleControls(t *testing.T) {
	valid := Sample{Mode: "SIGKILL", OutageMS: 1500, CgroupID: 42, PolicyEpochBefore: 1, PolicyEpochAfter: 1, AgentEpochBefore: 10, AgentEpochAfter: 11,
		Before: Counts{IngressAllowed: 1, EgressAllowed: 2, Replies: 1, IngressBlocked: 2, EgressBlocked: 2}, During: Counts{IngressAllowed: 20, EgressAllowed: 30, Replies: 20, IngressBlocked: 30, EgressBlocked: 30}, After: Counts{IngressAllowed: 50, EgressAllowed: 60, Replies: 50, IngressBlocked: 70, EgressBlocked: 70}}
	if err := ValidateSamples([]Sample{valid}, 1, "SIGKILL"); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Sample){
		"ingress leak":            func(s *Sample) { s.During.IngressProhibited = 1 },
		"egress leak":             func(s *Sample) { s.After.EgressProhibited = 1 },
		"idle ingress":            func(s *Sample) { s.During.IngressAllowed = s.Before.IngressAllowed },
		"idle egress":             func(s *Sample) { s.After.EgressAllowed = s.During.EgressAllowed },
		"idle replies":            func(s *Sample) { s.After.Replies = s.During.Replies },
		"empty baseline":          func(s *Sample) { s.Before.Replies = 0 },
		"short outage":            func(s *Sample) { s.OutageMS = 1499 },
		"nonfinite outage":        func(s *Sample) { s.OutageMS = math.NaN() },
		"infinite outage":         func(s *Sample) { s.OutageMS = math.Inf(1) },
		"changed policy":          func(s *Sample) { s.PolicyEpochAfter = 2 },
		"zero controller epoch":   func(s *Sample) { s.AgentEpochAfter = 0 },
		"reused controller epoch": func(s *Sample) { s.AgentEpochAfter = s.AgentEpochBefore },
		"wrong signal":            func(s *Sample) { s.Mode = "SIGTERM" },
		"no subject":              func(s *Sample) { s.CgroupID = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			sample := valid
			mutate(&sample)
			if err := ValidateSamples([]Sample{sample}, 1, "SIGKILL"); err == nil {
				t.Fatal("invalid evidence accepted")
			}
		})
	}
	if err := ValidateSamples(nil, 1, "SIGKILL"); err == nil {
		t.Fatal("missing samples accepted")
	}
}
