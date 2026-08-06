package compliance

import (
	"context"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"ztap/internal/audit"
	"ztap/internal/policy"
)

type BuildOptions struct {
	PolicyName       string
	DefaultPolicyKey string

	Frameworks []FrameworkID

	MappingFileYAML []byte
	Strict          bool

	AuditLogPath   string
	EvidenceWindow time.Duration
}

func BuildReport(ctx context.Context, policies []policy.NetworkPolicy, opts BuildOptions) (Report, error) {
	_ = ctx

	frameworks := opts.Frameworks
	if len(frameworks) == 0 {
		frameworks = KnownFrameworks()
	}
	frameworkSet := make(map[FrameworkID]struct{}, len(frameworks))
	for _, fw := range frameworks {
		frameworkSet[fw] = struct{}{}
	}

	defaultKey := strings.TrimSpace(opts.DefaultPolicyKey)
	if defaultKey == "" {
		defaultKey = deriveDefaultPolicyKey(policies, strings.TrimSpace(opts.PolicyName))
	}

	warnings := []string{}

	var fileMappings []MappingEntry
	mappingSource := "annotations"
	if len(opts.MappingFileYAML) > 0 {
		m, baseKey, w, err := ParseMappingFile(opts.MappingFileYAML, defaultKey, MappingFileOptions{Strict: opts.Strict})
		if err != nil {
			return Report{}, err
		}
		fileMappings = m
		if strings.TrimSpace(baseKey) != "" {
			defaultKey = baseKey
		}
		warnings = append(warnings, w...)
		mappingSource = "mapping_file"
	}

	annMappings, w, err := ExtractMappingsFromAnnotations(policies, defaultKey, AnnotationParseOptions{Strict: opts.Strict})
	if err != nil {
		return Report{}, err
	}
	warnings = append(warnings, w...)

	merged := mergeMappings(fileMappings, annMappings)
	merged = filterMappingsByFramework(merged, frameworkSet)

	report := Report{
		Metadata: ReportMetadata{
			GeneratedAt:   time.Now().UTC(),
			HostOS:        runtime.GOOS,
			HostArch:      runtime.GOARCH,
			PolicyName:    strings.TrimSpace(opts.PolicyName),
			PolicyKey:     defaultKey,
			MappingSource: mappingSource,
			AuditLogPath:  strings.TrimSpace(opts.AuditLogPath),
		},
		Warnings: warnings,
	}

	auditEv, policyEvidence, warn := collectEvidence(opts.AuditLogPath, merged, opts.EvidenceWindow)
	report.Audit = auditEv
	report.Warnings = append(report.Warnings, warn...)

	controls, policiesOut := materialize(merged, policyEvidence)
	report.Controls = controls
	report.Policies = policiesOut

	return report, nil
}

func deriveDefaultPolicyKey(policies []policy.NetworkPolicy, policyName string) string {
	policyName = strings.TrimSpace(policyName)
	if policyName != "" {
		if strings.Contains(policyName, "/") {
			return policyName
		}
		return "default/" + policyName
	}
	if len(policies) == 1 {
		name := strings.TrimSpace(policies[0].Metadata.Name)
		if name != "" {
			return "default/" + name
		}
	}
	// Multi-doc or unnamed policies: best-effort.
	return "default/policy"
}

func mergeMappings(fileMappings, annMappings []MappingEntry) []MappingEntry {
	if len(fileMappings) == 0 {
		return annMappings
	}
	if len(annMappings) == 0 {
		return fileMappings
	}

	// Precedence: mapping file overrides annotations for the same policy object.
	// The mapping file may also override the policy key.
	byObject := make(map[string]MappingEntry, len(fileMappings)+len(annMappings))
	for _, m := range annMappings {
		name := strings.TrimSpace(m.Policy.PolicyObjectName)
		if name == "" {
			continue
		}
		byObject[name] = m
	}
	for _, m := range fileMappings {
		name := strings.TrimSpace(m.Policy.PolicyObjectName)
		if name == "" {
			continue
		}
		byObject[name] = m
	}

	out := make([]MappingEntry, 0, len(byObject))
	for _, v := range byObject {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Policy.PolicyKey == out[j].Policy.PolicyKey {
			return out[i].Policy.PolicyObjectName < out[j].Policy.PolicyObjectName
		}
		return out[i].Policy.PolicyKey < out[j].Policy.PolicyKey
	})
	return out
}

func filterMappingsByFramework(in []MappingEntry, allowed map[FrameworkID]struct{}) []MappingEntry {
	out := make([]MappingEntry, 0, len(in))
	for _, m := range in {
		filtered := map[FrameworkID][]string{}
		for fw, ids := range m.Controls {
			if _, ok := allowed[fw]; !ok {
				continue
			}
			filtered[fw] = ids
		}
		if len(filtered) == 0 {
			continue
		}
		m.Controls = filtered
		out = append(out, m)
	}
	return out
}

func collectEvidence(auditLogPath string, mappings []MappingEntry, window time.Duration) (AuditEvidence, map[string]PolicyEvidence, []string) {
	warnings := []string{}
	pEv := make(map[string]PolicyEvidence, len(mappings))

	path := strings.TrimSpace(auditLogPath)
	if path == "" {
		// Best-effort default.
		if home, err := os.UserHomeDir(); err == nil {
			path = home + string(os.PathSeparator) + ".ztap" + string(os.PathSeparator) + "audit.log"
		}
	}
	if strings.TrimSpace(path) == "" {
		return AuditEvidence{IntegrityStatus: EvidenceUnknown}, pEv, warnings
	}

	if _, err := os.Stat(path); err != nil {
		warnings = append(warnings, "audit log not accessible: "+err.Error())
		return AuditEvidence{IntegrityStatus: EvidenceUnknown}, pEv, warnings
	}

	ok, verr := audit.VerifyFileIntegrity(path)
	ae := AuditEvidence{IntegrityStatus: EvidenceMissing}
	if verr != nil {
		ae.IntegrityStatus = EvidenceMissing
		ae.IntegrityError = verr.Error()
		warnings = append(warnings, "audit integrity check failed: "+verr.Error())
	} else if ok {
		ae.IntegrityStatus = EvidencePresent
	}

	if st, err := audit.GetFileStats(path); err == nil {
		ae.EntryCount = st.EntryCount
		ae.LastHash = st.LastHash
	} else {
		warnings = append(warnings, "audit stats unavailable: "+err.Error())
	}

	// Only trust enforcement evidence when integrity verified.
	if ae.IntegrityStatus != EvidencePresent {
		warnings = append(warnings, "audit integrity not verified; enforcement evidence marked unknown")
		for _, m := range mappings {
			key := strings.TrimSpace(m.Policy.PolicyKey) + "|" + strings.TrimSpace(m.Policy.PolicyObjectName)
			pEv[key] = PolicyEvidence{Policy: m.Policy, Enforced: EvidenceUnknown}
		}
		return ae, pEv, warnings
	}

	var start *time.Time
	if window > 0 {
		t := time.Now().Add(-window)
		start = &t
	}

	policyCounts := make(map[string]int, len(mappings))
	keyByPolicy := make(map[string]string, len(mappings))
	for _, m := range mappings {
		key := strings.TrimSpace(m.Policy.PolicyKey) + "|" + strings.TrimSpace(m.Policy.PolicyObjectName)
		policyCounts[key] = 0
		keyByPolicy[m.Policy.PolicyKey] = key
	}

	evt := audit.EventPolicyEnforced
	err := audit.ScanFile(path, audit.QueryOptions{StartTime: start, EventType: &evt}, func(entry audit.AuditEntry) bool {
		key, ok := keyByPolicy[entry.Resource]
		if !ok {
			return true
		}
		policyCounts[key]++
		return true
	})
	if err != nil {
		warnings = append(warnings, "audit query failed: "+err.Error())
		for _, m := range mappings {
			key := strings.TrimSpace(m.Policy.PolicyKey) + "|" + strings.TrimSpace(m.Policy.PolicyObjectName)
			pEv[key] = PolicyEvidence{Policy: m.Policy, Enforced: EvidenceUnknown}
		}
		return ae, pEv, warnings
	}

	for _, m := range mappings {
		key := strings.TrimSpace(m.Policy.PolicyKey) + "|" + strings.TrimSpace(m.Policy.PolicyObjectName)
		ref := m.Policy
		pev := PolicyEvidence{Policy: ref, Enforced: EvidenceUnknown}
		pev.EnforcedCount = policyCounts[key]
		if pev.EnforcedCount > 0 {
			pev.Enforced = EvidencePresent
		} else {
			pev.Enforced = EvidenceMissing
		}
		pEv[key] = pev
	}

	return ae, pEv, warnings
}

func materialize(mappings []MappingEntry, evidence map[string]PolicyEvidence) ([]ControlMapping, []PolicyMapping) {
	// Build control->policies index.
	controlPolicies := make(map[string]map[string]PolicyRef)
	policyControls := make(map[string]map[string]ControlRef)
	policyMeta := make(map[string]struct {
		rationale string
		owner     string
	}, len(mappings))

	for _, m := range mappings {
		pkey := m.Policy.PolicyKey + "|" + m.Policy.PolicyObjectName
		policyMeta[pkey] = struct {
			rationale string
			owner     string
		}{rationale: strings.TrimSpace(m.Rationale), owner: strings.TrimSpace(m.Owner)}
		if _, ok := policyControls[pkey]; !ok {
			policyControls[pkey] = make(map[string]ControlRef)
		}
		for fw, ids := range m.Controls {
			for _, id := range ids {
				ck := string(fw) + ":" + id
				if _, ok := controlPolicies[ck]; !ok {
					controlPolicies[ck] = make(map[string]PolicyRef)
				}
				controlPolicies[ck][pkey] = m.Policy
				policyControls[pkey][ck] = ControlRef{Framework: fw, ControlID: id}
			}
		}
	}

	controlsOut := make([]ControlMapping, 0, len(controlPolicies))
	for ck, policies := range controlPolicies {
		parts := strings.SplitN(ck, ":", 2)
		fw := FrameworkID(parts[0])
		id := parts[1]

		pols := make([]PolicyRef, 0, len(policies))
		for _, p := range policies {
			pols = append(pols, p)
		}
		sort.Slice(pols, func(i, j int) bool {
			if pols[i].PolicyKey == pols[j].PolicyKey {
				return pols[i].PolicyObjectName < pols[j].PolicyObjectName
			}
			return pols[i].PolicyKey < pols[j].PolicyKey
		})

		status := EvidenceUnknown
		anyPresent := false
		anyMissing := false
		for _, p := range pols {
			evKey := p.PolicyKey + "|" + p.PolicyObjectName
			pev, ok := evidence[evKey]
			if !ok {
				anyMissing = true
				continue
			}
			switch pev.Enforced {
			case EvidencePresent:
				anyPresent = true
			case EvidenceMissing:
				anyMissing = true
			case EvidenceUnknown:
				// ignore
			}
		}
		if anyPresent {
			status = EvidencePresent
		} else if anyMissing {
			status = EvidenceMissing
		}

		controlsOut = append(controlsOut, ControlMapping{
			Framework: fw,
			ControlID: id,
			Policies:  pols,
			Evidence:  ControlEvidence{Framework: fw, ControlID: id, Status: status},
		})
	}
	sort.Slice(controlsOut, func(i, j int) bool {
		if controlsOut[i].Framework == controlsOut[j].Framework {
			return controlsOut[i].ControlID < controlsOut[j].ControlID
		}
		return controlsOut[i].Framework < controlsOut[j].Framework
	})

	policiesOut := make([]PolicyMapping, 0, len(policyControls))
	for pk, ctrls := range policyControls {
		controls := make([]ControlRef, 0, len(ctrls))
		for _, c := range ctrls {
			controls = append(controls, c)
		}
		sort.Slice(controls, func(i, j int) bool {
			if controls[i].Framework == controls[j].Framework {
				return controls[i].ControlID < controls[j].ControlID
			}
			return controls[i].Framework < controls[j].Framework
		})

		pev := evidence[pk]
		meta := policyMeta[pk]
		policiesOut = append(policiesOut, PolicyMapping{Policy: pev.Policy, Controls: controls, Evidence: pev, Rationale: meta.rationale, Owner: meta.owner})
	}
	sort.Slice(policiesOut, func(i, j int) bool {
		if policiesOut[i].Policy.PolicyKey == policiesOut[j].Policy.PolicyKey {
			return policiesOut[i].Policy.PolicyObjectName < policiesOut[j].Policy.PolicyObjectName
		}
		return policiesOut[i].Policy.PolicyKey < policiesOut[j].Policy.PolicyKey
	})

	return controlsOut, policiesOut
}
