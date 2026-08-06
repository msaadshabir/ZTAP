package compliance

import (
	"encoding/csv"
	"encoding/json"
	"io"
	"sort"
)

func WriteJSON(w io.Writer, report Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(report)
}

func WriteCSV(w io.Writer, report Report) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"framework_id", "framework_version", "control_id", "tenant", "policy_key", "policy_object_name", "rationale", "owner", "evidence_status"}); err != nil {
		return err
	}

	policyMeta := make(map[string]struct {
		rationale string
		owner     string
	}, len(report.Policies))
	for _, p := range report.Policies {
		k := p.Policy.PolicyKey + "|" + p.Policy.PolicyObjectName
		policyMeta[k] = struct {
			rationale string
			owner     string
		}{rationale: p.Rationale, owner: p.Owner}
	}

	controls := append([]ControlMapping(nil), report.Controls...)
	sort.Slice(controls, func(i, j int) bool {
		if controls[i].Framework == controls[j].Framework {
			return controls[i].ControlID < controls[j].ControlID
		}
		return controls[i].Framework < controls[j].Framework
	})

	for _, c := range controls {
		policies := append([]PolicyRef(nil), c.Policies...)
		sort.Slice(policies, func(i, j int) bool {
			if policies[i].PolicyKey == policies[j].PolicyKey {
				return policies[i].PolicyObjectName < policies[j].PolicyObjectName
			}
			return policies[i].PolicyKey < policies[j].PolicyKey
		})
		for _, p := range policies {
			k := p.PolicyKey + "|" + p.PolicyObjectName
			meta := policyMeta[k]
			if err := cw.Write([]string{string(c.Framework), "", c.ControlID, p.Tenant, p.PolicyKey, p.PolicyObjectName, meta.rationale, meta.owner, string(c.Evidence.Status)}); err != nil {
				return err
			}
		}
	}

	cw.Flush()
	return cw.Error()
}
