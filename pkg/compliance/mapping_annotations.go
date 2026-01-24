package compliance

import (
	"sort"
	"strings"

	"ztap/pkg/policy"
)

const annotationPrefix = "ztap.io/compliance."

type AnnotationParseOptions struct {
	Strict bool
}

// ExtractMappingsFromAnnotations returns per-policy control mappings found in annotations.
func ExtractMappingsFromAnnotations(policies []policy.NetworkPolicy, defaultPolicyKey string, opts AnnotationParseOptions) ([]MappingEntry, []string, error) {
	warnings := []string{}
	out := make([]MappingEntry, 0, len(policies))

	for _, p := range policies {
		policyName := strings.TrimSpace(p.Metadata.Name)
		if policyName == "" {
			continue
		}

		controls := map[FrameworkID][]string{}
		for k, v := range p.Metadata.Annotations {
			k = strings.TrimSpace(k)
			if !strings.HasPrefix(k, annotationPrefix) {
				continue
			}
			fwStr := strings.TrimPrefix(k, annotationPrefix)
			fw, ok := ParseFrameworkID(fwStr)
			if !ok {
				msg := "unknown compliance framework in annotation: " + k
				if opts.Strict {
					return nil, nil, Err(msg)
				}
				warnings = append(warnings, msg)
				continue
			}

			ids := splitCSV(v)
			for _, id := range ids {
				if err := ValidateControlID(fw, id); err != nil {
					msg := "invalid control id in " + k + ": " + err.Error()
					if opts.Strict {
						return nil, nil, Err(msg)
					}
					warnings = append(warnings, msg)
					continue
				}
				controls[fw] = append(controls[fw], strings.TrimSpace(id))
			}
		}

		for fw := range controls {
			controls[fw] = uniqueSorted(controls[fw])
		}
		if len(controls) == 0 {
			continue
		}

		ref := PolicyRef{
			Tenant:           tenantFromPolicyKey(defaultPolicyKey),
			PolicyKey:        defaultPolicyKey,
			PolicyObjectName: policyName,
		}
		out = append(out, MappingEntry{Policy: ref, Controls: controls})
	}

	return out, warnings, nil
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func uniqueSorted(in []string) []string {
	set := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := set[s]; ok {
			continue
		}
		set[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
