package compliance

import (
	"fmt"
	"sort"
	"strings"

	yaml "gopkg.in/yaml.v3"
)

type mappingFile struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Spec       struct {
		Defaults struct {
			Tenant    string `yaml:"tenant"`
			PolicyKey string `yaml:"policyKey"`
		} `yaml:"defaults"`
		Mappings []struct {
			PolicyObjectName string              `yaml:"policyObjectName"`
			PolicyKey        string              `yaml:"policyKey"`
			Controls         map[string][]string `yaml:"controls"`
			Rationale        string              `yaml:"rationale"`
			Owner            string              `yaml:"owner"`
		} `yaml:"mappings"`
	} `yaml:"spec"`
}

type MappingFileOptions struct {
	Strict bool
}

func ParseMappingFile(b []byte, defaultPolicyKey string, opts MappingFileOptions) ([]MappingEntry, string, []string, error) {
	var mf mappingFile
	if err := yaml.Unmarshal(b, &mf); err != nil {
		return nil, "", nil, err
	}

	if strings.TrimSpace(mf.APIVersion) == "" || strings.TrimSpace(mf.Kind) == "" {
		if opts.Strict {
			return nil, "", nil, Err("mapping file missing apiVersion/kind")
		}
	}

	warnings := []string{}
	baseKey := strings.TrimSpace(defaultPolicyKey)
	if strings.TrimSpace(mf.Spec.Defaults.PolicyKey) != "" {
		baseKey = strings.TrimSpace(mf.Spec.Defaults.PolicyKey)
	}

	out := make([]MappingEntry, 0, len(mf.Spec.Mappings))
	for _, m := range mf.Spec.Mappings {
		objName := strings.TrimSpace(m.PolicyObjectName)
		if objName == "" {
			msg := "mapping entry missing policyObjectName"
			if opts.Strict {
				return nil, "", nil, Err(msg)
			}
			warnings = append(warnings, msg)
			continue
		}
		pk := strings.TrimSpace(m.PolicyKey)
		if pk == "" {
			pk = baseKey
		}
		if pk == "" {
			pk = "default/" + objName
		}

		controls := map[FrameworkID][]string{}
		for fwStr, ids := range m.Controls {
			fw, ok := ParseFrameworkID(fwStr)
			if !ok {
				msg := fmt.Sprintf("unknown framework %q in mapping file", fwStr)
				if opts.Strict {
					return nil, "", nil, Err(msg)
				}
				warnings = append(warnings, msg)
				continue
			}
			for _, id := range ids {
				id = strings.TrimSpace(id)
				if id == "" {
					continue
				}
				if err := ValidateControlID(fw, id); err != nil {
					msg := "invalid control id in mapping file: " + err.Error()
					if opts.Strict {
						return nil, "", nil, Err(msg)
					}
					warnings = append(warnings, msg)
					continue
				}
				controls[fw] = append(controls[fw], id)
			}
		}
		for fw := range controls {
			controls[fw] = uniqueSorted(controls[fw])
		}

		ref := PolicyRef{Tenant: tenantFromPolicyKey(pk), PolicyKey: pk, PolicyObjectName: objName}
		out = append(out, MappingEntry{Policy: ref, Controls: controls, Rationale: strings.TrimSpace(m.Rationale), Owner: strings.TrimSpace(m.Owner)})
	}

	// Stable ordering.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Policy.PolicyKey == out[j].Policy.PolicyKey {
			return out[i].Policy.PolicyObjectName < out[j].Policy.PolicyObjectName
		}
		return out[i].Policy.PolicyKey < out[j].Policy.PolicyKey
	})

	return out, baseKey, warnings, nil
}
