package policy

import (
	"bytes"
	"io"
	"os"

	"gopkg.in/yaml.v2"
)

// NetworkPolicy defines a zero-trust rule
type NetworkPolicy struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec struct {
		PodSelector struct {
			MatchLabels map[string]string `yaml:"matchLabels"`
		} `yaml:"podSelector"`
		Egress []struct {
			To struct {
				PodSelector struct {
					MatchLabels map[string]string `yaml:"matchLabels"`
				} `yaml:"podSelector,omitempty"`
				IPBlock struct {
					CIDR string `yaml:"cidr"`
				} `yaml:"ipBlock,omitempty"`
			} `yaml:"to"`
			Ports []struct {
				Protocol string `yaml:"protocol"`
				Port     int    `yaml:"port"`
			} `yaml:"ports"`
		} `yaml:"egress"`
	} `yaml:"spec"`
}

// LoadFromFile reads policies from a YAML file
func LoadFromFile(filename string) ([]NetworkPolicy, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var policies []NetworkPolicy
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var policy NetworkPolicy
		if err := decoder.Decode(&policy); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		policies = append(policies, policy)
	}
	return policies, nil
}
