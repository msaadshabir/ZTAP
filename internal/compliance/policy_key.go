package compliance

import (
	"strings"
)

func tenantFromPolicyKey(policyKey string) string {
	policyKey = strings.TrimSpace(policyKey)
	if policyKey == "" {
		return "default"
	}
	parts := strings.SplitN(policyKey, "/", 2)
	if len(parts) == 1 {
		return "default"
	}
	if strings.TrimSpace(parts[0]) == "" {
		return "default"
	}
	return strings.TrimSpace(parts[0])
}
