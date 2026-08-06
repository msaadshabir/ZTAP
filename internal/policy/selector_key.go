package policy

import (
	"fmt"
	"slices"
	"strings"
)

// SelectorKey returns a deterministic string representation of a label selector.
//
// It is used for stable caching and watch de-duplication.
func SelectorKey(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(labels[k])
	}
	return b.String()
}

// SelectorKeySpec returns a deterministic string representation of a selector spec.
func SelectorKeySpec(selector PodSelectorSpec) string {
	labelKey := SelectorKey(selector.MatchLabels)
	if len(selector.MatchExpressions) == 0 {
		return labelKey
	}

	exprs := make([]string, 0, len(selector.MatchExpressions))
	for _, expr := range selector.MatchExpressions {
		values := append([]string(nil), expr.Values...)
		slices.Sort(values)
		exprs = append(exprs, fmt.Sprintf("%s:%s:%s", expr.Key, expr.Operator, strings.Join(values, ",")))
	}
	slices.Sort(exprs)

	var b strings.Builder
	if labelKey != "" {
		b.WriteString(labelKey)
		b.WriteByte('|')
	}
	b.WriteString(strings.Join(exprs, "|"))
	return b.String()
}
