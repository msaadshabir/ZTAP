package policy

import "testing"

func TestSelectorKey_Empty(t *testing.T) {
	if got := SelectorKey(nil); got != "" {
		t.Fatalf("expected empty key for nil map, got %q", got)
	}
	if got := SelectorKey(map[string]string{}); got != "" {
		t.Fatalf("expected empty key for empty map, got %q", got)
	}
}

func TestSelectorKey_StableOrdering(t *testing.T) {
	labels := map[string]string{"b": "2", "a": "1"}
	if got := SelectorKey(labels); got != "a=1,b=2" {
		t.Fatalf("expected stable ordering, got %q", got)
	}
}

func TestSelectorKeySpec_WithExpressions(t *testing.T) {
	selector := PodSelectorSpec{
		MatchLabels: map[string]string{"app": "web"},
		MatchExpressions: []LabelSelectorRequirement{
			{Key: "tier", Operator: "In", Values: []string{"api", "web"}},
		},
	}
	if got := SelectorKeySpec(selector); got != "app=web|tier:In:api,web" {
		t.Fatalf("expected selector key with expressions, got %q", got)
	}
}
