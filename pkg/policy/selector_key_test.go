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
