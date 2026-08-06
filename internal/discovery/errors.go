package discovery

import (
	"fmt"
)

// NoMatchesError indicates that a lookup succeeded but yielded zero results.
//
// It is intentionally distinguishable via the NoMatches() marker method so
// higher-level components (like policy resolution) can treat it as an empty
// result set instead of a fatal error.
type NoMatchesError struct {
	Resource string
	Scope    string
	Labels   map[string]string
}

func (e *NoMatchesError) Error() string {
	resource := e.Resource
	if resource == "" {
		resource = "targets"
	}
	if e.Scope != "" {
		return fmt.Sprintf("no %s found matching labels in %s: %v", resource, e.Scope, e.Labels)
	}
	return fmt.Sprintf("no %s found matching labels: %v", resource, e.Labels)
}

func (e *NoMatchesError) NoMatches() bool {
	return true
}
