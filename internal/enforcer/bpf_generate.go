//go:generate go run ../../tools/bpfgen

// Package-level go:generate directive kept in a build-tag-free file so it
// runs on any host (tools/bpfgen runs bpf2go and inlines the object bytes).
package enforcer
