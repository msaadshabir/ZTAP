package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeGuardEvidenceFixture(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	root := filepath.Join(directory, "restart-guard-evidence")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(path string, value any) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	base := time.Unix(100, 0).UnixNano()
	for index, mode := range []string{"pause", "term", "kill", "api"} {
		cid := fmt.Sprintf("%064x", index+1)
		counters := guardKernelEvidence{Schema: 2, Cgroup: uint64(index + 10), Epoch: 3, Ingress: 20, Egress: 30}
		meta := guardMetadata{Schema: 2, Mode: mode, Kernel: "test-kernel", Runtime: "test-runtime", PodUID: mode, Container: cid, Cgroup: counters.Cgroup, Path: "/sys/fs/cgroup/kubepods.slice/cri-containerd-" + cid + ".scope", Start: uint64(base), End: uint64(base + 3100*int64(time.Millisecond)), Counters: counters, ReplacementUID: "agent", OldController: strings.Repeat("a", 64), ReplacementController: strings.Repeat("b", 64)}
		write(filepath.Join(root, mode+".json"), meta)
		write(filepath.Join(root, mode+"-kernel.json"), counters)
		for _, direction := range []string{"ingress", "egress"} {
			var before strings.Builder
			for sample := range 12 {
				r := guardPacketReport{SchemaVersion: 2, StartedNS: base - int64(time.Second), TimestampNS: base + int64(sample)*250*int64(time.Millisecond), AllowedAttempts: uint64(sample + 1), ProhibitedAttempts: uint64(sample + 1)}
				payload, err := json.Marshal(r)
				if err != nil {
					t.Fatal(err)
				}
				before.Write(payload)
				before.WriteByte('\n')
			}
			if err := os.WriteFile(filepath.Join(root, mode+"-"+direction+"-before.jsonl"), []byte(before.String()), 0o600); err != nil {
				t.Fatal(err)
			}
			last := guardPacketReport{SchemaVersion: 2, StartedNS: base - int64(time.Second), TimestampNS: base + 4*int64(time.Second), Allowed: 1, AllowedAttempts: 20, ProhibitedAttempts: 20}
			payload, err := json.Marshal(last)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, mode+"-"+direction+".jsonl"), append([]byte(before.String()), append(payload, '\n')...), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	write(filepath.Join(directory, "explicit-uninstall-evidence.json"), map[string]any{"schema_version": 2, "kernel": "test-kernel", "containerd": "test-runtime", "competing_agent_refused": true, "daemonset_deletion_preserved_both_directions": true, "explicit_cleanup_removed_enforcement": true, "cleanup_retry_passed": true})
	write(filepath.Join(directory, "rolling-compatible-upgrade.json"), map[string]any{"schema_version": 2, "original_image": "original", "compatible_image": "compatible", "rollback_completed": true})
	return directory
}

func TestGuardEvidenceRejectsMissingZeroAndTransientEarlyTraffic(t *testing.T) {
	for _, mode := range []string{"missing-zero", "early-connection", "wrong-cgroup"} {
		t.Run(mode, func(t *testing.T) {
			root := writeGuardEvidenceFixture(t)
			if err := validateHostedGuardEvidence(root); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "restart-guard-evidence", "pause-egress.jsonl")
			if mode == "wrong-cgroup" {
				path = filepath.Join(root, "restart-guard-evidence", "pause-kernel.json")
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "missing-zero":
				data = []byte(strings.Replace(string(data), `,"unknown_tcp_connections":0`, "", 1))
			case "early-connection":
				data = []byte(strings.Replace(string(data), `"unknown_tcp_connections":0`, `"unknown_tcp_connections":1`, 1))
			case "wrong-cgroup":
				data = []byte(strings.Replace(string(data), `"cgroup_id":10`, `"cgroup_id":11`, 1))
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := validateHostedGuardEvidence(root); err == nil {
				t.Fatal("incomplete or contradictory guard evidence was accepted")
			}
		})
	}
}
