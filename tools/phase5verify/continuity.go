package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

func validateHostedContinuityRolling(values map[string][]string, path string) error {
	allowed := make(map[string]struct{}, len(hostedRollingEvidenceKeys)+10)
	for key := range hostedRollingEvidenceKeys {
		if key != "fail_open_start_ns" && key != "fail_open_end_ns" && key != "fail_open_interval_ms" {
			allowed[key] = struct{}{}
		}
	}
	for _, key := range []string{"schema_version", "kernel_release", "containerd_version", "outage_started_ns", "outage_finished_ns", "ingress_allowed", "egress_allowed", "ingress_prohibited", "egress_prohibited"} {
		allowed[key] = struct{}{}
	}
	if err := validateHostedKeySet(values, path, allowed); err != nil {
		return err
	}
	for key, want := range map[string]string{"schema_version": "2", "baseline_selected_smoke_client": "blocked", "old_namespace": hostedAgentNamespace, "replacement_namespace": hostedAgentNamespace, "old_ready": "true", "replacement_ready": "true", "ingress_prohibited": "0", "egress_prohibited": "0"} {
		if err := requireHostedValue(values, path, key, want); err != nil {
			return err
		}
	}
	read := func(key string) (string, error) { return hostedSingleValue(values, path, key) }
	oldPod, err := read("old_pod")
	if err != nil {
		return err
	}
	newPod, err := read("replacement_pod")
	if err != nil {
		return err
	}
	if !validHostedAgentPodName(oldPod) || !validHostedAgentPodName(newPod) || oldPod == newPod {
		return errors.New("continuity evidence requires different valid DaemonSet Pods")
	}
	oldUID, err := read("old_uid")
	if err != nil {
		return err
	}
	newUID, err := read("replacement_uid")
	if err != nil {
		return err
	}
	if oldUID == "" || newUID == "" || oldUID == newUID {
		return errors.New("continuity evidence requires different nonempty Pod UIDs")
	}
	node, err := read("smoke_client_node")
	if err != nil {
		return err
	}
	for _, key := range []string{"old_node", "replacement_node"} {
		if err := requireHostedValue(values, path, key, node); err != nil {
			return err
		}
	}
	for _, key := range []string{"kernel_release", "containerd_version"} {
		value, err := read(key)
		if err != nil {
			return err
		}
		if value == "" {
			return fmt.Errorf("%s is missing %s", path, key)
		}
	}
	start, err := parseHostedUint(values, path, "outage_started_ns")
	if err != nil {
		return err
	}
	end, err := parseHostedUint(values, path, "outage_finished_ns")
	if err != nil {
		return err
	}
	rollout, err := parseHostedUint(values, path, "rollout_started_ns")
	if err != nil {
		return err
	}
	observed, err := parseHostedUint(values, path, "replacement_observed_ns")
	if err != nil {
		return err
	}
	createdText, err := read("replacement_created_at")
	if err != nil {
		return err
	}
	created, err := time.Parse(time.RFC3339Nano, createdText)
	if err != nil || created.UnixNano() <= 0 {
		return errors.New("continuity replacement creation time is invalid")
	}
	resolution := hostedTimestampResolutionNS(createdText)
	if start == 0 || end <= start || end-start < uint64(6*time.Second) || rollout < start || rollout > end || observed < rollout || observed > end || uint64(created.UnixNano()) > observed || uint64(created.UnixNano())+resolution <= rollout {
		return errors.New("continuity outage and replacement timestamps are inconsistent")
	}
	for _, direction := range []string{"ingress", "egress"} {
		total, err := parseHostedUint(values, path, direction+"_allowed")
		if err != nil {
			return err
		}
		if total == 0 {
			return errors.New("continuity lacks allowed controls")
		}
		raw := filepath.Join(filepath.Dir(path), "rolling-continuity-"+direction+".jsonl")
		if err := validateHostedContinuityPackets(raw, start, rollout, end, total); err != nil {
			return err
		}
	}
	return validateHostedGuardEvidence(filepath.Dir(path))
}

type hostedContinuityReport struct {
	SchemaVersion      int    `json:"schema_version"`
	TimestampNS        int64  `json:"timestamp_ns"`
	StartedNS          int64  `json:"started_ns"`
	Allowed            uint64 `json:"allowed"`
	Prohibited         uint64 `json:"prohibited"`
	AllowedAttempts    uint64 `json:"allowed_attempts"`
	ProhibitedAttempts uint64 `json:"prohibited_attempts"`
}

func validateHostedContinuityPackets(path string, start, rollout, end, total uint64) (returnErr error) {
	file, err := openRegularFile(path, "continuity packet evidence")
	if err != nil {
		return err
	}
	defer func() { returnErr = errors.Join(returnErr, file.Close()) }()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	var previous hostedContinuityReport
	var baseline, during, after hostedContinuityReport
	count := 0
	for scanner.Scan() {
		data := scanner.Bytes()
		if err := validateStrictJSONKeys(data); err != nil {
			return err
		}
		var r hostedContinuityReport
		if err := validateRequiredJSONFields(data, &r); err != nil {
			return err
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&r); err != nil {
			return err
		}
		if r.SchemaVersion != 2 || r.TimestampNS <= 0 || r.StartedNS <= 0 || r.StartedNS >= r.TimestampNS || r.Prohibited != 0 || r.Allowed > r.AllowedAttempts {
			return errors.New("invalid continuity packet record or observed prohibited connection")
		}
		if count > 0 && (r.StartedNS != previous.StartedNS || r.TimestampNS <= previous.TimestampNS || r.Allowed < previous.Allowed || r.ProhibitedAttempts < previous.ProhibitedAttempts || r.AllowedAttempts < previous.AllowedAttempts) {
			return errors.New("nonmonotonic continuity packet record")
		}
		switch {
		case uint64(r.TimestampNS) < start:
			baseline = r
		case uint64(r.TimestampNS) < rollout:
			during = r
		case uint64(r.TimestampNS) <= end:
			after = r
		}
		previous = r
		count++
		if count > 2000 {
			return errors.New("too many continuity records")
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if count < 8 || previous.Allowed != total || baseline.Allowed == 0 || baseline.ProhibitedAttempts == 0 || during.Allowed <= baseline.Allowed || during.ProhibitedAttempts <= baseline.ProhibitedAttempts || after.Allowed <= during.Allowed || after.ProhibitedAttempts <= during.ProhibitedAttempts {
		return errors.New("continuity packet records lack baseline, sustained outage, recovery controls, or matching totals")
	}
	return nil
}
