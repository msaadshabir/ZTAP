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

type guardKernelEvidence struct {
	Schema  int    `json:"schema_version"`
	Cgroup  uint64 `json:"cgroup_id"`
	Epoch   uint64 `json:"policy_epoch"`
	Ingress uint64 `json:"blocked_ingress"`
	Egress  uint64 `json:"blocked_egress"`
}

type guardMetadata struct {
	Schema                int                 `json:"schema_version"`
	Mode                  string              `json:"mode"`
	Kernel                string              `json:"kernel"`
	Runtime               string              `json:"containerd"`
	PodUID                string              `json:"pod_uid"`
	Container             string              `json:"container_id"`
	Cgroup                uint64              `json:"cgroup_id"`
	Path                  string              `json:"cgroup_path"`
	Start                 uint64              `json:"observation_started_ns"`
	End                   uint64              `json:"observation_finished_ns"`
	Counters              guardKernelEvidence `json:"kernel_evidence"`
	ReplacementUID        string              `json:"replacement_uid"`
	OldController         string              `json:"old_controller_container_id"`
	ReplacementController string              `json:"replacement_container_id"`
}

type guardPacketReport struct {
	SchemaVersion      int    `json:"schema_version"`
	TimestampNS        int64  `json:"timestamp_ns"`
	StartedNS          int64  `json:"started_ns"`
	Allowed            uint64 `json:"allowed"`
	Prohibited         uint64 `json:"prohibited"`
	AllowedAttempts    uint64 `json:"allowed_attempts"`
	ProhibitedAttempts uint64 `json:"prohibited_attempts"`
	Unknown            uint64 `json:"unknown_tcp_connections"`
}

func guardPacketRecords(path string, before bool) ([]guardPacketReport, error) {
	text, err := readHostedEvidence(path)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(bytes.NewBufferString(text))
	scanner.Buffer(make([]byte, 4096), 64<<10)
	var records []guardPacketReport
	for scanner.Scan() {
		data := scanner.Bytes()
		if err := validateStrictJSONKeys(data); err != nil {
			return nil, err
		}
		var record guardPacketReport
		if err := validateRequiredJSONFields(data, &record); err != nil {
			return nil, err
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&record); err != nil {
			return nil, err
		}
		if record.SchemaVersion != 2 || record.TimestampNS <= record.StartedNS || record.StartedNS <= 0 || record.Unknown != 0 || record.Prohibited != 0 || record.Allowed > record.AllowedAttempts || (before && record.Allowed != 0) {
			return nil, errors.New("guard evidence contains invalid or premature/prohibited TCP traffic")
		}
		if len(records) > 0 {
			previous := records[len(records)-1]
			if record.StartedNS != previous.StartedNS || record.TimestampNS < previous.TimestampNS || record.Allowed < previous.Allowed || record.AllowedAttempts < previous.AllowedAttempts || record.ProhibitedAttempts < previous.ProhibitedAttempts {
				return nil, errors.New("guard evidence counters or timestamps regressed")
			}
		}
		records = append(records, record)
		if len(records) > 2000 {
			return nil, errors.New("too many guard evidence records")
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(records) < 8 || records[len(records)-1].AllowedAttempts == 0 || records[len(records)-1].ProhibitedAttempts == 0 {
		return nil, errors.New("guard evidence lacks sustained traffic attempts")
	}
	return records, nil
}

func validateHostedGuardEvidence(directory string) error {
	var kernel, runtime string
	for _, mode := range []string{"pause", "term", "kill", "api"} {
		root := filepath.Join(directory, "restart-guard-evidence")
		var metadata guardMetadata
		if err := readEvidence(filepath.Join(root, mode+".json"), &metadata); err != nil {
			return err
		}
		if metadata.Schema != 2 || metadata.Mode != mode || metadata.Kernel == "" || metadata.Runtime == "" || metadata.PodUID == "" || metadata.ReplacementUID == "" || !validHostedContainerID(metadata.Container) || !validHostedContainerCgroupPath(metadata.Path, metadata.Container) || metadata.Cgroup == 0 || metadata.Start == 0 || metadata.End <= metadata.Start || metadata.End-metadata.Start < uint64(3*time.Second) || !validHostedContainerID(metadata.OldController) || !validHostedContainerID(metadata.ReplacementController) {
			return fmt.Errorf("invalid %s guard identity or outage metadata", mode)
		}
		if (mode == "term" || mode == "kill") && metadata.OldController == metadata.ReplacementController {
			return errors.New("terminated controller was not replaced")
		}
		if kernel == "" {
			kernel, runtime = metadata.Kernel, metadata.Runtime
		}
		if metadata.Kernel != kernel || metadata.Runtime != runtime {
			return errors.New("guard evidence mixes kernel/runtime environments")
		}
		var counters guardKernelEvidence
		if err := readEvidence(filepath.Join(root, mode+"-kernel.json"), &counters); err != nil {
			return err
		}
		if counters != metadata.Counters || counters.Schema != 2 || counters.Cgroup != metadata.Cgroup || counters.Epoch == 0 || counters.Ingress == 0 || counters.Egress == 0 {
			return errors.New("guard kernel evidence has a mismatched identity, epoch, or direction")
		}
		for _, direction := range []string{"ingress", "egress"} {
			before, err := guardPacketRecords(filepath.Join(root, mode+"-"+direction+"-before.jsonl"), true)
			if err != nil {
				return err
			}
			after, err := guardPacketRecords(filepath.Join(root, mode+"-"+direction+".jsonl"), false)
			if err != nil {
				return err
			}
			if len(after) < len(before) || uint64(before[len(before)-1].TimestampNS) > metadata.End || uint64(before[len(before)-1].TimestampNS) < metadata.Start+uint64(2*time.Second) || after[len(after)-1].Allowed == 0 || after[len(after)-1].AllowedAttempts <= before[len(before)-1].AllowedAttempts {
				return errors.New("guard evidence lacks the outage interval or recovered allowed control")
			}
			for index, record := range before {
				if record != after[index] {
					return errors.New("guard pre-recovery evidence is not a prefix of the final transcript")
				}
			}
		}
	}
	var uninstall struct {
		Schema    int    `json:"schema_version"`
		Kernel    string `json:"kernel"`
		Runtime   string `json:"containerd"`
		Competing bool   `json:"competing_agent_refused"`
		Preserved bool   `json:"daemonset_deletion_preserved_both_directions"`
		Removed   bool   `json:"explicit_cleanup_removed_enforcement"`
		Retry     bool   `json:"cleanup_retry_passed"`
	}
	if err := readEvidence(filepath.Join(directory, "explicit-uninstall-evidence.json"), &uninstall); err != nil {
		return err
	}
	if uninstall.Schema != 2 || uninstall.Kernel != kernel || uninstall.Runtime != runtime || !uninstall.Competing || !uninstall.Preserved || !uninstall.Removed || !uninstall.Retry {
		return errors.New("missing or inconsistent explicit uninstall evidence")
	}
	var upgrade struct {
		Schema     int    `json:"schema_version"`
		Original   string `json:"original_image"`
		Compatible string `json:"compatible_image"`
		Rollback   bool   `json:"rollback_completed"`
	}
	if err := readEvidence(filepath.Join(directory, "rolling-compatible-upgrade.json"), &upgrade); err != nil {
		return err
	}
	if upgrade.Schema != 2 || upgrade.Original == "" || upgrade.Compatible == "" || upgrade.Original == upgrade.Compatible || !upgrade.Rollback {
		return errors.New("missing compatible image replacement/rollback evidence")
	}
	return nil
}
