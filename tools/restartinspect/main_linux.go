//go:build linux

// restartinspect records kernel evidence for the disposable kind release gate.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
)

type activeConfig struct {
	Slot, Reserved uint32
	Epoch          uint64
}
type guardKey struct {
	Cgroup, Epoch       uint64
	Direction, Reserved uint32
}

func run() error {
	root := flag.String("root", "/sys/fs/bpf/ztap", "owned durable map directory")
	cgroup := flag.Uint64("cgroup", 0, "actual container socket cgroup ID")
	flag.Parse()
	if *cgroup == 0 {
		return errors.New("a cgroup ID is required")
	}
	outer, err := ebpf.LoadPinnedMap(filepath.Join(*root, "active_config"), nil)
	if err != nil {
		return err
	}
	defer func() { _ = outer.Close() }()
	zero, id := uint32(0), uint32(0)
	if err := outer.Lookup(&zero, &id); err != nil {
		return err
	}
	var config activeConfig
	found := false
	for slot := range 2 {
		inner, err := ebpf.LoadPinnedMap(filepath.Join(*root, fmt.Sprintf("configuration_%d", slot)), nil)
		if err != nil {
			return err
		}
		info, err := inner.Info()
		if err != nil {
			_ = inner.Close()
			return err
		}
		kernelID, ok := info.ID()
		if ok && uint32(kernelID) == id {
			err = inner.Lookup(&zero, &config)
			found = true
		}
		_ = inner.Close()
		if err != nil {
			return err
		}
	}
	if !found || config.Epoch == 0 {
		return errors.New("no committed owned configuration")
	}
	blocks, err := ebpf.LoadPinnedMap(filepath.Join(*root, "guard_blocks"), nil)
	if err != nil {
		return err
	}
	defer func() { _ = blocks.Close() }()
	counts := map[uint32]uint64{}
	var key guardKey
	var values []uint64
	iter := blocks.Iterate()
	for iter.Next(&key, &values) {
		if key.Cgroup == *cgroup && key.Epoch == config.Epoch {
			for _, value := range values {
				counts[key.Direction] += value
			}
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(struct {
		Schema  int    `json:"schema_version"`
		Cgroup  uint64 `json:"cgroup_id"`
		Epoch   uint64 `json:"policy_epoch"`
		Ingress uint64 `json:"blocked_ingress"`
		Egress  uint64 `json:"blocked_egress"`
	}{2, *cgroup, config.Epoch, counts[1], counts[0]})
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
