//go:build linux

package enforcer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// RemoveEnforcement intentionally removes validated ZTAP objects. Its caller
// must hold the node agent lock. Every surviving object is verified before any
// mutation; partial removal can be retried from the durable ownership journal.
func RemoveEnforcement(ctx context.Context, bpffsRoot string) (resultErr error) {
	return removeEnforcement(ctx, bpffsRoot, nil)
}

func removeEnforcement(ctx context.Context, bpffsRoot string, afterRemove func(string)) (resultErr error) {
	if ctx == nil {
		return errors.New("cleanup context is nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := absoluteDirectoryPath(bpffsRoot, "/sys/fs/bpf")
	if err != nil {
		return err
	}
	if err := requireFilesystemType(root, bpfSuperMagic, "bpffs"); err != nil {
		return err
	}
	fd, err := openEngineDirectoryNoFollow(filepath.Join(root, "ztap"), "ZTAP cleanup directory")
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), "ztap cleanup directory")
	defer func() { resultErr = errors.Join(resultErr, directory.Close()) }()
	if err := trustedPinDirectory(directory); err != nil {
		return err
	}
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	spec, err := loadEngine()
	if err != nil {
		return err
	}
	durableMapSpecs(spec)
	maps, err := openDurableMaps(directory, spec, true)
	if err != nil {
		return fmt.Errorf("validate cleanup ownership: %w", err)
	}
	defer func() {
		for _, m := range maps {
			_ = m.Close()
		}
	}()
	zero := uint32(0)
	var metadata durableMetadata
	if err := maps[durableMetadataPin].Lookup(&zero, &metadata); err != nil {
		return err
	}
	names := durableMapNames(spec)
	// Missing map pins can still have live kernel references. Reopen by the
	// recorded ID for program-reference verification without creating objects.
	for index, name := range names {
		if maps[name] != nil {
			continue
		}
		m, err := ebpf.NewMapFromID(ebpf.MapID(metadata.MapIDs[index]))
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return err
		}
		if err := spec.Maps[name].Compatible(m); err != nil {
			_ = m.Close()
			return err
		}
		maps[name] = m
	}
	owners := make(map[uint64]WorkloadIdentity)
	if m := maps[ownerMapName]; m != nil {
		var id uint64
		var value durableOwner
		iter := m.Iterate()
		for iter.Next(&id, &value) {
			owner, err := ownerFromDisk(value)
			if err != nil || id != owner.CgroupID {
				return errors.New("corrupt cleanup ownership metadata")
			}
			owners[id] = owner
		}
		if err := iter.Err(); err != nil {
			return err
		}
	}
	registry := make(map[uint32]durableProgram)
	guards := make(map[uint64]durableGuardOwner)
	if m := maps[guardOwnerMapName]; m != nil {
		var id uint64
		var owner durableGuardOwner
		iter := m.Iterate()
		for iter.Next(&id, &owner) {
			if id == 0 || id != owner.CgroupID || owner.Complete > 1 {
				return errors.New("corrupt guard cleanup ownership")
			}
			guards[id] = owner
		}
		if err := iter.Err(); err != nil {
			return err
		}
	}
	if m := maps[programRegistryName]; m != nil {
		var id uint32
		var value durableProgram
		iter := m.Iterate()
		for iter.Next(&id, &value) {
			registry[id] = value
		}
		if err := iter.Err(); err != nil {
			return err
		}
	}
	var linkPins, programPins, mapPins []string
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		if spec.Maps[name] != nil {
			mapPins = append(mapPins, name)
			continue
		}
		if strings.HasPrefix(name, "program_") {
			id, err := strconv.ParseUint(strings.TrimPrefix(name, "program_"), 10, 32)
			record, known := registry[uint32(id)]
			if err != nil || !known || name != programPinName(ebpf.ProgramID(id)) {
				return errors.New("program pin is not in the durable registry")
			}
			expected := spec.Programs[strings.TrimRight(string(record.Name[:]), "\x00")]
			if expected == nil || record.Semantics != durableSemantics || record.Attach != uint32(expected.AttachType) {
				return errors.New("foreign cleanup program generation")
			}
			path, err := trustedPinAt(directory, name)
			if err != nil {
				return err
			}
			program, err := ebpf.LoadPinnedProgram(path, nil)
			if err != nil {
				return err
			}
			info, infoErr := program.Info()
			if infoErr == nil {
				kernelID, ok := info.ID()
				if !ok || uint64(kernelID) != id || info.Tag != strings.TrimRight(string(record.Tag[:]), "\x00") {
					infoErr = errors.New("foreign cleanup program object")
				} else {
					infoErr = verifyProgramMaps(program, expected, maps)
				}
			}
			closeErr := program.Close()
			if err := errors.Join(infoErr, closeErr); err != nil {
				return err
			}
			programPins = append(programPins, name)
			continue
		}
		if strings.HasPrefix(name, "subject_") || strings.HasPrefix(name, "guard_") {
			parts := strings.Split(name, "_")
			if len(parts) != 3 {
				return errors.New("invalid subject link pin")
			}
			id, err := strconv.ParseUint(parts[1], 10, 64)
			owner, known := owners[id]
			direction := 0
			attach := ebpf.AttachCGroupInetEgress
			if parts[2] == "ingress" {
				direction = 1
				attach = ebpf.AttachCGroupInetIngress
			}
			expectedPin := subjectPinName(id, direction)
			expectedProgram := [2]string{"ztap_egress", "ztap_ingress"}[direction]
			if parts[0] == "guard" {
				guard, found := guards[id]
				known = found
				owner.CgroupID = guard.CgroupID
				if parts[2] == "socket" {
					direction = 2
					attach = ebpf.AttachCGroupInetSockCreate
				}
				expectedPin = guardPinName(id, direction)
				expectedProgram = guardProgramNames[direction]
			}
			if err != nil || !known || name != expectedPin {
				return errors.New("subject link pin has no verified ownership")
			}
			path, err := trustedPinAt(directory, name)
			if err != nil {
				return err
			}
			handle, err := link.LoadPinnedLink(path, nil)
			if err != nil {
				return err
			}
			info, infoErr := handle.Info()
			if infoErr == nil {
				cgroup := info.Cgroup()
				record, known := registry[uint32(info.Program)]
				if cgroup == nil || (cgroup.CgroupId != owner.CgroupID && cgroup.CgroupId != 0) || uint32(cgroup.AttachType) != uint32(attach) || !known || record.Attach != uint32(attach) || record.Semantics != durableSemantics || strings.TrimRight(string(record.Name[:]), "\x00") != expectedProgram {
					infoErr = errors.New("foreign cleanup link target or program")
				}
			}
			closeErr := handle.Close()
			if err := errors.Join(infoErr, closeErr); err != nil {
				return err
			}
			linkPins = append(linkPins, name)
		}
		// Unrelated entries are preserved. They never become cleanup targets.
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	metadata.Flags = 1
	if err := maps[durableMetadataPin].Put(&zero, &metadata); err != nil {
		return err
	}
	// Remove links, then programs, then maps, with the journal last. Keeping
	// records until their referenced pins are gone makes every step retryable.
	slices.Sort(linkPins)
	slices.Sort(programPins)
	slices.Sort(mapPins)
	mapPins = slices.DeleteFunc(mapPins, func(name string) bool { return name == durableMetadataPin })
	ordered := append(append(append(linkPins, programPins...), mapPins...), durableMetadataPin)
	for _, name := range ordered {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := removeOwnedEnginePinAt(fd, name); err != nil {
			return fmt.Errorf("remove owned enforcement pin %s: %w", name, err)
		}
		if afterRemove != nil {
			afterRemove(name)
		}
	}
	return nil
}
