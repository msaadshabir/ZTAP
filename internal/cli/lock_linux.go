//go:build linux

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// openZTAPLock creates or opens a node-local lock file without following
// symlinked path components. The run directory is created one component at a
// time so an attacker cannot redirect MkdirAll through an existing symlink.
func openZTAPLock(runDir, lockName, owner string) (result *os.File, resultPath string, resultErr error) {
	runDir = strings.TrimSpace(runDir)
	if runDir == "" {
		runDir = "/run/ztap"
	}
	if lockName == "" || filepath.Base(lockName) != lockName {
		return nil, "", fmt.Errorf("invalid %s lock name %q", owner, lockName)
	}
	absRunDir, err := filepath.Abs(runDir)
	if err != nil {
		return nil, "", fmt.Errorf("resolve %s run directory %q: %w", owner, runDir, err)
	}
	absRunDir = filepath.Clean(absRunDir)
	lockPath := filepath.Join(absRunDir, lockName)
	directoryFD, err := openLockDirectory(absRunDir, owner)
	if err != nil {
		return nil, "", err
	}
	defer func() {
		if err := unix.Close(directoryFD); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close %s run directory %q: %w", owner, absRunDir, err))
			if result != nil {
				resultErr = errors.Join(resultErr, result.Close())
				result = nil
				resultPath = ""
			}
		}
	}()

	fd, err := unix.Openat(directoryFD, lockName, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, "", fmt.Errorf("%s lock %q is a symlink", owner, lockPath)
		}
		if errors.Is(err, unix.EISDIR) {
			return nil, "", fmt.Errorf("%s lock %q is not a regular file", owner, lockPath)
		}
		return nil, "", fmt.Errorf("open %s lock %q: %w", owner, lockPath, err)
	}
	file := os.NewFile(uintptr(fd), lockPath)
	if file == nil {
		_ = unix.Close(fd)
		return nil, "", fmt.Errorf("open %s lock %q returned no file handle", owner, lockPath)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, "", errors.Join(
			fmt.Errorf("stat %s lock %q: %w", owner, lockPath, err),
			file.Close(),
		)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, "", errors.Join(
			fmt.Errorf("%s lock %q is not a regular file", owner, lockPath),
			file.Close(),
		)
	}
	if uint64(stat.Uid) != uint64(os.Geteuid()) {
		return nil, "", errors.Join(fmt.Errorf("%s lock %q has an untrusted owner", owner, lockPath), file.Close())
	}
	// Even read permission lets another user flock the file and deny startup.
	if stat.Mode&0o077 != 0 {
		return nil, "", errors.Join(fmt.Errorf("%s lock %q has unsafe permissions; require owner-only access", owner, lockPath), file.Close())
	}
	if stat.Nlink != 1 {
		return nil, "", errors.Join(fmt.Errorf("%s lock %q has a hard link", owner, lockPath), file.Close())
	}
	return file, lockPath, nil
}

func openLockDirectory(path, owner string) (int, error) {
	return openDirectoryNoFollow(path, owner, true)
}

func openExistingDirectory(path, owner string) (int, error) {
	return openDirectoryNoFollow(path, owner, false)
}

func openDirectoryNoFollow(path, owner string, createMissing bool) (int, error) {
	if !filepath.IsAbs(path) {
		return -1, fmt.Errorf("%s directory %q is not absolute", owner, path)
	}
	path = filepath.Clean(path)
	rootFD, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, fmt.Errorf("open root for %s directory %q: %w", owner, path, err)
	}
	currentFD := rootFD
	if createMissing {
		if err := validateLockDirectory(rootFD, "/", owner, path == "/"); err != nil {
			_ = unix.Close(rootFD)
			return -1, err
		}
	}
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for index, component := range components {
		if component == "" || component == "." {
			continue
		}
		nextFD, openErr := unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(openErr, unix.ENOENT) && createMissing {
			if mkdirErr := unix.Mkdirat(currentFD, component, 0o750); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = unix.Close(currentFD)
				return -1, fmt.Errorf("create %s directory component %q: %w", owner, component, mkdirErr)
			}
			nextFD, openErr = unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			if errors.Is(openErr, unix.ELOOP) ||
				(errors.Is(openErr, unix.ENOTDIR) && isSymlinkEntryAt(currentFD, component)) {
				_ = unix.Close(currentFD)
				return -1, fmt.Errorf("%s directory %q contains symlink component %q", owner, path, component)
			}
			_ = unix.Close(currentFD)
			if errors.Is(openErr, unix.ENOTDIR) {
				return -1, fmt.Errorf("%s directory %q component %q is not a directory", owner, path, component)
			}
			return -1, fmt.Errorf("inspect %s directory component %q: %w", owner, component, openErr)
		}
		if createMissing {
			if err := validateLockDirectory(nextFD, component, owner, index == len(components)-1); err != nil {
				_ = unix.Close(nextFD)
				_ = unix.Close(currentFD)
				return -1, err
			}
		}
		_ = unix.Close(currentFD)
		currentFD = nextFD
	}
	return currentFD, nil
}

// Validate the opened directory before creating entries or traversing further.
// A writable ancestor could let another user replace the lock directory and
// start a second agent with a different lock inode. A trusted sticky ancestor
// (such as /tmp) protects its owner-controlled children; the final directory
// must always forbid group and other writes.
func validateLockDirectory(fd int, component, owner string, final bool) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("inspect %s directory component %q: %w", owner, component, err)
	}
	if stat.Uid != 0 && uint64(stat.Uid) != uint64(os.Geteuid()) {
		return fmt.Errorf("%s directory component %q has an untrusted owner", owner, component)
	}
	if stat.Mode&0o022 != 0 && (final || stat.Mode&unix.S_ISVTX == 0) {
		return fmt.Errorf("%s directory component %q has unsafe permissions; forbid group and other writes", owner, component)
	}
	return nil
}

func isSymlinkEntryAt(directoryFD int, name string) bool {
	var stat unix.Stat_t
	if err := unix.Fstatat(directoryFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return false
	}
	return stat.Mode&unix.S_IFMT == unix.S_IFLNK
}
