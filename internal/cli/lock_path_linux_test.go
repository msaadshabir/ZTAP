//go:build linux

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestZTAPLocksRejectSymlinkedRunDirectories(t *testing.T) {
	target := t.TempDir()
	linkParent := t.TempDir()
	linkedRunDir := filepath.Join(linkParent, "run")
	if err := os.Symlink(target, linkedRunDir); err != nil {
		t.Fatalf("symlink run directory: %v", err)
	}

	for _, test := range []struct {
		name    string
		acquire func(string) (func() error, error)
	}{
		{name: "agent", acquire: acquireNativeAgentLock},
		{name: "flow reader", acquire: acquireFlowReaderLock},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := test.acquire(linkedRunDir); err == nil || !strings.Contains(err.Error(), "symlink") {
				t.Fatalf("acquire through symlinked run directory error = %v, want symlink rejection", err)
			}
		})
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatalf("read symlink target: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("symlink target received lock entries: %v", entries)
	}
}

func TestZTAPDirectoryOpenRejectsRelativePaths(t *testing.T) {
	if fd, err := openExistingDirectory("relative/dir", "test"); err == nil {
		_ = unix.Close(fd)
		t.Fatal("openExistingDirectory accepted a relative path")
	} else if !strings.Contains(err.Error(), "not absolute") {
		t.Fatalf("relative directory error = %v, want absolute-path validation", err)
	}
}

func TestZTAPLocksRejectSymlinkedLockFiles(t *testing.T) {
	for _, test := range []struct {
		name     string
		lockName string
		acquire  func(string) (func() error, error)
	}{
		{name: "agent", lockName: "agent.lock", acquire: acquireNativeAgentLock},
		{name: "flow reader", lockName: "flows.lock", acquire: acquireFlowReaderLock},
	} {
		t.Run(test.name, func(t *testing.T) {
			runDir := t.TempDir()
			target := filepath.Join(t.TempDir(), "redirected.lock")
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatalf("create redirected lock: %v", err)
			}
			if err := os.Symlink(target, filepath.Join(runDir, test.lockName)); err != nil {
				t.Fatalf("symlink lock file: %v", err)
			}
			if _, err := test.acquire(runDir); err == nil || !strings.Contains(err.Error(), "symlink") {
				t.Fatalf("acquire through symlinked lock file error = %v, want symlink rejection", err)
			}
		})
	}
}

func TestZTAPLocksRejectUnsafeDirectoriesAndFiles(t *testing.T) {
	for _, lock := range []struct {
		name    string
		acquire func(string) (func() error, error)
	}{
		{name: "agent", acquire: acquireNativeAgentLock},
		{name: "flows", acquire: acquireFlowReaderLock},
	} {
		for _, attack := range []string{"writable-directory", "writable-parent", "readable-file", "writable-file", "hard-link", "fifo"} {
			t.Run(lock.name+"/"+attack, func(t *testing.T) {
				parent := t.TempDir()
				runDir := filepath.Join(parent, "run")
				if err := os.Mkdir(runDir, 0o700); err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(runDir, lock.name+".lock")
				want := "permissions"
				switch attack {
				case "writable-directory":
					if err := os.Chmod(runDir, 0o777); err != nil {
						t.Fatal(err)
					}
				case "writable-parent":
					if err := os.Chmod(parent, 0o770); err != nil {
						t.Fatal(err)
					}
				case "readable-file", "writable-file", "hard-link":
					if err := os.WriteFile(path, []byte("preserve"), 0o600); err != nil {
						t.Fatal(err)
					}
					if attack == "hard-link" {
						want = "hard link"
						if err := os.Link(path, filepath.Join(parent, "other.lock")); err != nil {
							t.Fatal(err)
						}
					} else {
						mode := os.FileMode(0o644)
						if attack == "writable-file" {
							mode = 0o660
						}
						if err := os.Chmod(path, mode); err != nil {
							t.Fatal(err)
						}
					}
				case "fifo":
					want = "regular file"
					if err := unix.Mkfifo(path, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				unlock, err := lock.acquire(runDir)
				if unlock != nil {
					_ = unlock()
				}
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("unsafe lock error = %v, want %q rejection", err, want)
				}
				if attack == "writable-directory" || attack == "writable-parent" {
					if _, err := os.Lstat(path); !os.IsNotExist(err) {
						t.Fatalf("unsafe directory received a lock file: %v", err)
					}
				}
			})
		}
	}
}

func TestZTAPLockAllowsProtectedDirectoryUnderStickyParent(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(parent, "private")
	unlock, err := acquireNativeAgentLock(runDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
}

func TestZTAPLocksRejectForeignOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing ownership requires root")
	}
	for _, target := range []string{"directory", "file"} {
		t.Run(target, func(t *testing.T) {
			runDir := t.TempDir()
			path := runDir
			if target == "file" {
				path = filepath.Join(runDir, "agent.lock")
				if err := os.WriteFile(path, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Chown(path, 65534, -1); err != nil {
				t.Fatal(err)
			}
			unlock, err := acquireNativeAgentLock(runDir)
			if unlock != nil {
				_ = unlock()
			}
			if err == nil || !strings.Contains(err.Error(), "owner") {
				t.Fatalf("foreign-owned lock error = %v, want owner rejection", err)
			}
		})
	}
}
