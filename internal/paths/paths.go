// Package paths provides shared filesystem path helpers.
package paths

import (
	"os"
	"path/filepath"
	"strings"
)

// Expand trims surrounding whitespace, expands environment variables, and
// resolves ~ and ~/... (or ~\\... on Windows) against the current user's home
// directory. Other leading-tilde paths, such as ~other, are left unchanged.
// If the home directory cannot be determined, a home-relative path is also
// left unchanged.
func Expand(p string) string {
	clean := os.ExpandEnv(strings.TrimSpace(p))
	if clean != "~" && !strings.HasPrefix(clean, "~/") && !strings.HasPrefix(clean, `~\`) {
		return clean
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return clean
	}
	rest := strings.TrimLeft(clean[1:], `/\`)
	return filepath.Join(home, rest)
}
