// Package paths provides shared filesystem path helpers.
package paths

import (
	"os"
	"path/filepath"
	"strings"
)

// Expand trims surrounding whitespace, expands environment variables, and
// resolves a leading "~" against the user's home directory. If the home
// directory cannot be determined, the "~" is left in place.
func Expand(p string) string {
	clean := os.ExpandEnv(strings.TrimSpace(p))
	if strings.HasPrefix(clean, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			clean = filepath.Join(home, strings.TrimPrefix(clean, "~"))
		}
	}
	return clean
}
