package state

import (
	"os"
	"path/filepath"
)

// DefaultStateDir returns all candidates for the config data dir in order of
// writing.
func DefaultStateDirs() []string {
	return []string{filepath.Clean(filepath.Join(os.Getenv("ProgramData"), DefaultVendorSubdir))}
}
