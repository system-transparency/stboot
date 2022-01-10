//go:build linux || darwin || !windows
// +build linux darwin !windows

package state

import (
	"os"
	"path/filepath"
)

// Defaults for Linux and MacOS
const (
	// gloablProgramStateDir stores programatically generated state
	gloablProgramStateDir string = "/var/lib"
	localProgramStateDir  string = ".local/share"
)

// DefaultStateDir returns all candidates for the config data dir in order of
// writing.
func DefaultStateDirs() []string {
	paths := []string{gloablProgramStateDir}

	if home := os.Getenv("HOME"); home != "" && filepath.IsAbs(home) {
		paths = append(paths, filepath.Join(home, localProgramStateDir))
	}

	for i := range paths {
		paths[i] = filepath.Clean(filepath.Join(paths[i], DefaultVendorSubdir))
	}
	return paths
}
