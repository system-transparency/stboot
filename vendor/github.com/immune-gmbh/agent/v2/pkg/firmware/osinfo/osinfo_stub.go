// +build !linux,!windows

package osinfo

import (
	"errors"
	"runtime"
)

func readOSReleasePrettyName() (string, error) {
	return "unsupported", errors.New("osinfo.readOSReleasePrettyName not implemented on " + runtime.GOOS)
}
