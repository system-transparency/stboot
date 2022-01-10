// +build !linux,!windows

package txt

import (
	"errors"
	"runtime"
)

func readTXTPublicSpace() ([]byte, error) {
	return nil, errors.New("txt.ReadTXTPublicSpace not implemented on " + runtime.GOOS)
}
