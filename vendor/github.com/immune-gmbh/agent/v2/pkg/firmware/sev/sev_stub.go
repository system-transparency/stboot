// +build !linux,!windows

package sev

import (
	"errors"
	"runtime"
)

func runSEVCommand(command uint32, retLen uint32) ([]byte, error) {
	return nil, errors.New("sev.RunSEVCommand not implemented on " + runtime.GOOS)
}
