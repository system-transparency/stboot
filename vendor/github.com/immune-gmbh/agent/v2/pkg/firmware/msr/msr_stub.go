// +build !linux,!windows

package msr

import (
	"errors"
	"runtime"
)

func readMSR(cpu, msr uint32) (uint64, error) {
	return 0, errors.New("msr.ReadMSR not implemented on " + runtime.GOOS)
}
