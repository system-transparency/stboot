// +build !linux,!windows

package pci

import (
	"errors"
	"runtime"
)

func readConfigSpace(bus, device, function, offset, maxcount uint32) (outBuf []byte, err error) {
	err = errors.New("pciconfig.ReadConfigSpace not implemented on " + runtime.GOOS)
	return
}
