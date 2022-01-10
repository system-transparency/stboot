// +build !linux,!windows

package netif

import (
	"errors"
	"runtime"
)

func readMACAddresses() ([]string, error) {
	return nil, errors.New("msr.ReadMACAddresses not implemented on " + runtime.GOOS)
}
