// +build !linux,!windows

package smbios

import (
	"errors"
	"runtime"
)

func readSMBIOS() ([]byte, error) {
	return nil, errors.New("smbios.ReadSmbios not implemented on " + runtime.GOOS)
}
