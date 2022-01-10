// +build !linux,!windows

package acpi

import (
	"errors"
	"runtime"
)

func readACPITables() (map[string][]byte, error) {
	return nil, errors.New("acpi.readACPITables not implemented on " + runtime.GOOS)
}
