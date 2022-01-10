// +build !windows,!linux

package util

import (
	"errors"
	"runtime"
)

// WinAddTokenPrivilege dummy implementation for other OSes
func WinAddTokenPrivilege(name string) error {
	return nil
}

func IsKernelModuleLoaded(name string) (bool, error) {
	return false, errors.New("IsRoot not implemented on " + runtime.GOOS)
}

func IsRoot() (ret bool, err error) {
	return false, errors.New("IsRoot not implemented on " + runtime.GOOS)
}
