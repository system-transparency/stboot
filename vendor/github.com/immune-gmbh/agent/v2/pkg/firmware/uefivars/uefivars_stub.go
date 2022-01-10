// +build !linux,!windows

package uefivars

import (
	"errors"
	"runtime"
)

func readUEFIVariable(name, guid string) ([]byte, error) {
	return nil, errors.New("uefivars.ReadUEFIVariable not implemented on " + runtime.GOOS)
}
