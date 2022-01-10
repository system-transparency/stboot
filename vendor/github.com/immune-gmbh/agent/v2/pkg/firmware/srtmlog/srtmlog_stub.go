// +build !linux,!windows

package srtmlog

import (
	"errors"
	"io"
	"runtime"
)

func readTPM2EventLog(conn io.ReadWriteCloser) ([]byte, error) {
	return nil, errors.New("srtmlog.ReadTPM2EventLog not implemented on " + runtime.GOOS)
}
