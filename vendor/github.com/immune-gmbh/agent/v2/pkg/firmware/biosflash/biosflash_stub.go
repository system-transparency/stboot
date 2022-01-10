// +build !linux,!windows

package biosflash

import (
	"errors"
	"runtime"
)

func readBiosFlashMMap() (outBuf []byte, err error) {
	return nil, errors.New("biosflash.ReadBiosFlashMMap not implemented on " + runtime.GOOS)
}
