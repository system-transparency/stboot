// +build !linux

package heci

import (
	"errors"
	"runtime"
)

// readHECI1FWSTS3 reads FWSTS3 register from HECI1 PCI config space
func readHECI1FWSTS3() (uint32, error) {
	return 0, errors.New("heci.readHECI1FWSTS3 not implemented on " + runtime.GOARCH)
}
