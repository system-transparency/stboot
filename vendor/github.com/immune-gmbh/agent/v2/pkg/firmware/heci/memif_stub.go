// +build !linux,!windows

package heci

import (
	"errors"
	"runtime"
)

type osHandleType *int

func openHECI1(clientAddress uint8) (*heci, error) {
	return nil, errors.New("heci.openHECI1 not implemented on " + runtime.GOARCH)
}

func (m *heci) close() error {
	return errors.New("heci.heci.close not implemented on " + runtime.GOARCH)
}
