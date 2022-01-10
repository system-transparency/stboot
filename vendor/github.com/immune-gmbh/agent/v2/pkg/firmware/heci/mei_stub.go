// +build !linux,!windows
//
// implement HECI using ME interface (mei) via official kernel drivers

package heci

import (
	"errors"
	"runtime"

	"github.com/google/uuid"
)

// openMEI connects to a specific ME client via HECI device
func openMEI(path string, clientGUID uuid.UUID) (*meiClient, error) {
	return nil, errors.New("heci.openMEI not implemented on " + runtime.GOOS)
}

func (m *meiClient) close() error {
	return errors.New("heci.meiClient.close not implemented on " + runtime.GOOS)
}

func (m *meiClient) write(p []byte) (int, error) {
	return 0, errors.New("heci.meiClient.write not implemented on " + runtime.GOOS)
}

func (m *meiClient) read(p []byte) (int, error) {
	return 0, errors.New("heci.meiClient.read not implemented on " + runtime.GOOS)
}
