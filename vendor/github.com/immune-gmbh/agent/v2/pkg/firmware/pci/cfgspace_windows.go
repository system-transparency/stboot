package pci

import "github.com/immune-gmbh/agent/v2/pkg/firmware/immunepci"

// readConfigSpace is just a wrapper to keep things consistent
func readConfigSpace(bus, device, function, offset, maxcount uint32) (outBuf []byte, err error) {
	return immunepci.ReadConfigSpace(bus, device, function, offset, maxcount)
}
