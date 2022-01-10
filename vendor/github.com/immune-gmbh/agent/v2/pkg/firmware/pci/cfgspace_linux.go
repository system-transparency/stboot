package pci

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	pciPath = "/sys/bus/pci/devices"
)

func readConfigSpace(bus, device, function, offset, maxcount uint32) ([]byte, error) {
	devPath := filepath.Join(pciPath, fmt.Sprintf("0000:%02x:%02x.%d", bus, device, function))
	f, err := os.Open(filepath.Join(devPath, "config"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, maxcount)
	f.Seek(int64(offset), 0)
	_, err = f.Read(buf)

	return buf, err
}
