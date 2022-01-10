package heci

import (
	"encoding/binary"
	"fmt"
	"os"
)

const heci1PciConfigPath = "/sys/bus/pci/devices/0000:00:15.0/config"

func readReg8(f *os.File, offset int64) (reg uint8, err error) {
	_, err = f.Seek(offset, 0)
	if err != nil {
		err = fmt.Errorf("can't seek to HECI PCI config register: %w", err)
		return
	}
	err = binary.Read(f, binary.LittleEndian, &reg)
	if err != nil {
		err = fmt.Errorf("can't read HECI PCI config register: %w", err)
	}
	return
}

func readReg16(f *os.File, offset int64) (reg uint16, err error) {
	_, err = f.Seek(offset, 0)
	if err != nil {
		err = fmt.Errorf("can't seek to HECI PCI config register: %w", err)
		return
	}
	err = binary.Read(f, binary.LittleEndian, &reg)
	if err != nil {
		err = fmt.Errorf("can't read HECI PCI config register: %w", err)
	}
	return
}

func readReg32(f *os.File, offset int64) (reg uint32, err error) {
	_, err = f.Seek(offset, 0)
	if err != nil {
		err = fmt.Errorf("can't seek to HECI PCI config register: %w", err)
		return
	}
	err = binary.Read(f, binary.LittleEndian, &reg)
	if err != nil {
		err = fmt.Errorf("can't read HECI PCI config register: %w", err)
	}
	return
}

func readReg64(f *os.File, offset int64) (reg uint64, err error) {
	_, err = f.Seek(offset, 0)
	if err != nil {
		err = fmt.Errorf("can't seek to HECI PCI config register: %w", err)
		return
	}
	err = binary.Read(f, binary.LittleEndian, &reg)
	if err != nil {
		err = fmt.Errorf("can't read HECI PCI config register: %w", err)
	}
	return
}

func writeReg8(f *os.File, offset int64, reg uint8) (err error) {
	_, err = f.Seek(offset, 0)
	if err != nil {
		err = fmt.Errorf("can't seek to HECI PCI config register: %w", err)
		return
	}
	err = binary.Write(f, binary.LittleEndian, reg)
	if err != nil {
		err = fmt.Errorf("can't write HECI PCI config register: %w", err)
	}
	return
}
