// implement HECI using direct memory-mapped interface (mei) via official kernel drivers
package heci

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

const defaultDevMemPath = "/dev/mem"

func openHECI1(clientAddress uint8) (*heci, error) {
	f, err := os.Open(heci1PciConfigPath)
	if err != nil {
		return nil, fmt.Errorf("can't open HECI PCI config space: %w", err)
	}
	defer f.Close()

	// test if vendor is intel
	reg16, err := readReg16(f, 0)
	if err != nil {
		return nil, err
	}
	if reg16 != 0x8086 {
		return nil, errors.New("no HECI if found")
	}

	// get memory mapped region base address
	MMIOBase, err := readReg64(f, heci1MMIOOffset)
	if err != nil {
		return nil, err
	}
	MMIOBase = MMIOBase & 0xfffffffffffffff0

	// see if mapping is enabled and enable if not
	reg8, err := readReg8(f, heci1Options)
	if err != nil {
		return nil, err
	}
	memSpaceEnable := (reg8>>1)&1 != 0
	if !memSpaceEnable {
		reg8 |= (1 << 1)
		writeReg8(f, heci1Options, reg8)
		if err != nil {
			return nil, err
		}
	}

	// open memory
	var m heci
	m.fd, err = os.OpenFile(defaultDevMemPath, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	m.data, err = syscall.Mmap(int(m.fd.Fd()), int64(MMIOBase), maxMappedMem, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return &m, err
	}
	return &m, nil
}

func (m *heci) close() error {
	if err := syscall.Munmap(m.data); err != nil {
		return err
	}
	return m.fd.Close()
}
