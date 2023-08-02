package metadata

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Metadata struct {
	Cmdline string

	contents *os.File
}

const (
	pmemAddressPath  = "/sys/kernel/fake_pmem/address"
	pmemContentsPath = "/sys/kernel/fake_pmem/contents"

	UxIdentity = 0x44495855
	EventLog   = 0x474F4C45

	currentVersion = "stboot metadata v1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
)

var (
	ErrNotAvailable = errors.New("metadata not available")
)

func Allocate() (*Metadata, error) {
	// parse fake_pmem address.
	addrstr, err := os.ReadFile(pmemAddressPath)
	if err != nil {
		return nil, ErrNotAvailable
	}

	addr, err := strconv.ParseUint(strings.TrimSpace(string(addrstr)), 0, 64)
	if err != nil {
		return nil, ErrNotAvailable
	}

	if addr == 0 {
		return nil, ErrNotAvailable
	}

	// open the contents file.
	contents, err := os.OpenFile(pmemContentsPath, os.O_RDWR, 0)
	if err != nil {
		return nil, ErrNotAvailable
	}

	_, err = contents.Write([]byte(currentVersion))
	if err != nil {
		return nil, err
	}

	finfo, err := contents.Stat()
	if err != nil {
		return nil, err
	}

	meta := Metadata{
		contents: contents,
		Cmdline:  fmt.Sprintf("memmap=0x%x!0x%08x", finfo.Size(), addr),
	}

	return &meta, nil
}

func (m *Metadata) Set(ty uint32, data []byte) error {
	err := binary.Write(m.contents, binary.LittleEndian, ty)
	if err != nil {
		return err
	}

	err = binary.Write(m.contents, binary.LittleEndian, uint32(len(data)))
	if err != nil {
		return err
	}

	_, err = m.contents.Write(data)
	if err != nil {
		return err
	}

	return nil
}

func (m *Metadata) Close() error {
	return m.contents.Close()
}
