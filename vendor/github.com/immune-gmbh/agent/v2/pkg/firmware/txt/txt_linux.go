package txt

import (
	"bytes"
	"io"
	"os"
	"syscall"

	"github.com/immune-gmbh/agent/v2/pkg/firmware/common"
)

const (
	txtPubSpaceFilePath = "/sys/kernel/txt_mmap/public_space"
	maxMappedMem        = 0x10000
	txtPublicRegionMmap = 0xFED30000
)

func readTXTPublicSpace() ([]byte, error) {
	f, err := os.Open(txtPubSpaceFilePath)
	var r io.Reader
	if os.IsNotExist(err) {
		fd, err := os.OpenFile(common.DefaultDevMemPath, os.O_RDWR, 0)
		if err != nil {
			return nil, err
		}
		defer fd.Close()
		mem, err := syscall.Mmap(int(fd.Fd()), int64(txtPublicRegionMmap), maxMappedMem, syscall.PROT_READ, syscall.MAP_SHARED)
		if err != nil {
			return nil, err
		}
		defer syscall.Munmap(mem)
		r = bytes.NewReader(mem)
	} else if err != nil {
		return nil, err
	} else {
		defer f.Close()
		r = f
	}
	return io.ReadAll(r)
}
