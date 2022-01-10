package biosflash

import (
	"bytes"
	"io"
	"os"
	"syscall"

	"github.com/immune-gmbh/agent/v2/pkg/firmware/common"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/cpuid"
)

const (
	flashFilePath  = "/sys/firmware/flash_mmap/bios_region"
	maxMappedMem   = 0x1000000 // must be a multiple of 0x100
	biosRegionMmap = 0xFF000000
)

func readBiosFlashMMap() (outBuf []byte, err error) {
	f, err := os.Open(flashFilePath)
	var r io.Reader
	if os.IsNotExist(err) {
		var fd *os.File
		fd, err = os.OpenFile(common.DefaultDevMemPath, os.O_RDWR, 0)
		if err != nil {
			return
		}
		defer fd.Close()

		var mem []byte
		mem, err = syscall.Mmap(int(fd.Fd()), int64(biosRegionMmap), maxMappedMem, syscall.PROT_READ, syscall.MAP_SHARED)
		if err != nil {
			return
		}
		defer syscall.Munmap(mem)

		// defeat golang's mem copy optimization b/c it crashes on certain AMD processors
		// see issue #588
		if cpuid.Vendor() == cpuid.VendorAMD {
			outBuf = make([]byte, len(mem))
			for i := 0; i < maxMappedMem; i += 0x100 {
				copy(outBuf[i:i+0x100], mem[i:i+0x100])
			}
			return
		}

		r = bytes.NewReader(mem)
	} else if err != nil {
		return nil, err
	} else {
		defer f.Close()
		r = f
	}

	return io.ReadAll(r)
}
