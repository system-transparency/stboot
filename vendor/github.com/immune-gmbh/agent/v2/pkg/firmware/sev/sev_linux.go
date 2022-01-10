package sev

import (
	"encoding/binary"
	"errors"
	"os"
	"runtime/debug"
	"syscall"
	"unsafe"
)

// ioctl number 0x53 and flags combined
const (
	defaultSEVDevice = "/dev/sev"
	IOCTL_SEV_CMD    = 0xc0105300
)

func runSEVCommand(command, readLength uint32) ([]byte, error) {
	if readLength == 0 {
		return nil, errors.New("readLength is 0")
	}

	fd, err := os.OpenFile(defaultSEVDevice, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}

	// allocate request and response buffer as a contiguous region to benefit from special memory semantics during syscall execution
	// the request struct is 20 bytes long and the response struct is retLen bytes long
	var base uint32 = 20
	buf := make([]byte, base+readLength)
	// subcommand
	binary.LittleEndian.PutUint32(buf[0:], command)
	// turn off GC to prevent it from moving our array while we are using a raw pointer value
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	// pass response struct ptr, this is meant for 64bit only
	binary.LittleEndian.PutUint64(buf[4:], uint64(uintptr(unsafe.Pointer(&buf[base]))))
	_, _, ep := syscall.Syscall(syscall.SYS_IOCTL, fd.Fd(), IOCTL_SEV_CMD, uintptr(unsafe.Pointer(&buf[0])))
	if ep != 0 {
		return nil, syscall.Errno(ep)
	}
	return buf[base:], nil
}
