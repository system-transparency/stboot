package immunecpu

import (
	"encoding/binary"
	"errors"
	"fmt"
	"syscall"

	"github.com/immune-gmbh/agent/v2/pkg/util"
	"golang.org/x/sys/windows"
)

const (
	DriverServiceName string = "immuneCPU"
	DriverDeviceFile  string = "\\\\?\\GLOBALROOT\\Device\\immuneCPU"
	IOCTL_GETFLASH    uint32 = (0x8000 << 16) | 1<<14 | (0x800 << 2) | 2
	IOCTL_GETMSR      uint32 = (0x8000 << 16) | 3<<14 | (0x802 << 2)
	IOCTL_GETTXTPUB   uint32 = (0x8000 << 16) | 1<<14 | (0x804 << 2) | 2
)

func loadDriver() (handle windows.Handle, err error) {
	err = util.StartDriverIfNotRunning(DriverServiceName)
	if err != nil {
		return
	}
	defer util.StopDriver(DriverServiceName)

	u16fname, err := syscall.UTF16FromString(DriverDeviceFile)
	if err != nil {
		return
	}

	var nullHandle windows.Handle
	handle, err = windows.CreateFile(&u16fname[0],
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		nullHandle)

	if (handle != windows.InvalidHandle) && (err != nil) {
		return
	}

	return
}

func ReadBiosFlashMMap() (outBuf []byte, err error) {
	var bytesReturned uint32
	inBuf := make([]byte, 1)
	outBuf = make([]byte, 16*1024*1024)

	handle, err := loadDriver()
	if err != nil {
		err = fmt.Errorf("error opening CPU driver file: %w", err)
		return
	}
	defer windows.CloseHandle(handle)

	err = windows.DeviceIoControl(handle, IOCTL_GETFLASH, &inBuf[0], uint32(len(inBuf)), &outBuf[0], uint32(len(outBuf)), &bytesReturned, nil)
	if err != nil {
		err = fmt.Errorf("IOCTL_GETFLASH err: %w", err)
		return
	}
	if bytesReturned != uint32(len(outBuf)) {
		err = errors.New("read flash wrong number of bytes returned")
	}

	return
}

func ReadTxtPublicSpace() (outBuf []byte, err error) {
	var bytesReturned uint32
	inBuf := make([]byte, 1)
	outBuf = make([]byte, 0x10000)

	handle, err := loadDriver()
	if err != nil {
		err = fmt.Errorf("error opening CPU driver file: %w", err)
		return
	}
	defer windows.CloseHandle(handle)

	err = windows.DeviceIoControl(handle, IOCTL_GETTXTPUB, &inBuf[0], uint32(len(inBuf)), &outBuf[0], uint32(len(outBuf)), &bytesReturned, nil)
	if err != nil {
		err = fmt.Errorf("IOCTL_GETTXTPUB err: %w", err)
		return
	}
	if bytesReturned != uint32(len(outBuf)) {
		err = errors.New("read TXT public space wrong number of bytes returned")
	}

	return
}

func ReadMSR(cpu, msr uint32) (data uint64, err error) {
	var bytesReturned uint32
	inBuf := make([]byte, 2*4)
	outBuf := make([]byte, 8)

	handle, err := loadDriver()
	if err != nil {
		err = fmt.Errorf("error opening immuneCPU driver file: %w", err)
		return
	}
	defer windows.CloseHandle(handle)

	binary.LittleEndian.PutUint32(inBuf[0:], cpu)
	binary.LittleEndian.PutUint32(inBuf[4:], msr)

	err = windows.DeviceIoControl(handle, IOCTL_GETMSR, &inBuf[0], uint32(len(inBuf)), &outBuf[0], 8, &bytesReturned, nil)
	if err != nil {
		err = fmt.Errorf("IOCTL_GETMSR err: %w", err)
		return
	}
	if bytesReturned != 8 {
		err = errors.New("read MSR wrong number of bytes returned")
	}

	data = binary.LittleEndian.Uint64(outBuf)
	return
}
