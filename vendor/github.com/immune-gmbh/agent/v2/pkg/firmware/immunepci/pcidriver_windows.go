package immunepci

import (
	"encoding/binary"
	"fmt"
	"syscall"

	"github.com/immune-gmbh/agent/v2/pkg/util"
	"golang.org/x/sys/windows"
)

const (
	DriverServiceName         string = "immunePCI_ctrl"
	ImmunePCIDriverDeviceFile string = "\\\\?\\GLOBALROOT\\Device\\immunePCI_ctrl"
	IOCTL_GETPCI              uint32 = (0x8000 << 16) | 3<<14 | (0x804 << 2) | 2
)

func loadDriver() (handle windows.Handle, err error) {
	err = util.StartDriverIfNotRunning(DriverServiceName)
	if err != nil {
		return
	}
	defer util.StopDriver(DriverServiceName)

	u16fname, err := syscall.UTF16FromString(ImmunePCIDriverDeviceFile)
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

func ReadConfigSpace(bus, device, function, offset, maxcount uint32) (outBuf []byte, err error) {
	var bytesReturned uint32
	inBuf := make([]byte, 5*4)
	outBuf = make([]byte, maxcount)

	handle, err := loadDriver()
	if err != nil {
		err = fmt.Errorf("Error opening immunePCI driver file %w", err)
		return
	}
	defer windows.CloseHandle(handle)

	binary.LittleEndian.PutUint32(inBuf[0:], bus)
	binary.LittleEndian.PutUint32(inBuf[4:], device)
	binary.LittleEndian.PutUint32(inBuf[8:], function)
	binary.LittleEndian.PutUint32(inBuf[12:], offset)
	binary.LittleEndian.PutUint32(inBuf[16:], maxcount)

	err = windows.DeviceIoControl(handle, IOCTL_GETPCI, &inBuf[0], uint32(len(inBuf)), &outBuf[0], maxcount, &bytesReturned, nil)
	if err != nil {
		err = fmt.Errorf("IOCTL_GETPCI err: %w", err)
		return
	}

	return
}
