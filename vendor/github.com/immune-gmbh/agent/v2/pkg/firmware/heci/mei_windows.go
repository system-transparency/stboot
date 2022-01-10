// implement HECI using ME interface (mei) via kernel drivers
package heci

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

type osHandleType windows.Handle

// MEI device IOCTLs
const IOCTL_CONNECT_CLIENT uint32 = 0x8000e004

// windows configuration manager constants
const (
	CM_GET_DEVICE_INTERFACE_LIST_PRESENT     uint32 = 0x0
	CM_GET_DEVICE_INTERFACE_LIST_ALL_DEVICES uint32 = 0x1
)

// This is the interface GUID used by the official management engine drivers
// {0xE2D1FF34, 0x3458, 0x49A9, 0x88, 0xDA, 0x8E, 0x69, 0x15, 0xCE, 0x9B, 0xE5}
// https://github.com/intel/metee/blob/master/src/Windows/public.h
var GUID_DEVINTERFACE_HECI = [16]byte{0x34, 0xFF, 0xD1, 0xE2, 0x58, 0x34, 0xA9, 0x49, 0x88, 0xDA, 0x8E, 0x69, 0x15, 0xCE, 0x9B, 0xE5}

var (
	libCfgMgr32 = syscall.NewLazyDLL("CfgMgr32.dll")

	// MSDN Documentation for CM_Get_Device_Interface_List_SizeA:
	// https://docs.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_get_device_interface_list_sizea
	procCMGetDeviceInterfaceListSizeA = libCfgMgr32.NewProc("CM_Get_Device_Interface_List_SizeA")

	// MSDN Documentation for CM_Get_Device_Interface_ListA:
	// https://docs.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_get_device_interface_lista
	procCMGetDeviceInterfaceListA = libCfgMgr32.NewProc("CM_Get_Device_Interface_ListA")
)

// openMEI connects to a specific ME client via HECI device
func openMEI(path string, clientGUID uuid.UUID) (*meiClient, error) {
	if path == "" {
		v, err := getHECIDevicePath()
		if err != nil {
			return nil, fmt.Errorf("failed to open HECI device: %w", err)
		}
		path = v
	}
	h, err := openHECIDevice(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open HECI device: %w", err)
	}

	logrus.Tracef("Connecting MEI client %v\n", clientGUID.String())
	data, err := connectClientGUID(h, clientGUID)
	if err != nil {
		return nil, fmt.Errorf("failed to connect ME client: %w", err)
	}
	var m meiClient
	m.handle = osHandleType(h)
	if len(data) < 5 {
		err = m.close()
		if err != nil {
			return nil, fmt.Errorf("IOCTL_CONNECT_CLIENT not enough data returned and close error: %w", err)
		}
		return nil, fmt.Errorf("IOCTL_CONNECT_CLIENT not enough data returned")
	}

	// we expect at least 5 meaningful bytes to be returned, read them as per:
	// include/uapi/linux/mei.h
	m.maxMsgLength = binary.LittleEndian.Uint32(data[:4])
	m.protoVersion = int(uint8(data[4]))

	logrus.Tracef("Opened MEI: %#v", m)
	return &m, nil
}

func (m *meiClient) close() error {
	return windows.Close(windows.Handle(m.handle))
}

func (m *meiClient) write(p []byte) (int, error) {
	return windows.Write(windows.Handle(m.handle), p)
}

func (m *meiClient) read(p []byte) (int, error) {
	return windows.Read(windows.Handle(m.handle), p)
}

func openHECIDevice(devicePath string) (handle windows.Handle, err error) {
	u16fname, err := syscall.UTF16FromString(devicePath)
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

	return
}

func getHECIDevicePath() (string, error) {
	var listSize uint64
	flags := CM_GET_DEVICE_INTERFACE_LIST_PRESENT
	r1, _, err := procCMGetDeviceInterfaceListSizeA.Call(
		uintptr(unsafe.Pointer(&listSize)),                  // pulLen
		uintptr(unsafe.Pointer(&GUID_DEVINTERFACE_HECI[0])), // InterfaceClassGuid
		0,              // pDeviceID = NULL
		uintptr(flags), // ulFlags = 0
	)

	// err is never nil, must check r1, see doc here
	// https://golang.org/pkg/syscall/?GOOS=windows#Proc.Call
	if r1 != 0 {
		return "", fmt.Errorf("error determining interface list size: CONFIGRET %v", r1)
	}
	if listSize <= 1 {
		return "", fmt.Errorf("me device not found: %w", err)
	}

	buf := make([]byte, listSize)
	r1, _, err = procCMGetDeviceInterfaceListA.Call(
		uintptr(unsafe.Pointer(&GUID_DEVINTERFACE_HECI[0])), // InterfaceClassGuid
		0,                                // pDeviceID  = NULL
		uintptr(unsafe.Pointer(&buf[0])), // Buffer
		uintptr(listSize),                // BufferLen = 0
		uintptr(flags),                   // ulFlags = 0
	)

	if r1 != 0 {
		return "", fmt.Errorf("error getting device interface list: CONFIGRET %v, %v", r1, err)
	}

	if i := bytes.IndexByte(buf, 0); i > 0 {
		buf = buf[:i]
	}
	return string(buf), nil
}

func connectClientGUID(handle windows.Handle, guid uuid.UUID) (outBuf []byte, err error) {
	var bytesReturned uint32
	bytes := 16
	outBuf = make([]byte, bytes)
	data := littleEndianUUID(guid)
	err = windows.DeviceIoControl(handle, IOCTL_CONNECT_CLIENT, &data[0], uint32(len(data)), &outBuf[0], uint32(bytes), &bytesReturned, nil)
	if err != nil {
		return
	}
	outBuf = outBuf[:bytesReturned]
	return
}
