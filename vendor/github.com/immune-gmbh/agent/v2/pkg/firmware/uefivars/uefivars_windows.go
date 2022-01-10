package uefivars

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

const defaultMaxBufferSz = 8192

var (
	libKernel32 = syscall.NewLazyDLL("kernel32.dll")

	// MSDN Documentation for EnumSystemFirmwareTables:
	// https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwareenvironmentvariableexa
	procGetFirmwareEnvironmentVariableExA = libKernel32.NewProc("GetFirmwareEnvironmentVariableExA")
)

func readUEFIVariable(name, guid string) ([]byte, error) {
	buf, _, err := readUEFIVariableGUID(name, fmt.Sprintf("{%s}", strings.ToUpper(guid)))
	return buf, err
}

func readUEFIVariableGUID(name, guid string) ([]byte, uint32, error) {
	var attr uint32
	bufSz := defaultMaxBufferSz
	buf := make([]byte, bufSz)
	bName := append([]byte(name), 0)
	bGuid := append([]byte(guid), 0)

	// calling with NULL buffer will return required buffer size
	r1, _, err := procGetFirmwareEnvironmentVariableExA.Call(
		uintptr(unsafe.Pointer(&bName[0])), // lpName
		uintptr(unsafe.Pointer(&bGuid[0])), // lpGuid
		uintptr(unsafe.Pointer(&buf[0])),   // pBuffer = NULL
		uintptr(bufSz),                     // nSize = 0
		uintptr(attr),                      // pdwAttribubutes = NULL
	)

	// err is never nil, must check r1, see doc here
	// https://golang.org/pkg/syscall/?GOOS=windows#Proc.Call
	if r1 == 0 {
		return nil, 0, fmt.Errorf("failed to get UEFI var: %w", err)
	}

	return buf[:uint32(r1)], attr, nil
}
