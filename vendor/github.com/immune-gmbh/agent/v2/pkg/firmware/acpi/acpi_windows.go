package acpi

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/immune-gmbh/agent/v2/pkg/util"
	log "github.com/sirupsen/logrus"
)

var (
	libKernel32 = syscall.NewLazyDLL("kernel32.dll")

	// MSDN Documentation for EnumSystemFirmwareTables:
	// https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-enumsystemfirmwaretables
	procEnumSystemFirmwareTables = libKernel32.NewProc("EnumSystemFirmwareTables")

	// MSDN Documentation for GetSystemFirmwareTable:
	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms724379(v=vs.85).aspx
	procGetSystemFirmwareTable = libKernel32.NewProc("GetSystemFirmwareTable")
)

// 'ACPI' as uint32
const firmwareTableProviderSigACPI uint32 = 0x41435049

func enumACPITableIDs() ([]uint32, error) {
	// calling with NULL buffer will return required buffer size
	r1, _, err := procEnumSystemFirmwareTables.Call(
		uintptr(firmwareTableProviderSigACPI), // FirmwareTableProviderSignature
		0,                                     // pFirmwareTableEnumBuffer = NULL
		0,                                     // BufferSize = 0
	)

	// err is never nil, must check r1, see doc here
	// https://golang.org/pkg/syscall/?GOOS=windows#Proc.Call
	if r1 == 0 {
		return nil, fmt.Errorf("error determining required buffer size: %w", err)
	}

	// do the real call with a large enough buffer
	bufSz := uint32(r1)
	buf := make([]uint32, bufSz/4)
	r1, _, err = procEnumSystemFirmwareTables.Call(
		uintptr(firmwareTableProviderSigACPI), // FirmwareTableProviderSignature
		uintptr(unsafe.Pointer(&buf[0])),      // pFirmwareTableEnumBuffer
		uintptr(bufSz),                        // BufferSize
	)

	wrSz := uint32(r1)
	if wrSz > bufSz {
		return nil, fmt.Errorf("too many bytes written: expected %d got %d", bufSz, wrSz)
	}
	if wrSz == 0 {
		return nil, fmt.Errorf("failed to enum ACPI table IDs: %w", err)
	}

	return buf, nil
}

func readACPITable(firmwareTableID uint32) ([]byte, error) {
	// calling with NULL buffer will return required buffer size
	r1, _, err := procGetSystemFirmwareTable.Call(
		uintptr(firmwareTableProviderSigACPI), // FirmwareTableProviderSignature
		uintptr(firmwareTableID),              // FirmwareTableID
		0,                                     // pFirmwareTableBuffer = NULL
		0,                                     // BufferSize = 0
	)

	// err is never nil, must check r1, see doc here
	// https://golang.org/pkg/syscall/?GOOS=windows#Proc.Call
	if r1 == 0 {
		return nil, fmt.Errorf("error determining required buffer size: %w", err)
	}

	// do the real call with a large enough buffer
	bufSz := uint32(r1)
	buf := make([]byte, bufSz)
	r1, _, err = procGetSystemFirmwareTable.Call(
		uintptr(firmwareTableProviderSigACPI), // FirmwareTableProviderSignature
		uintptr(firmwareTableID),              // FirmwareTableID
		uintptr(unsafe.Pointer(&buf[0])),      // pFirmwareTableBuffer
		uintptr(bufSz),                        // BufferSize
	)

	wrSz := uint32(r1)
	if wrSz > bufSz {
		return nil, fmt.Errorf("too many bytes written: expected %d got %d", bufSz, wrSz)
	}
	if wrSz == 0 {
		return nil, fmt.Errorf("failed to read ACPI table '%s': %w", util.Uint32ToStr(firmwareTableID), err)
	}

	return buf, nil
}

func readACPITables() (map[string][]byte, error) {
	tableIDs, err := enumACPITableIDs()
	if err != nil {
		return nil, err
	}

	tables := make(map[string][]byte)
	completeFailure := true
	for _, id := range tableIDs {
		table, err := readACPITable(id)
		if err != nil {
			log.Warnf("error getting acpi table '%v': %s", table, err.Error())
			continue
		}
		completeFailure = false
		tables[util.Uint32ToStr(id)] = table
	}

	if completeFailure {
		//XXX wrap to firmware error
		return nil, err
	}

	return tables, nil
}
