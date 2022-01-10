package firmware

import (
	"errors"
	"io"

	"github.com/immune-gmbh/agent/v2/pkg/api"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/acpi"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/biosflash"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/common"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/cpuid"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/heci"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/msr"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/netif"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/osinfo"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/pci"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/sev"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/smbios"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/srtmlog"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/txt"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/uefivars"
	"github.com/immune-gmbh/agent/v2/pkg/tcg"
	"github.com/immune-gmbh/agent/v2/pkg/util"
	"github.com/sirupsen/logrus"
)

// GatherFirmwareData passes the server-sent configuration leafs to the appropriate report sub-functions.
// Error handling and logging is mostly left to the leaf functions. If part of the report fails, it is
// simply omitted. Errors that are meaningful for the SaaS are stored in the error members of the api structs.
func GatherFirmwareData(tpmConn io.ReadWriteCloser, request *api.Configuration) (api.FirmwareProperties, error) {
	logrus.Trace("start gathering firmware data")

	var fwData api.FirmwareProperties
	cpuVendor := cpuid.Vendor()

	// Get ourselves windows security permissions to read UEFI vars
	err := util.WinAddTokenPrivilege("SeSystemEnvironmentPrivilege")
	if err != nil {
		logrus.Debugf("util.WinAddTokenPrivilege(): %s", err.Error())
		logrus.Warnf("Failed to get windows security permissions to read UEFI variables")
	}

	// Basic Input/Output System flash
	biosflash.ReportBiosFlash(&fwData.Flash)

	// CPUID leaves
	fwData.CPUIDLeafs = request.CPUIDLeafs
	for i := range fwData.CPUIDLeafs {
		v := &fwData.CPUIDLeafs[i]
		cpuid.ReportCPUIDLeaf(v)
	}

	// Model Specific Registers
	fwData.MSRs = request.MSRs
	msr.ReportMSRs(fwData.MSRs)

	// Medium Access Control addresses
	netif.ReportMACAddresses(&fwData.MACAddresses)

	// Peripheral Component Interconnect config space
	fwData.PCIConfigSpaces = request.PCIConfigSpaces
	pci.ReportConfigSpaces(fwData.PCIConfigSpaces)

	// Advanced Micro Devices Secure Encrypted Virtualization
	if cpuVendor == cpuid.VendorAMD {
		fwData.SEV = request.SEV
		sev.ReportSEVCommands(fwData.SEV)
	}

	// Advanced Configuration and Power Interface tables
	acpi.ReportACPITables(&fwData.ACPI)

	// System Management BIOS tables
	smbios.ReportSMBIOS(&fwData.SMBIOS)

	// Intel Trusted Execution Technology public space
	if cpuVendor == cpuid.VendorIntel {
		txt.ReportTXTPublicSpace(&fwData.TXTPublicSpace)
	}

	// UEFI variables
	fwData.UEFIVariables = request.UEFIVariables
	uefivars.ReportUEFIVariables(fwData.UEFIVariables)

	// Trusted Platform Module event log
	if tpmConn != nil {
		srtmlog.ReportTPM2EventLog(&fwData.TPM2EventLog, tpmConn)
	}

	// Trusted Platform Module 2 properties
	fwData.TPM2Properties = request.TPM2Properties
	ReportTPM2Properties(fwData.TPM2Properties, tpmConn)

	// Trusted Platform Module 2 Non-Volatile Random Access Memory
	for _, nvIndex := range request.TPM2NVRAM {
		val := api.TPM2NVIndex{
			Index: nvIndex,
			Error: api.NotImplemented,
		}
		fwData.TPM2NVRAM = append(fwData.TPM2NVRAM, val)
	}

	// Intel Management Engine
	if cpuVendor == cpuid.VendorIntel {
		fwData.ME = request.ME
		heci.ReportMECommands(fwData.ME)
	}

	// Operating System information
	osinfo.ReportOSInfo(&fwData.OS)

	// Intel VT-d registers
	fwData.VTdRegisterSet.Error = api.NotImplemented

	// System memory map
	fwData.Memory.Error = api.NotImplemented

	logrus.Traceln("done gathering report data")
	return fwData, nil
}

func ReportTPM2Properties(properties []api.TPM2Property, tpmConn io.ReadWriteCloser) (err error) {
	logrus.Traceln("ReportTPM2Properties()")

	if tpmConn != nil {
		allFailed := true
		for i := range properties {
			v := &properties[i]
			val, err := tcg.Property(tpmConn, v.Property)
			allFailed = allFailed && err != nil
			if err != nil {
				v.Error = common.ServeApiError(err)
				logrus.Debugf("tcg.Property(): %s", err.Error())
			} else {
				v.Value = &val
			}
		}
		if allFailed && len(properties) > 0 {
			logrus.Warnf("Failed to get TPM 2.0 properties")
			return
		}
		err = nil
	} else {
		for i := range properties {
			properties[i].Error = api.NoResponse
		}
		err = errors.New("tpm connection is nil")
	}
	return
}
