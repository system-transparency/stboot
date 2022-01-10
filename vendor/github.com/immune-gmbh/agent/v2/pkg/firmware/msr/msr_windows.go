package msr

import "github.com/immune-gmbh/agent/v2/pkg/firmware/immunecpu"

const (
	ImmuneCPUDriverDeviceFile = "\\\\?\\GLOBALROOT\\Device\\immuneCPU"
)

func readMSR(cpu, msr uint32) (data uint64, err error) {
	return immunecpu.ReadMSR(cpu, msr)
}
