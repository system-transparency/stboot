package msr

import (
	"fmt"

	"github.com/fearful-symmetry/gomsr"
)

func readMSR(cpu, msr uint32) (data uint64, err error) {
	if (cpu & 0x80000000) > 0 {
		return 0, fmt.Errorf("cpu number too large for int: %d", cpu)
	}
	ctx, err := gomsr.MSR(int(cpu))
	if err != nil {
		return 0, fmt.Errorf("no MSR support for core %d", cpu)
	}
	defer ctx.Close()
	data, err = ctx.Read(int64(msr))
	if err != nil {
		return 0, err
	}
	return
}
