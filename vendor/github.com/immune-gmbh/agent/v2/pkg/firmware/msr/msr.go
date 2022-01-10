package msr

import (
	"fmt"
	"runtime"

	"github.com/immune-gmbh/agent/v2/pkg/api"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/common"
	"github.com/immune-gmbh/agent/v2/pkg/util"
	"github.com/shirou/gopsutil/cpu"
	"github.com/sirupsen/logrus"
)

func reportMSR(msr *api.MSR) error {
	cpu, err := cpu.Counts(false)
	if err != nil {
		return err
	}

	var values []uint64
	completeFailure := true
	for i := 0; i < cpu; i++ {
		var value uint64
		// -> if at least one readout works, there is no error
		value, err = readMSR(uint32(i), msr.MSR)
		if err != nil {
			logrus.Tracef("[MSR] couldn't read msr %x on core %d: %s", msr.MSR, i, err)
			continue
		}
		completeFailure = false
		values = append(values, value)
	}

	if completeFailure {
		return fmt.Errorf("couldn't read msr %x", msr.MSR)
	}

	msr.Values = values
	return nil
}

func ReportMSRs(MSRs []api.MSR) error {
	logrus.Traceln("ReportMSRs()")

	completeFailure := true
	var err error
	for i := range MSRs {
		v := &MSRs[i]
		err = reportMSR(v)
		completeFailure = completeFailure && err != nil
		if err != nil {
			logrus.Debugf("[MSR] %v", err.Error())
			v.Error = common.ServeApiError(common.MapFSErrors(err))
		}
	}
	if completeFailure && len(MSRs) > 0 {
		logrus.Warnf("Failed to access model specific registers")
		if runtime.GOOS == "linux" {
			loaded, err := util.IsKernelModuleLoaded("msr")
			if err != nil {
				logrus.Warnf("error checking if msr kernel module is loaded: %v", err.Error())
			} else if !loaded {
				logrus.Warnf("msr kernel module is not loaded")
			}
		}
		return err
	}

	return nil
}
