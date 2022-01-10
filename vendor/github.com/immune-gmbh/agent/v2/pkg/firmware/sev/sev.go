package sev

import (
	"github.com/immune-gmbh/agent/v2/pkg/api"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/common"
	"github.com/sirupsen/logrus"
)

func reportSEVCommand(cmd *api.SEVCommand) error {
	val, err := runSEVCommand(cmd.Command, cmd.ReadLength)
	if err != nil {
		logrus.Debugf("sev.ReportSEVCommand(): %s", err.Error())
		cmd.Error = common.ServeApiError(common.MapFSErrors(err))
		return err
	}

	buf := api.Buffer(val)
	cmd.Response = &buf
	return nil
}

func ReportSEVCommands(cmds []api.SEVCommand) (err error) {
	logrus.Traceln("ReportSEVCommands()")

	allFailed := true
	for i := range cmds {
		v := &cmds[i]
		err = reportSEVCommand(v)
		allFailed = allFailed && err != nil
	}
	if allFailed && len(cmds) > 0 {
		logrus.Warnf("Failed to access AMD SecureProcessor")
		return
	}

	err = nil
	return
}
