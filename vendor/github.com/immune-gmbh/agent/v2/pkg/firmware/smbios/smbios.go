package smbios

import (
	"github.com/immune-gmbh/agent/v2/pkg/api"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/common"
	"github.com/sirupsen/logrus"
)

func ReportSMBIOS(table *api.ErrorBuffer) error {
	logrus.Traceln("ReportSMBIOS()")

	buf, err := readSMBIOS()
	if err != nil {
		table.Error = common.ServeApiError(common.MapFSErrors(err))
		logrus.Debugf("smbios.ReportSMBIOS(): %s", err.Error())
		logrus.Warnf("Failed to get SMBIOS tables")
		return err
	}
	table.Data = buf
	return nil
}
