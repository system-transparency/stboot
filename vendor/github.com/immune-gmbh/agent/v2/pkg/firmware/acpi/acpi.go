package acpi

import (
	"github.com/immune-gmbh/agent/v2/pkg/api"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/common"
	"github.com/sirupsen/logrus"
)

func ReportACPITables(acpiTables *api.ACPITables) error {
	logrus.Traceln("ReportACPITables()")

	t, err := readACPITables()
	if err != nil {
		acpiTables.Error = common.ServeApiError(common.MapFSErrors(err))
		logrus.Debugf("acpi.ReadACPITables(): %s", err.Error())
		logrus.Warnf("Failed to get ACPI tables")
		return err
	}
	// map map to cast []byte to api.Buffer
	acpiTables.Tables = make(map[string]api.Buffer)
	for k, v := range t {
		acpiTables.Tables[k] = v
	}
	return nil
}
