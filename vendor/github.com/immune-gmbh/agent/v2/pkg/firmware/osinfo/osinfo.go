package osinfo

import (
	"os"

	"github.com/immune-gmbh/agent/v2/pkg/api"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/common"
	"github.com/sirupsen/logrus"
)

// XXX the stuct filled by this function has inconsistent error reporting semantics
func ReportOSInfo(osInfo *api.OS) error {
	logrus.Traceln("ReportOSInfo()")

	release, err := readOSReleasePrettyName()
	if err != nil {
		osInfo.Error = common.ServeApiError(common.MapFSErrors(err))
		logrus.Debugf("osinfo.ReportOSInfo(): %s", err.Error())
		logrus.Warnf("Failed to gather host informations")
		return err
	}
	osInfo.Release = release

	hostname, err := os.Hostname()
	if err != nil {
		osInfo.Error = common.ServeApiError(common.MapFSErrors(err))
		logrus.Debugf("osinfo.ReportOSInfo(): %s", err.Error())
		logrus.Warnf("Failed to gather host informations")
		return err
	}
	osInfo.Hostname = hostname

	return nil
}
