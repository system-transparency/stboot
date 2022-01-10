package txt

import (
	"github.com/immune-gmbh/agent/v2/pkg/api"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/common"
	"github.com/sirupsen/logrus"
)

func ReportTXTPublicSpace(pubSpace *api.ErrorBuffer) error {
	logrus.Traceln("ReportTXTPublicSpace()")

	buf, err := readTXTPublicSpace()
	if err != nil {
		pubSpace.Error = common.ServeApiError(common.MapFSErrors(err))
		logrus.Debugf("txt.ReportTXTPublicSpace(): %s", err.Error())
		logrus.Warnf("Failed to get Intel TXT public space")
		return err
	}
	pubSpace.Data = buf
	return nil
}
