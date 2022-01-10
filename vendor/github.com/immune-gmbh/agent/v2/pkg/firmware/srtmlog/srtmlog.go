package srtmlog

import (
	"io"

	"github.com/immune-gmbh/agent/v2/pkg/api"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/common"
	"github.com/sirupsen/logrus"
)

func ReportTPM2EventLog(log *api.ErrorBuffer, conn io.ReadWriteCloser) error {
	logrus.Traceln("ReportTPM2EventLog()")

	buf, err := readTPM2EventLog(conn)
	if err != nil {
		logrus.Debugf("srtmlog.ReportTPM2EventLog(): %s", err.Error())
		logrus.Warnf("Failed to read TPM 2.0 event log")
		//XXX map tpmutil errors
		log.Error = common.ServeApiError(common.MapFSErrors(err))
		return err
	}
	log.Data = buf
	return nil
}
