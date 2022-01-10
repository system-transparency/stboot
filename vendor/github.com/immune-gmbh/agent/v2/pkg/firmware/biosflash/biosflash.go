package biosflash

import (
	"github.com/immune-gmbh/agent/v2/pkg/api"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/common"
	"github.com/klauspost/compress/zstd"
	"github.com/sirupsen/logrus"
)

func ReportBiosFlash(flash *api.ErrorBuffer) error {
	logrus.Traceln("ReportBiosFlash()")

	buf, err := readBiosFlashMMap()
	if err != nil {
		flash.Error = common.ServeApiError(common.MapFSErrors(err))
		logrus.Debugf("biosflash.ReportBiosFlash(): %s", err.Error())
		logrus.Warnf("Failed to read UEFI/BIOS flash")
		return err
	}
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		return err
	}
	flash.Data = encoder.EncodeAll(buf, make([]byte, 0, len(buf)))
	return nil
}
