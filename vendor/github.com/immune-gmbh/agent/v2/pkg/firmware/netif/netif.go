package netif

import (
	"strings"

	"github.com/immune-gmbh/agent/v2/pkg/api"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/common"
	"github.com/sirupsen/logrus"
)

func ReportMACAddresses(macs *api.MACAddresses) error {
	logrus.Traceln("ReportMACAddresses()")

	m, err := readMACAddresses()
	if err != nil {
		//XXX windows syscall errors should be targeted by this, however, the WMI package errors are more complicated and might need new mappings
		macs.Error = common.ServeApiError(common.MapFSErrors(err))
		logrus.Debugf("netif.ReportMACAddresses(): %s", err.Error())
		logrus.Warnf("Failed to get MAC addresses")
		return err
	}

	// normalize hex strings from different OSes to ensure diffability
	for i := range m {
		m[i] = strings.ToUpper(m[i])
	}

	macs.Addresses = m
	return nil
}
