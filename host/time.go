// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package host

import (
	"errors"
	"time"

	"github.com/system-transparency/stboot/sterror"
	"github.com/system-transparency/stboot/stlog"
	"github.com/u-root/u-root/pkg/rtc"
)

// Operations used for raising Errors of this package.
const (
	ErrOpCheckSystemTime sterror.Op = "CheckSystemTime"
)

// Errors which may be raised and wrapped in this package.
var (
	ErrCheckingSystemTime = errors.New("failed to check system's time")
)

// CheckSystemTime sets RTC and OS time according buildtime.
func CheckSystemTime(builtTime time.Time) error {
	rtc, err := rtc.OpenRTC()
	if err != nil {
		return sterror.E(ErrScope, ErrOpCheckSystemTime, ErrCheckingSystemTime, err.Error())
	}

	rtcTime, err := rtc.Read()
	if err != nil {
		return sterror.E(ErrScope, ErrOpCheckSystemTime, ErrCheckingSystemTime, err.Error())
	}

	stlog.Info("Systemtime: %v", rtcTime.UTC())

	if rtcTime.UTC().Before(builtTime.UTC()) {
		stlog.Warn("Systemtime is invalid: %v", rtcTime.UTC())
		stlog.Warn("Set system time to stboot installation timestamp")
		stlog.Warn("System time will not be up to date!")
		stlog.Warn("Update RTC to %v", builtTime.UTC())

		err = rtc.Set(builtTime)
		if err != nil {
			return sterror.E(ErrScope, ErrOpCheckSystemTime, ErrCheckingSystemTime, err.Error())
		}

		stlog.Info("Set system time. Need to reboot.")
		Recover()
	}

	return nil
}
