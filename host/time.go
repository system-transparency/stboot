// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package host

import (
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/system-transparency/stboot/stlog"
	"github.com/u-root/u-root/pkg/rtc"
)

func ParseUNIXTimestamp(raw string) (time.Time, error) {
	reg, err := regexp.Compile("[^0-9]+")
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing UNIX timestamp: %v", err)
	}
	digits := reg.ReplaceAllString(raw, "")

	timeFixInt64, err := strconv.ParseInt(string(digits), 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing UNIX timestamp: %v", err)
	}
	return time.Unix(timeFixInt64, 0), nil
}

// validateSystemTime sets RTC and OS time according to
// realtime clock, timestamp and ntp
func CheckSystemTime(builtTime time.Time) error {
	rtc, err := rtc.OpenRTC()
	if err != nil {
		return fmt.Errorf("opening RTC failed: %v", err)
	}
	rtcTime, err := rtc.Read()
	if err != nil {
		return fmt.Errorf("reading RTC failed: %v", err)
	}

	stlog.Info("Systemtime: %v", rtcTime.UTC())
	if rtcTime.UTC().Before(builtTime.UTC()) {
		stlog.Warn("Systemtime is invalid: %v", rtcTime.UTC())
		stlog.Warn("Set system time to stboot installation timestamp")
		stlog.Warn("System time will not be up to date!")
		stlog.Warn("Update RTC to %v", builtTime.UTC())
		err = rtc.Set(builtTime)
		if err != nil {
			return fmt.Errorf("writing RTC failed: %v", err)
		}
		stlog.Info("Set system time. Need to reboot.")
		Recover()
	}
	return nil
}
