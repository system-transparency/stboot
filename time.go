package main

import (
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/u-root/u-root/pkg/rtc"
)

func parseUNIXTimestamp(raw string) (time.Time, error) {
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
func checkSystemTime(builtTime time.Time) error {
	rtc, err := rtc.OpenRTC()
	if err != nil {
		return fmt.Errorf("opening RTC failed: %v", err)
	}
	rtcTime, err := rtc.Read()
	if err != nil {
		return fmt.Errorf("reading RTC failed: %v", err)
	}

	info("Systemtime: %v", rtcTime.UTC())
	if rtcTime.UTC().Before(builtTime.UTC()) {
		info("Systemtime is invalid: %v", rtcTime.UTC())
		info("Set system time to stboot installation timestamp")
		info("WARNING: System time will not be up to date!")
		info("Update RTC to %v", builtTime.UTC())
		err = rtc.Set(builtTime)
		if err != nil {
			return fmt.Errorf("writing RTC failed: %v", err)
		}
		reboot("Set system time. Need to reboot.")
	}
	return nil
}
