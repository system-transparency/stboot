// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package host exposes functionality to interact with the host mashine.
package host

import (
	"errors"
	"fmt"
	"math/rand"
	"syscall"
	"time"

	"github.com/system-transparency/stboot/stlog"
)

var (
	ErrRecover = errors.New("reboot of the system failed")
)

// Recover reboots the system after RecoverTimeout secounds.
// If reboot fails, it will try rebooting forever.
func Recover() {
	const (
		timeout   = 6 * time.Second
		randomMax = 10
		randomMin = 2
	)

	time.Sleep(timeout)

	for {
		stlog.Info("Recover ...")

		err := syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART)
		if err != nil {
			err = fmt.Errorf("%w: %v", ErrRecover, err)
			stlog.Error("%v", err)
		}

		// nolint:gosec
		// math/rand is sufficient here, nothing security related
		n := rand.Intn(randomMax-randomMin) + randomMin
		time.Sleep(time.Duration(n) * time.Second)
	}
}
