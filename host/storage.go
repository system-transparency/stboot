// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package host

import (
	"errors"
	"time"

	"git.glasklar.is/system-transparency/core/stboot/sterror"
	"git.glasklar.is/system-transparency/core/stboot/stlog"
	"github.com/u-root/u-root/pkg/mount"
	"golang.org/x/sys/unix"
)

// Operations used for raising Errors of this package.
const (
	ErrOpTryMount   sterror.Op = "tryMount"
	ErrOpMountCdrom sterror.Op = "mountCdrom"
)

// Errors which may be raised and wrapped in this package.
var (
	ErrMount = errors.New("failed to mount")
)

const (
	MountPoint = "boot"
)

func MountCdrom() error {
	return tryMount(mountCdrom)
}

func tryMount(mountFunc func() error) error {
	retries := 8
	retryWait := 1

	var err error

	for try := 0; try < retries; try++ {
		err := mountFunc()
		if err == nil {
			break
		} else {
			err = sterror.E(ErrScope, ErrOpTryMount, ErrMount, err.Error())
		}

		time.Sleep(time.Second * time.Duration(retryWait))
		stlog.Debug("Failed to mount %v, retry %v", err, try+1)
	}

	return err
}

func mountCdrom() error {
	mp, err := mount.Mount("/dev/sr0", MountPoint, "iso9660", "",
		unix.MS_RDONLY|unix.MS_NOATIME)
	if err == nil {
		stlog.Debug("Mounted device %s at %s", mp.Device, mp.Path)

		return nil
	}

	return sterror.E(ErrScope, ErrOpMountCdrom, err.Error())
}
