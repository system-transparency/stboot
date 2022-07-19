// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package host

import (
	"errors"
	"time"

	"github.com/system-transparency/stboot/sterror"
	"github.com/system-transparency/stboot/stlog"
	"github.com/u-root/u-root/pkg/mount"
	"github.com/u-root/u-root/pkg/mount/block"
	"golang.org/x/sys/unix"
)

// Operations used for raising Errors of this package.
const (
	ErrOpmountPartitionRetry sterror.Op = "mountPartitionRetry"
	ErrOpmountCdrom          sterror.Op = "mountCdrom"
	ErrOpmountPartition      sterror.Op = "mountPartition"
)

// Errors which may be raised and wrapped in this package.
var (
	ErrMount = errors.New("failed to mount")
)

const (
	DataPartitionFSType     = "ext4"
	DataPartitionLabel      = "STDATA"
	DataPartitionMountPoint = "data"
	BootPartitionFSType     = "vfat"
	BootPartitionLabel      = "STBOOT"
	BootPartitionMountPoint = "boot"
)

// Files at STBOOT partition.
const (
	HostConfigFile = "/host_configuration.json"
)

// Files at STDATA partition.
const (
	TimeFixFile        = "stboot/etc/system_time_fix"
	CurrentOSPkgFile   = "stboot/etc/current_ospkg_pathname"
	LocalOSPkgDir      = "stboot/os_pkgs/local/"
	LocalBootOrderFile = "stboot/os_pkgs/local/boot_order"
)

func MountBootPartition() error {
	return mountPartitionRetry(func() error {
		return mountPartition(BootPartitionLabel, BootPartitionFSType, BootPartitionMountPoint)
	})
}

func MountDataPartition() error {
	return mountPartitionRetry(func() error {
		return mountPartition(DataPartitionLabel, DataPartitionFSType, DataPartitionMountPoint)
	})
}

func MountCdrom() error {
	return mountPartitionRetry(mountCdrom)
}

func mountPartitionRetry(mountFunc func() error) error {
	retries := 8
	retryWait := 1

	var err error

	for try := 0; try < retries; try++ {
		err := mountFunc()
		if err == nil {
			break
		} else {
			err = sterror.E(ErrScope, ErrOpmountPartitionRetry, ErrMount, err.Error())
		}

		time.Sleep(time.Second * time.Duration(retryWait))
		stlog.Debug("Failed to mount %v, retry %v", err, try+1)
	}

	return err
}

func mountCdrom() error {
	mp, err := mount.Mount("/dev/sr0", BootPartitionMountPoint, "iso9660", "",
		unix.MS_RDONLY|unix.MS_NOATIME)
	if err == nil {
		stlog.Debug("Mounted device %s at %s", mp.Device, mp.Path)

		return nil
	}

	return sterror.E(ErrScope, ErrOpmountCdrom, err.Error())
}

func mountPartition(label, fsType, mountPoint string) error {
	devs, err := block.GetBlockDevices()
	if err != nil {
		return sterror.E(ErrScope, ErrOpmountPartition, err.Error())
	}

	devs = devs.FilterPartLabel(label)
	if len(devs) == 0 {
		return sterror.E(ErrScope, ErrOpmountPartition, "no matching disc partition found")
	}

	if len(devs) > 1 {
		stlog.Warn("Multiple partitions with label %s:", label)
		stlog.Warn("%v", devs)
		stlog.Warn("Takeing the first one!")
	}

	d := devs[0].DevicePath()

	mp, err := mount.Mount(d, mountPoint, fsType, "", 0)
	if err != nil {
		return sterror.E(ErrScope, ErrOpmountPartition, err.Error())
	}

	stlog.Debug("Mounted device %s at %s", mp.Device, mp.Path)

	return nil
}
