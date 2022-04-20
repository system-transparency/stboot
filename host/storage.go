// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package host

import (
	"fmt"
	"time"

	"github.com/system-transparency/stboot/stlog"
	"github.com/u-root/u-root/pkg/mount"
	"github.com/u-root/u-root/pkg/mount/block"
	"golang.org/x/sys/unix"
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
		return MountPartition(BootPartitionLabel, BootPartitionFSType, BootPartitionMountPoint)
	})
}

func MountDataPartition() error {
	return mountPartitionRetry(func() error {
		return MountPartition(DataPartitionLabel, DataPartitionFSType, DataPartitionMountPoint)
	})
}

func MountCdrom() error {
	return mountPartitionRetry(mountCdrom)
}

func mountPartitionRetry(fn func() error) error {
	retries := 8
	retryWait := 1

	var err error = nil

	for i := 0; i < retries; i++ {
		err := fn()
		if err == nil {
			break
		}

		time.Sleep(time.Second * time.Duration(retryWait))
		stlog.Debug("Failed to mount %v, retry %v", err, i+1)
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

	return fmt.Errorf("failed to mount CDROM (/dev/sr0)")
}

func MountPartition(label, fsType, mountPoint string) error {
	devs, err := block.GetBlockDevices()
	if err != nil {
		return fmt.Errorf("host storage: %v", err)
	}

	devs = devs.FilterPartLabel(label)
	if len(devs) == 0 {
		return fmt.Errorf("host storage: no partition with label %s", label)
	}

	if len(devs) > 1 {
		return fmt.Errorf("host storage: multiple partitions with label %s", label)
	}

	d := devs[0].DevicePath()

	mp, err := mount.Mount(d, mountPoint, fsType, "", 0)
	if err != nil {
		return fmt.Errorf("host storage: %v", err)
	}

	stlog.Debug("Mounted device %s at %s", mp.Device, mp.Path)

	return nil
}
