// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package host

import (
	"fmt"

	"github.com/system-transparency/stboot/stlog"
	"github.com/u-root/u-root/pkg/mount"
	"github.com/u-root/u-root/pkg/mount/block"
)

const (
	DataPartitionFSType     = "ext4"
	DataPartitionLabel      = "STDATA"
	DataPartitionMountPoint = "data"
	BootPartitionFSType     = "vfat"
	BootPartitionLabel      = "STBOOT"
	BootPartitionMountPoint = "boot"
)

func MountBootPartition() error {
	return mountPartition(BootPartitionLabel, BootPartitionFSType, BootPartitionMountPoint, 60)
}

func MountDataPartition() error {
	return mountPartition(DataPartitionLabel, DataPartitionFSType, DataPartitionMountPoint, 60)
}

func mountPartition(label, fsType, mountPoint string, timeout uint) error {
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
