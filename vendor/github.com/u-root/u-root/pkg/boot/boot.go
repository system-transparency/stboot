// Copyright 2018 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package boot is the high-level interface for booting another operating
// system from Linux using kexec.
package boot

import (
	"fmt"

	"github.com/u-root/u-root/pkg/boot/kexec"
)

// OSImage represents a bootable OS package.
type OSImage interface {
	fmt.Stringer

	// Label is a name or short description for this OSImage.
	//
	// Label is intended for boot menus.
	Label() string

	// Rank the priority of the images for boot menus.
	//
	// The larger the number, the prior the image shows in the menu.
	Rank() int

	// Edit the kernel command line if possible. Must be called before
	// Load.
	Edit(func(cmdline string) string)

	// Load loads the OS image into kernel memory, ready for execution.
	//
	// After Load is called, call boot.Execute() to stop Linux and boot the
	// loaded OSImage.
	Load(verbose bool) error
}

// Execute executes a previously loaded OSImage.
//
// This will only work if OSImage.Load was called on some OSImage.
func Execute() error {
	return kexec.Reboot()
}
