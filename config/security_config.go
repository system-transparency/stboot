// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package config

import "fmt"

const SecurityCfgVersion int = 1

var (
	ErrSecurityCfgVersionMissmatch = InvalidError("version missmatch, want version " + fmt.Sprint(SecurityCfgVersion))
	ErrMissingBootMode             = InvalidError("boot mode must be set")
	ErrUnknownBootMode             = InvalidError("unknown boot mode")
)

type BootMode int

const (
	UnsetBootMode BootMode = iota
	LocalBoot
	NetworkBoot
)

func (b BootMode) String() string {
	switch b {
	case UnsetBootMode:
		return "unset"
	case LocalBoot:
		return "local"
	case NetworkBoot:
		return "network"
	default:
		return "unknown"
	}
}

// SecurityConfig contains security critical configuration data for a System Transparency host.
type SecurityCfg struct {
	Version                 int
	ValidSignatureThreshold uint
	BootMode
	UsePkgCache bool
}

var scValidators = []scValidator{
	checkSecurityConfigVersion,
	checkBootMode,
}

func checkSecurityConfigVersion(c *SecurityCfg) error {
	if c.Version != SecurityCfgVersion {
		return ErrSecurityCfgVersionMissmatch
	}
	return nil
}

func checkBootMode(c *SecurityCfg) error {
	if c.BootMode == UnsetBootMode {
		return ErrMissingBootMode
	}
	if c.BootMode > NetworkBoot {
		return ErrUnknownBootMode
	}
	return nil
}
