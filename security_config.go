package main

import (
	"fmt"
)

const SecurityConfigVersion int = 1

//go:generate jsonenums -type=bootmode
type bootmode int

// bootmodes values defines where to load a OS package from.
const (
	Local bootmode = iota
	Network
)

func (b bootmode) String() string {
	return []string{"local", "network"}[b]
}

// SecurityConfig contains platform-specific data.
type SecurityConfig struct {
	Version                int      `json:"version"`
	MinimalSignaturesMatch int      `json:"minimal_signatures_match"`
	BootMode               bootmode `json:"boot_mode"`
	UsePkgCache            bool     `json:"use_ospkg_cache"`

	isValid bool
}

// Validate checks the integrety of sc.
func (sc *SecurityConfig) Validate() error {
	if sc.isValid {
		return nil
	}
	if sc.Version != SecurityConfigVersion {
		return fmt.Errorf("version missmatch, want %d, got %d", SecurityConfigVersion, sc.Version)
	}
	if sc.MinimalSignaturesMatch < 0 {
		return fmt.Errorf("minimal signatures match cannot be negative")
	}
	sc.isValid = true
	return nil
}
