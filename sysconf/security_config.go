// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sysconf

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/system-transparency/stboot/host"
	"github.com/system-transparency/stboot/ospkg"
	"github.com/system-transparency/stboot/stlog"
)

const SecurityConfigVersion int = 1

//go:generate jsonenums -type=bootmode
type Bootmode int

// bootmodes values defines where to load a OS package from.
const (
	Local Bootmode = iota
	Network
)

func (b Bootmode) String() string {
	return []string{"local", "network"}[b]
}

// SecurityConfig contains platform-specific data.
type SecurityConfig struct {
	Version                int      `json:"version"`
	MinimalSignaturesMatch int      `json:"minimal_signatures_match"`
	BootMode               Bootmode `json:"boot_mode"`
	UsePkgCache            bool     `json:"use_ospkg_cache"`

	isValid bool
}

func LoadSecurityConfig(path string) (*SecurityConfig, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %v", err)
	}
	var sc SecurityConfig
	if err = json.Unmarshal(b, &sc); err != nil {
		return nil, fmt.Errorf("parsing JSON failed: %v", err)
	}

	str, _ := json.MarshalIndent(sc, "", "  ")
	stlog.Debug("Security configuration: %s", str)

	if err = sc.Validate(); err != nil {
		return nil, fmt.Errorf("invalid: %v", err)
	}
	return &sc, nil
}

func LoadBootOrder(path, localOSPkgDir string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %v", err)
	}

	var names []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		names = append(names, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scann file: %v", err)
	}
	f.Close()
	if len(names) == 0 {
		return nil, fmt.Errorf("no entries found")
	}

	var bootorder []string
	for _, name := range names {
		ext := filepath.Ext(name)
		if ext == ospkg.OSPackageExt || ext == ospkg.DescriptorExt {
			name = strings.TrimSuffix(name, ext)
		}
		p := filepath.Join(host.DataPartitionMountPoint, localOSPkgDir, name+ospkg.OSPackageExt)
		_, err := os.Stat(p)
		if err != nil {
			stlog.Debug("Skip %s: %v", name, err)
			continue
		}
		p = filepath.Join(host.DataPartitionMountPoint, localOSPkgDir, name+ospkg.DescriptorExt)
		_, err = os.Stat(p)
		if err != nil {
			stlog.Debug("Skip %s: %v", name, err)
			continue
		}
		bootorder = append(bootorder, name)
	}
	if len(bootorder) == 0 {
		return nil, fmt.Errorf("no valid entries found")
	}
	return bootorder, nil
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
