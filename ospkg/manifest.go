// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ospkg

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/system-transparency/stboot/stlog"
)

const (
	ErrInvalidManifest = Error("invalid manifest")
	ErrManifestWrite   = Error("cannot write manifest")
)

const (
	ManifestVersion int = 1
	// ManifestName is the name of OS packages' internal configuration file.
	ManifestName string = "manifest.json"
)

// OSManifest describes the content and configuration of an OS package
// loaded by stboot.
type OSManifest struct {
	Version int    `json:"version"`
	Label   string `json:"label"`

	KernelPath    string `json:"kernel"`
	InitramfsPath string `json:"initramfs"`
	Cmdline       string `json:"cmdline"`
}

func NewOSManifest(label, kernelPath, initramfsPath, cmdline string) *OSManifest {
	return &OSManifest{
		Version:       ManifestVersion,
		Label:         label,
		KernelPath:    kernelPath,
		InitramfsPath: initramfsPath,
		Cmdline:       cmdline,
	}
}

// OSManifestFromBytes parses a manifest from a byte slice.
func OSManifestFromBytes(data []byte) (*OSManifest, error) {
	var m OSManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("descriptor: parsing failed: %w", err)
	}

	return &m, nil
}

// Write saves m to file named by stboot.ManifestName at a path named by dir.
func (m *OSManifest) Write(dir string) error {
	stat, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("OSManitest write: %w", err)
	}

	if !stat.IsDir() {
		stlog.Debug("%s is not a directory.", dir)

		return ErrManifestWrite
	}

	buf, err := m.Bytes()
	if err != nil {
		return err
	}

	dst := filepath.Join(dir, ManifestName)

	err = ioutil.WriteFile(dst, buf, os.ModePerm)
	if err != nil {
		return fmt.Errorf("manifest: writing to %s failed: %w", dir, err)
	}

	return nil
}

// Bytes serializes a manifest stuct into a byte slice.
func (m *OSManifest) Bytes() ([]byte, error) {
	buf, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("manifest: serializing failed: %w", err)
	}

	return buf, nil
}

// Validate returns no.
func (m *OSManifest) Validate() error {
	// Version
	if m.Version != ManifestVersion {
		stlog.Debug("manifest: invalid version %d. Want %d", m.Version, ManifestVersion)

		return ErrInvalidManifest
	}
	// Kernel path is mandatory
	if m.KernelPath == "" {
		stlog.Debug("manifest: missing kernel path")

		return ErrInvalidManifest
	}
	// Initramfs path is mandatory
	if m.InitramfsPath == "" {
		stlog.Debug("manifest: missing initramfs path")

		return ErrInvalidManifest
	}

	return nil
}
