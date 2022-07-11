// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ospkg

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/system-transparency/stboot/stlog"
)

var (
	ErrManifestFromBytes            = errors.New("failed to parse os manifest from bytes")
	ErrOSBytes                      = errors.New("failed to serialize os manifest to bytes")
	ErrManifestWrite                = errors.New("cannot write manifest")
	ErrManifestWriteIsNotDir        = errors.New("is not a directory")
	ErrManifestWriteToDirectory     = errors.New("failed to write to directory")
	ErrInvalidManifest              = errors.New("invalid manifest")
	ErrInvalidManifestVersion       = errors.New("invalid version")
	ErrInvalidManifestKernelPath    = errors.New("missing kernel path")
	ErrInvalidManifestInitramfsPath = errors.New("missing initramfs path")
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
		return nil, fmt.Errorf("%w: %v", ErrManifestFromBytes, err)
	}

	return &m, nil
}

// Write saves m to file named by stboot.ManifestName at a path named by dir.
func (m *OSManifest) Write(dir string) error {
	stat, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrManifestWrite, err)
	}

	if !stat.IsDir() {
		stlog.Debug("%s is not a directory.", dir)

		return fmt.Errorf("%w: %v", ErrManifestWrite, ErrManifestWriteIsNotDir)
	}

	buf, err := m.Bytes()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrManifestWrite, err)

	}

	dst := filepath.Join(dir, ManifestName)

	err = ioutil.WriteFile(dst, buf, os.ModePerm)
	if err != nil {
		return fmt.Errorf("%w: %v %s: %v", ErrManifestWrite, ErrManifestWriteToDirectory, dir, err)
	}

	return nil
}

// Bytes serializes a manifest stuct into a byte slice.
func (m *OSManifest) Bytes() ([]byte, error) {
	buf, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOSBytes, err)
	}

	return buf, nil
}

// Validate returns no.
func (m *OSManifest) Validate() error {
	// Version
	if m.Version != ManifestVersion {
		stlog.Debug("manifest: invalid version %d. Want %d", m.Version, ManifestVersion)

		return fmt.Errorf("%w: %v", ErrInvalidManifest, ErrInvalidManifestVersion)
	}
	// Kernel path is mandatory
	if m.KernelPath == "" {
		stlog.Debug("manifest: missing kernel path")

		return fmt.Errorf("%w: %v", ErrInvalidManifest, ErrInvalidManifestKernelPath)
	}
	// Initramfs path is mandatory
	if m.InitramfsPath == "" {
		stlog.Debug("manifest: missing initramfs path")

		return fmt.Errorf("%w: %v", ErrInvalidManifest, ErrInvalidManifestInitramfsPath)
	}

	return nil
}
