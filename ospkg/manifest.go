// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ospkg

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

const (
	ManifestVersion int = 1
	// ManifestName is the name of OS packages' internal configuration file
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

	TbootPath string   `json:"tboot"`
	TbootArgs string   `json:"tboot_args"`
	ACMPaths  []string `json:"acms"`
}

func NewOSManifest(label, kernelPath, initramfsPath, cmdline, tbootPath, tbootArgs string, acmPaths []string) *OSManifest {
	return &OSManifest{
		Version:       ManifestVersion,
		Label:         label,
		KernelPath:    kernelPath,
		InitramfsPath: initramfsPath,
		Cmdline:       cmdline,
		TbootPath:     tbootPath,
		TbootArgs:     tbootArgs,
		ACMPaths:      acmPaths,
	}
}

// OSManifestFromFile parses a manifest from a json file
func OSManifestFromFile(src string) (*OSManifest, error) {
	bytes, err := ioutil.ReadFile(src)
	if err != nil {
		return nil, fmt.Errorf("manifest: cannot find JSON: %v", err)
	}
	return OSManifestFromBytes(bytes)
}

func OSManifestFromStream(stream io.Reader) (*OSManifest, error) {
	bytes, err := streamToBytes(stream)
	if err != nil {
		return nil, fmt.Errorf("manifest: byte conversion failed: %v", err)
	}
	return OSManifestFromBytes(bytes)
}

// OSManifestFromBytes parses a manifest from a byte slice.
func OSManifestFromBytes(data []byte) (*OSManifest, error) {
	var m OSManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("descriptor: parsing failed: %v", err)
	}
	return &m, nil
}

// Write saves m to file named by stboot.ManifestName at a path named by dir.
func (m *OSManifest) Write(dir string) error {
	stat, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !stat.IsDir() {
		return fmt.Errorf("manifest: not a directory: %s", dir)
	}

	buf, err := m.Bytes()
	if err != nil {
		return err
	}
	dst := filepath.Join(dir, ManifestName)
	err = ioutil.WriteFile(dst, buf, os.ModePerm)
	if err != nil {
		return fmt.Errorf("manifest: writing to %s failed: %v", dir, err)
	}
	return nil
}

// Bytes serializes a manifest stuct into a byte slice.
func (m *OSManifest) Bytes() ([]byte, error) {
	buf, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("manifest: serializing failed: %v", err)
	}
	return buf, nil
}

// Validate returns no.
func (m *OSManifest) Validate() error {
	// Version
	if m.Version != ManifestVersion {
		return fmt.Errorf("manifest: invalid version %d. Want %d", m.Version, ManifestVersion)
	}
	// Kernel path is mandatory
	if m.KernelPath == "" {
		return errors.New("manifest: missing kernel path")
	}
	// Initramfs path is mandatory
	if m.InitramfsPath == "" {
		return errors.New("manifest: missing initramfs path")
	}
	// tboot
	if m.TbootPath != "" && len(m.ACMPaths) == 0 {
		return errors.New("manifest: tboot provided but missing ACM")
	}
	return nil
}

func streamToBytes(stream io.Reader) ([]byte, error) {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(stream)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
