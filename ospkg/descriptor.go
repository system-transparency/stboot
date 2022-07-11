// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ospkg

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"

	"github.com/system-transparency/stboot/stlog"
)

var (
	ErrDescriptorFromFile             = errors.New("failed to parse manifest from file")
	ErrDescriptorFromBytes            = errors.New("failed to parse manifest from bytes")
	ErrBytes                          = errors.New("failed to serialize manifest to bytes")
	ErrInvalidDescriptor              = errors.New("invalid descriptor")
	ErrInvalidDescriptorVersion       = errors.New("invalid version")
	ErrInvalidDescriptorPkgURL        = errors.New("invalid package url")
	ErrInvalidDescriptorMissingScheme = errors.New("missing scheme")
)

const (
	DescriptorVersion int = 1
	// DescriptorExt is the file extension of OS package descriptor file.
	DescriptorExt string = ".json"
)

// Descriptor represents the descriptor JSON file of an OS package.
type Descriptor struct {
	Version int    `json:"version"`
	PkgURL  string `json:"os_pkg_url"`

	Certificates [][]byte `json:"certificates"`
	Signatures   [][]byte `json:"signatures"`
}

// DescriptorFromFile parses a manifest from a json file.
func DescriptorFromFile(src string) (*Descriptor, error) {
	bytes, err := ioutil.ReadFile(src)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDescriptorFromFile, err)
	}

	return DescriptorFromBytes(bytes)
}

// DescriptorFromBytes parses a manifest from a byte slice.
func DescriptorFromBytes(data []byte) (*Descriptor, error) {
	var d Descriptor
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDescriptorFromBytes, err)
	}

	return &d, nil
}

// Bytes serializes a manifest stuct into a byte slice.
func (d *Descriptor) Bytes() ([]byte, error) {
	buf, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBytes, err)
	}

	return buf, nil
}

// Validate returns true if d has valid content.
func (d *Descriptor) Validate() error {
	// Version
	if d.Version != DescriptorVersion {
		stlog.Debug("descriptor: invalid version %d. Want %d", d.Version, DescriptorVersion)

		return fmt.Errorf("%w: %v", ErrInvalidDescriptor, ErrInvalidDescriptorVersion)
	}

	// Package URL
	u, err := url.Parse(d.PkgURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidDescriptor, ErrInvalidDescriptorPkgURL)
	}

	if d.PkgURL != "" && u.Scheme == "" {
		stlog.Debug("descriptor: invalid package URL: missing scheme")

		return fmt.Errorf("%w: %v", ErrInvalidDescriptor, ErrInvalidDescriptorMissingScheme)
	}

	return nil
}
