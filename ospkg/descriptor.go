// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ospkg

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"

	"system-transparency.org/stboot/sterror"
	"system-transparency.org/stboot/stlog"
)

// Operations used for raising Errors of this package.
const (
	ErrOpDescFromFile  sterror.Op = "DescriptorFromFile"
	ErrOpDescFromBytes sterror.Op = "DescriptorFomBytes"
	ErrOpDescBytes     sterror.Op = "Descriptor.Bytes"
	ErrOpDValidate     sterror.Op = "Descriptor.Validate"
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
	bytes, err := os.ReadFile(src)
	if err != nil {
		return nil, sterror.E(ErrScope, ErrOpDescFromFile, ErrParse, err.Error())
	}

	return DescriptorFromBytes(bytes)
}

// DescriptorFromBytes parses a manifest from a byte slice.
func DescriptorFromBytes(data []byte) (*Descriptor, error) {
	var d Descriptor
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, sterror.E(ErrScope, ErrOpDescFromBytes, ErrParse, err.Error())
	}

	return &d, nil
}

// Bytes serializes a manifest stuct into a byte slice.
func (d *Descriptor) Bytes() ([]byte, error) {
	buf, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, sterror.E(ErrScope, ErrOpDescBytes, ErrSerialize, err.Error())
	}

	return buf, nil
}

// Validate returns true if d has valid content.
func (d *Descriptor) Validate() error {
	// Version
	if d.Version != DescriptorVersion {
		stlog.Debug("descriptor: invalid version %d. Want %d", d.Version, DescriptorVersion)

		return sterror.E(ErrScope, ErrOpDValidate, ErrValidate, fmt.Sprintf(ErrInfoInvalidVer, d.Version, DescriptorVersion))
	}

	// Package URL
	u, err := url.Parse(d.PkgURL)
	if err != nil {
		return sterror.E(ErrScope, ErrOpDValidate, ErrValidate, "invalid package url")
	}

	if d.PkgURL != "" && u.Scheme == "" {
		stlog.Debug("descriptor: invalid package URL: missing scheme")

		return sterror.E(ErrScope, ErrOpDValidate, ErrValidate, ErrInfoMissingScheme)
	}

	return nil
}
