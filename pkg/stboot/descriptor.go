package stboot

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/url"
)

const DescriptorVersion int = 1

// Descriptor represents the descriptor JSON file of an OS package
type Descriptor struct {
	Version int    `json:"version"`
	PkgURL  string `json:"os_pkg_url"`

	Certificates [][]byte `json:"certificates"`
	Signatures   [][]byte `json:"signatures"`
}

// DescriptorFromFile parses a manifest from a json file
func DescriptorFromFile(src string) (*Descriptor, error) {
	bytes, err := ioutil.ReadFile(src)
	if err != nil {
		return nil, fmt.Errorf("descriptor: cannot find JSON: %v", err)
	}
	return DescriptorFromBytes(bytes)
}

// DescriptorFromBytes parses a manifest from a byte slice.
func DescriptorFromBytes(data []byte) (*Descriptor, error) {
	var d Descriptor
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("descriptor: parsing failed: %v", err)
	}
	return &d, nil
}

// Bytes serializes a manifest stuct into a byte slice.
func (d *Descriptor) Bytes() ([]byte, error) {
	buf, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("descriptor: serializing failed: %v", err)
	}
	return buf, nil
}

// Validate returns true if s has valid content.
func (d *Descriptor) Validate() error {
	// Version
	if d.Version != DescriptorVersion {
		return fmt.Errorf("descriptor: invalid version %d. Want %d", d.Version, DescriptorVersion)
	}

	// Package URL
	u, err := url.Parse(d.PkgURL)
	if err != nil {
		return fmt.Errorf("descriptor: invalid invalid package URL: %v", err)
	}
	if d.PkgURL != "" && u.Scheme == "" {
		return fmt.Errorf("descriptor: invalid invalid package URL: missing scheme")
	}
	return nil
}
