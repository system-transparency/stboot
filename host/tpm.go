// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package host

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/u-root/u-root/pkg/tss"
	"system-transparency.org/stboot/sterror"
)

// Scope and operations used for raising Errors of this package.
const (
	ErrScope        sterror.Scope = "Host"
	ErrOpMeasureTPM sterror.Op    = "MeasureTPM"
)

// stboot events
const (
	OspkgArchive   uint32 = 0xa0000000
	OspkgManifest  uint32 = 0xa0000001
	SecurityConfig uint32 = 0xa0000002
	SigningRoot    uint32 = 0xa0000003
	HttpsRoot      uint32 = 0xa0000004

	DetailPcr    uint32 = 12
	AuthorityPcr uint32 = 13
	IdentityPcr  uint32 = 14
)

var (
	specIdEvent = append(append(append(append(
		[]byte{
			0x00, 0x00, 0x00, 0x00,
			0x03, 0x00, 0x00, 0x00,
		},
		make([]byte, 20)...),
		[]byte{0x25, 0x00, 0x00, 0x00}...),
		[]byte("Spec ID Event03\000")...),
		[]byte{
			0x00, 0x00, 0x00, 0x00,
			0x00,
			0x02,
			0x02,
			0x02,
			0x02, 0x00, 0x00, 0x00,
			0x04, 0x00,
			20, 0x00,
			0x0b, 0x00,
			32, 0x00,
			0x00,
		}...)
)

// Errors which may be raised and wrapped in this package.
var (
	ErrTPM = errors.New("failed to measure TPM")
)

type Event struct {
	Index  uint32
	Type   uint32
	Data   []byte
	Sha256 []byte
}

type Measurements struct {
	tpm *tss.TPM
	log []Event
}

func NewMeasurements() (*Measurements, error) {
	tpm, err := tss.NewTPM()
	if err != nil {
		return nil, err
	}
	return &Measurements{tpm: tpm}, nil
}

func (m *Measurements) Info() (*tss.TPMInfo, error) {
	return m.tpm.Info()
}

// returns serialized TPM 2.0 event log
func (m *Measurements) Finalize() ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	// add spec id event
	if _, err := buf.Write(specIdEvent); err != nil {
		return nil, err
	}

	// add events
	for _, event := range m.log {
		if err := binary.Write(buf, binary.LittleEndian, event.Index); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.LittleEndian, event.Type); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.LittleEndian, uint32(1)); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.LittleEndian, tpm2.AlgSHA256); err != nil {
			return nil, err
		}
		if _, err := buf.Write(event.Sha256); err != nil {
			return nil, err
		}
		if err := binary.Write(buf, binary.LittleEndian, uint32(len(event.Data))); err != nil {
			return nil, err
		}
		if _, err := buf.Write(event.Data); err != nil {
			return nil, err
		}
	}

	err := m.tpm.Close()
	return buf.Bytes(), err
}

func (m *Measurements) Add(index uint32, ty uint32, sha256 [32]byte, data []byte) error {
	if err := m.tpm.Measure(sha256[:], index); err != nil {
		return sterror.E(ErrScope, ErrOpMeasureTPM, ErrTPM, fmt.Sprintf("failed to measure: %v", err))
	}

	m.log = append(m.log, Event{
		Index:  index,
		Type:   ty,
		Data:   data,
		Sha256: sha256[:],
	})

	return nil
}
