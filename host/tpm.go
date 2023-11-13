// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package host

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-tpm/tpm2"
	"github.com/u-root/u-root/pkg/tss"
	"system-transparency.org/stboot/sterror"
)

type EventType uint32

// Scope and operations used for raising Errors of this package.
const (
	ErrScope        sterror.Scope = "Host"
	ErrOpMeasureTPM sterror.Op    = "MeasureTPM"
	ErrOpIdentity   sterror.Op    = "Identity"
)

// stboot events.
const (
	// PCR[12]: Detail measurements.

	// The SHA-256 hash of ospkg zip archive. The event log note is the archive's
	// file name. Only measured once.
	OspkgArchive EventType = 0xa0000000

	// The SHA-256 hash of the ospkg JSON manifest. The event log note is the
	// manifest itself. Only measured once.
	OspkgManifest EventType = 0xa0000001

	// PCR[13]: Authority measurements.

	// The SHA-256 hash of the stboot trust policy. The event log note is the
	// policy itself. Only measured once.
	SecurityConfig EventType = 0xa0000002

	// The SHA-256 hash of the root X.509 certificate used to verify the ospkg
	// signing key. The event log note is the X.509 DER certificate. Only measured once.
	SigningRoot EventType = 0xa0000003

	// The SHA-256 hash of all X.509 certificate used to verify the TLS connection
	// used to fetch the ospkg. The X.509 certificates are concatenated. The
	// event log note is the X.509 DER certificate. Only measured once.
	HTTPSRoot EventType = 0xa0000004

	// PCR[14]: Identity measurements.

	// The SHA-256 hash of the platform's human-readable identity. The event log
	// note is the identity itself.
	UxIdentity EventType = 0xa0000005

	DetailPcr    uint32 = 12
	AuthorityPcr uint32 = 13
	IdentityPcr  uint32 = 14

	sha1HashSize = 20

	uxIdentityIndex = 0x01_420001
)

// Errors which may be raised and wrapped in this package.
var (
	ErrTPM    = errors.New("failed to measure TPM")
	ErrNoInit = errors.New("TPM not initialized")
)

type Event struct {
	Index  uint32
	Type   EventType
	Data   []byte
	Sha256 []byte
}

type Measurements struct {
	tpm *tss.TPM
	log []Event
}

func NewMeasurements() *Measurements {
	tpm, err := tss.NewTPM()
	if err != nil {
		tpm = nil
	}

	return &Measurements{tpm: tpm}
}

func (m *Measurements) Info() (*tss.TPMInfo, error) {
	if m.tpm == nil {
		return nil, sterror.E(ErrScope, ErrOpMeasureTPM, ErrNoInit)
	}

	return m.tpm.Info()
}

// returns serialized TPM 2.0 event log.
func (m *Measurements) Finalize() ([]byte, error) {
	if m.tpm == nil {
		return nil, sterror.E(ErrScope, ErrOpMeasureTPM, ErrNoInit)
	}

	buf := bytes.NewBuffer(nil)

	// add spec id event.
	if err := specIDEvent(buf); err != nil {
		return nil, err
	}

	// add events.
	for _, event := range m.log {
		ev := event
		if err := m.addEvent(&ev, buf); err != nil {
			return nil, err
		}
	}

	err := m.tpm.Close()

	return buf.Bytes(), err
}

func (m *Measurements) Identity() (string, error) {
	if m.tpm == nil {
		return "", sterror.E(ErrScope, ErrOpIdentity, ErrNoInit)
	}

	rawid, err := tpm2.NVReadEx(m.tpm.RWC, uxIdentityIndex, uxIdentityIndex, "", 0)
	if err != nil {
		return "", sterror.E(ErrScope, ErrOpIdentity, ErrTPM, fmt.Sprintf("failed to retrieve id: %v", err))
	}

	return strings.Trim(string(rawid), "\x00"), nil
}

func (m *Measurements) addEvent(event *Event, buf io.Writer) error {
	if err := binary.Write(buf, binary.LittleEndian, event.Index); err != nil {
		return err
	}

	if err := binary.Write(buf, binary.LittleEndian, event.Type); err != nil {
		return err
	}

	if err := binary.Write(buf, binary.LittleEndian, uint32(1)); err != nil {
		return err
	}

	if err := binary.Write(buf, binary.LittleEndian, tpm2.AlgSHA256); err != nil {
		return err
	}

	if _, err := buf.Write(event.Sha256); err != nil {
		return err
	}

	if err := binary.Write(buf, binary.LittleEndian, uint32(len(event.Data))); err != nil {
		return err
	}

	if _, err := buf.Write(event.Data); err != nil {
		return err
	}

	return nil
}

func (m *Measurements) Add(index uint32, typ EventType, sha256 [32]byte, data []byte) error {
	if m.tpm == nil {
		return sterror.E(ErrScope, ErrOpMeasureTPM, ErrNoInit)
	}

	if err := m.tpm.Measure(sha256[:], index); err != nil {
		return sterror.E(ErrScope, ErrOpMeasureTPM, ErrTPM, fmt.Sprintf("failed to measure: %v", err))
	}

	m.log = append(m.log, Event{
		Index:  index,
		Type:   typ,
		Data:   data,
		Sha256: sha256[:],
	})

	return nil
}

func specIDEvent(out io.Writer) error {
	if _, err := out.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00}); err != nil {
		return err
	}

	if _, err := out.Write(make([]byte, sha1HashSize)); err != nil {
		return err
	}

	if _, err := out.Write([]byte{0x25, 0x00, 0x00, 0x00}); err != nil {
		return err
	}

	if _, err := out.Write([]byte("Spec ID Event03\000")); err != nil {
		return err
	}

	tail := []byte{
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
	}
	if _, err := out.Write(tail); err != nil {
		return err
	}

	return nil
}
