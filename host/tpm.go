// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package host

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/u-root/u-root/pkg/tss"
	"system-transparency.org/stboot/sterror"
	"system-transparency.org/stboot/stlog"
)

// Scope and operations used for raising Errors of this package.
const (
	ErrScope        sterror.Scope = "Host"
	ErrOpMeasureTPM sterror.Op    = "MeasureTPM"
)

// Errors which may be raised and wrapped in this package.
var (
	ErrTPM = errors.New("failed to measure TPM")
)

const bootConfigPCR uint32 = 8

func MeasureTPM(data ...[]byte) error {
	tpm, err := tss.NewTPM()
	if err != nil {
		return sterror.E(ErrScope, ErrOpMeasureTPM, ErrTPM, err.Error())
	}

	i, _ := tpm.Info()

	str, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		stlog.Debug("invalid TPM info: %w", err)
	} else {
		stlog.Debug("TPM info: %s", str)
	}

	for n, d := range data {
		if err := tpm.Measure(d, bootConfigPCR); err != nil {
			return sterror.E(ErrScope, ErrOpMeasureTPM, ErrTPM, fmt.Sprintf("failed to measure element %d: %v", n+1, err))
		}
	}

	if err = tpm.Close(); err != nil {
		return sterror.E(ErrScope, ErrOpMeasureTPM, ErrTPM, err.Error())
	}

	return nil
}
