// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package host

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/system-transparency/stboot/stlog"
	"github.com/u-root/u-root/pkg/tss"
)

var (
	ErrTPM                 = errors.New("failed to measure TPM")
)

const bootConfigPCR uint32 = 8

func MeasureTPM(data ...[]byte) error {
	tpm, err := tss.NewTPM()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTPM, err)
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
			return fmt.Errorf("%w: %v", ErrTPM, err)
		}
	}

	if err = tpm.Close(); err != nil {
		return fmt.Errorf("%w: %v", ErrTPM, err)
	}

	return nil
}
