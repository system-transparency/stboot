// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package host

import (
	"encoding/json"
	"fmt"

	"github.com/system-transparency/stboot/stlog"
	"github.com/u-root/u-root/pkg/tss"
)

const bootConfigPCR uint32 = 8

func MeasureTPM(data ...[]byte) error {
	tpm, err := tss.NewTPM()
	if err != nil {
		return fmt.Errorf("cannot open TPM: %w", err)
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
			return fmt.Errorf("measuring element %d failed: %w", n+1, err)
		}
	}

	if err = tpm.Close(); err != nil {
		return fmt.Errorf("closing tpm: %w", err)
	}

	return nil
}
