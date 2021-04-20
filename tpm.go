package main

import (
	"encoding/json"
	"fmt"

	"github.com/u-root/u-root/pkg/tss"
)

const bootConfigPCR uint32 = 8

func measureTPM(data ...[]byte) error {
	tpm, err := tss.NewTPM()
	if err != nil {
		return fmt.Errorf("cannot open TPM: %v", err)
	}
	if *doDebug {
		i, _ := tpm.Info()
		str, _ := json.MarshalIndent(i, "", "  ")
		info("TPM info: %s", str)
	}
	for n, d := range data {
		if err := tpm.Measure(d, bootConfigPCR); err != nil {
			return fmt.Errorf("measuring element %d failed: %v", n+1, err)
		}
	}
	return tpm.Close()
}
