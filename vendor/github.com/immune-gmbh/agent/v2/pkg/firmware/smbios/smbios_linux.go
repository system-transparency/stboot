package smbios

import (
	"bytes"
	"io"

	"github.com/digitalocean/go-smbios/smbios"
)

func readSMBIOS() ([]byte, error) {
	// find SMBIOS data in operating system-specific location.
	rc, _, err := smbios.Stream()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	// unwrap the rc-wrapped byte array again
	var buf bytes.Buffer
	io.Copy(&buf, rc)
	return buf.Bytes(), err
}
