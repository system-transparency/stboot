package host

import (
	"bytes"

	"git.glasklar.is/system-transparency/core/stboot/sterror"
	"github.com/u-root/u-root/pkg/efivarfs"
)

func readEFIVar(name string) (*bytes.Reader, error) {
	const operation = sterror.Op("read EFI var")

	e, err := efivarfs.New()
	if err != nil {
		return nil, sterror.E(ErrScope, operation, err.Error())
	}

	_, r, err := efivarfs.SimpleReadVariable(e, name)
	if err != nil {
		return nil, sterror.E(ErrScope, operation, err.Error())
	}

	return r, nil
}
