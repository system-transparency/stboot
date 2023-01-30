package host

import (
	"errors"
	"fmt"
	"io"
	"os"

	"system-transparency.org/stboot/sterror"
	"system-transparency.org/stboot/stlog"
)

// Operations used for raising Errors of this package.
const (
	ErrOpAutodetect sterror.Op = "config autodetect"
)

// Errors which may be raised and wrapped in this package.
var (
	ErrConfigNotFound = errors.New("no host configuration found")
)

// Sources used by ConfigAutodetect.
const (
	HostConfigInitrdPath = "/etc/host_configuration.json"
	HostConfigEFIVarName = "STHostConfig-f401f2c1-b005-4be0-8cee-f2e5945bcbe7"
)

type configLoader interface {
	probe() (io.Reader, error)
	info() string
}

// ConfigAutodetect looks for a known host configuration name in following order:
// - inside the initramfs at HostConfigInitrdPath
// - at the efivar filesystem for HostConfigEFIVarName
//
// It returns with a non-nil io.Reader, if an item exists with the defined name
// at a probed location. In case there is no match an ErrConfigNotFound is returned.
// Note: No validation is made on found configuration.
func ConfigAutodetect() (io.Reader, error) {
	var loadingOrder = []configLoader{
		&efivar{},
		&initramfs{},
	}

	stlog.Debug("Host configuration autodetect")

	for _, loader := range loadingOrder {
		stlog.Debug(loader.info())

		ret, err := loader.probe()
		if err != nil {
			stlog.Debug(err.Error())

			continue
		}

		if ret == nil {
			stlog.Debug("invalid source: nil reader")

			continue
		}

		return ret, nil
	}

	return nil, sterror.E(ErrScope, ErrOpAutodetect, ErrConfigNotFound)
}

type initramfs struct{}

var _ configLoader = &initramfs{}

func (i *initramfs) probe() (io.Reader, error) {
	ret, err := os.Open(HostConfigInitrdPath)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (i *initramfs) info() string {
	return fmt.Sprintf("Probing initramfs at %s", HostConfigInitrdPath)
}

type efivar struct{}

var _ configLoader = &efivar{}

func (e *efivar) probe() (io.Reader, error) {
	ret, err := readEFIVar(HostConfigEFIVarName)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (e *efivar) info() string {
	return fmt.Sprintf("Probing EFI variable %s", HostConfigEFIVarName)
}
