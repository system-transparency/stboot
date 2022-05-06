package opts

import (
	"regexp"
	"strings"
)

var (
	ErrMissingBootMode   = InvalidError("boot mode must be set")
	ErrUnknownBootMode   = InvalidError("unknown boot mode")
	ErrInvalidThreshold  = InvalidError("Treshold for valid signatures must be > 0")
	ErrMissingIPAddrMode = InvalidError("IP address mode must be set")
	ErrUnknownIPAddrMode = InvalidError("unknown IP address mode")
	ErrMissingProvURLs   = InvalidError("provisioning server URL list must not be empty")
	ErrInvalidProvURLs   = InvalidError("missing or unsupported scheme in provisioning URLs")
	ErrMissingIPAddr     = InvalidError("IP address must not be empty when static IP mode is set")
	ErrMissingGateway    = InvalidError("default gateway must not be empty when static IP mode is set")
	ErrMissingID         = InvalidError("ID must not be empty when a URL contains '$ID'")
	ErrInvalidID         = InvalidError("invalid ID string, min 1 char, allowed chars are [a-z,A-Z,0-9,-,_]")
	ErrMissingAuth       = InvalidError("Auth must be set when a URL contains '$AUTH'")
	ErrInvalidAuth       = InvalidError("invalid auth string, min 1 char, allowed chars are [a-z,A-Z,0-9,-,_]")
)

// Validater is the interface that wraps the Validate method.
//
// Validate takes Opts and performs validation on it. If Opts is not
// valid and InvalidError is returned.
type Validater interface {
	Validate(*Opts) error
}

type validFunc func(*Opts) error

// ValidationSet is a colection of validation functions.
type ValidationSet []validFunc

// Validate implements Validater.
func (v *ValidationSet) Validate(opts *Opts) error {
	for _, f := range *v {
		if err := f(opts); err != nil {
			return err
		}
	}

	return nil
}

// SecurityValidation is a Validater for host related fields of Opts.
func SecurityValidation() *ValidationSet {
	return &ValidationSet{
		checkValidSignatureThreshold,
		checkBootMode,
	}
}

// HostCfgValidation is a Validater for security related fields of Opts.
func HostCfgValidation() *ValidationSet {
	return &ValidationSet{
		checkIPAddrMode,
		checkHostIP,
		checkGateway,
		checkProvisioningURLs,
		checkID,
		checkAuth,
	}
}

func checkValidSignatureThreshold(opts *Opts) error {
	if opts.ValidSignatureThreshold < 1 {
		return ErrInvalidThreshold
	}

	return nil
}

func checkBootMode(opts *Opts) error {
	if opts.BootMode == BootModeUnset {
		return ErrMissingBootMode
	}

	return nil
}

func checkIPAddrMode(opts *Opts) error {
	if opts.IPAddrMode == IPUnset {
		return ErrMissingIPAddrMode
	}

	return nil
}

func checkHostIP(opts *Opts) error {
	if opts.IPAddrMode == IPStatic && opts.HostIP == nil {
		return ErrMissingIPAddr
	}

	return nil
}

func checkGateway(opts *Opts) error {
	if opts.IPAddrMode == IPStatic && opts.DefaultGateway == nil {
		return ErrMissingGateway
	}

	return nil
}

func checkProvisioningURLs(opts *Opts) error {
	if opts.ProvisioningURLs != nil {
		if len(*opts.ProvisioningURLs) == 0 {
			return ErrMissingProvURLs
		}

		for _, u := range *opts.ProvisioningURLs {
			s := u.Scheme
			if s == "" || s != "http" && s != "https" {
				return ErrInvalidProvURLs
			}
		}
	} else {
		return ErrMissingProvURLs
	}

	return nil
}

func checkID(opts *Opts) error {
	var used bool

	if opts.ProvisioningURLs != nil {
		for _, u := range *opts.ProvisioningURLs {
			if used = strings.Contains(u.String(), "$ID"); used {
				break
			}
		}
	}

	if used {
		if opts.ID == nil {
			return ErrMissingID
		} else if !hasAllowedChars(*opts.ID) {
			return ErrInvalidID
		}
	}

	return nil
}

func checkAuth(opts *Opts) error {
	var used bool

	if opts.ProvisioningURLs != nil {
		for _, u := range *opts.ProvisioningURLs {
			if used = strings.Contains(u.String(), "$AUTH"); used {
				break
			}
		}
	}

	if used {
		if opts.Auth == nil {
			return ErrMissingAuth
		} else if !hasAllowedChars(*opts.Auth) {
			return ErrInvalidAuth
		}
	}

	return nil
}

func hasAllowedChars(str string) bool {
	const maxLen = 64
	if len(str) > maxLen {
		return false
	}

	return regexp.MustCompile(`^[A-Za-z-_]+$`).MatchString(str)
}
