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
// Validate takes Opts and performs validation on it. In terms Opts is not
// valid and InvalidError is returned.
type Validater interface {
	Validate(Opts) error
}

type validFunc func(*Opts) error

type validationSet []validFunc

// Validate implements Validater.
func (v *validationSet) Validate(o *Opts) error {
	for _, f := range *v {
		if err := f(o); err != nil {
			return err
		}
	}
	return nil
}

// SecurityValidation is a validation set for host related fields of Opts.
var SecurityValidation = validationSet{
	checkValidSignatureThreshold,
	checkBootMode,
}

// HostCfgValidation is a validation set for security related fields of Opts.
var HostCfgValidation = validationSet{
	checkIPAddrMode,
	checkHostIP,
	checkGateway,
	checkProvisioningURLs,
	checkID,
	checkAuth,
}

func checkValidSignatureThreshold(o *Opts) error {
	if o.ValidSignatureThreshold < 1 {
		return ErrInvalidThreshold
	}
	return nil
}

func checkBootMode(o *Opts) error {
	if o.BootMode == BootModeUnset {
		return ErrMissingBootMode
	}
	return nil
}

func checkIPAddrMode(o *Opts) error {
	if o.IPAddrMode == IPUnset {
		return ErrMissingIPAddrMode
	}
	return nil
}

func checkHostIP(o *Opts) error {
	if o.IPAddrMode == IPStatic && o.HostIP == nil {
		return ErrMissingIPAddr
	}
	return nil
}

func checkGateway(o *Opts) error {
	if o.IPAddrMode == IPStatic && o.DefaultGateway == nil {
		return ErrMissingGateway
	}
	return nil
}

func checkProvisioningURLs(o *Opts) error {
	if o.ProvisioningURLs != nil {
		if len(*o.ProvisioningURLs) == 0 {
			return ErrMissingProvURLs
		}

		for _, u := range *o.ProvisioningURLs {
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

func checkID(o *Opts) error {
	var used bool
	if o.ProvisioningURLs != nil {
		for _, u := range *o.ProvisioningURLs {
			if used = strings.Contains(u.String(), "$ID"); used {
				break
			}
		}
	}
	if used {
		if o.ID == nil {
			return ErrMissingID
		} else if !hasAllowedChars(*o.ID) {
			return ErrInvalidID
		}
	}
	return nil
}

func checkAuth(o *Opts) error {
	var used bool
	if o.ProvisioningURLs != nil {
		for _, u := range *o.ProvisioningURLs {
			if used = strings.Contains(u.String(), "$AUTH"); used {
				break
			}
		}
	}
	if used {
		if o.Auth == nil {
			return ErrMissingAuth
		} else if !hasAllowedChars(*o.Auth) {
			return ErrInvalidAuth
		}
	}
	return nil
}

func hasAllowedChars(s string) bool {
	if len(s) > 64 {
		return false
	}
	return regexp.MustCompile(`^[A-Za-z-_]+$`).MatchString(s)
}
