package opts

import "strings"

var (
	ErrMissingBootMode   = InvalidError("boot mode must be set")
	ErrUnknownBootMode   = InvalidError("unknown boot mode")
	ErrMissingIPAddrMode = InvalidError("IP address mode must be set")
	ErrUnknownIPAddrMode = InvalidError("unknown IP address mode")
	ErrMissingProvURLs   = InvalidError("provisioning server URL list must not be empty")
	ErrInvalidProvURLs   = InvalidError("missing or unsupported scheme in provisioning URLs")
	ErrMissingIPAddr     = InvalidError("IP address must not be empty when static IP mode is set")
	ErrMissingGateway    = InvalidError("default gateway must not be empty when static IP mode is set")
	ErrMissingID         = InvalidError("ID must not be empty when a URL contains '$ID'")
	ErrInvalidID         = InvalidError("invalid ID string, max 64 characters [a-z,A-Z,0-9,-,_]")
	ErrMissingAuth       = InvalidError("Auth must not be empty when a URL contains '$AUTH'")
	ErrInvalidAuth       = InvalidError("invalid auth string, max 64 characters [a-z,A-Z,0-9,-,_]")
)

// sValids is a validator set for host related fields of Opts.
var sValids = []validator{
	checkBootMode,
}

// hValids is a validator set for security related fields of Opts.
var hValids = []validator{
	checkIPAddrMode,
	checkHostIP,
	checkGateway,
	checkProvisioningURLs,
	checkID,
	checkAuth,
}

func checkBootMode(o *Opts) error {
	if o.BootMode == BootModeUnset {
		return ErrMissingBootMode
	}
	if o.BootMode > NetworkBoot {
		return ErrUnknownBootMode
	}
	return nil
}

func checkIPAddrMode(o *Opts) error {
	if o.IPAddrMode == IPUnset {
		return ErrMissingIPAddrMode
	}
	if o.IPAddrMode > IPDynamic {
		return ErrUnknownIPAddrMode
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
	if len(o.ProvisioningURLs) == 0 {
		return ErrMissingProvURLs
	}
	for _, u := range o.ProvisioningURLs {
		s := u.Scheme
		if s == "" || s != "http" && s != "https" {
			return ErrInvalidProvURLs
		}
	}
	return nil
}

func checkID(o *Opts) error {
	var used bool
	for _, u := range o.ProvisioningURLs {
		if used = strings.Contains(u.String(), "$ID"); used {
			break
		}
	}
	if used {
		if o.ID == "" {
			return ErrMissingID
		} else if !hasAllowdChars(o.ID) {
			return ErrInvalidID
		}
	}
	return nil
}

func checkAuth(o *Opts) error {
	var used bool
	for _, u := range o.ProvisioningURLs {
		if used = strings.Contains(u.String(), "$AUTH"); used {
			break
		}
	}
	if used {
		if o.Auth == "" {
			return ErrMissingAuth
		} else if !hasAllowdChars(o.Auth) {
			return ErrInvalidAuth
		}
	}
	return nil
}

func hasAllowdChars(s string) bool {
	if len(s) > 64 {
		return false
	}
	for _, c := range s {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}
