package stboot

import (
	"net"
	"net/url"
	"strings"

	"github.com/vishvananda/netlink"
)

var (
	ErrMissingIPAddrMode = InvalidOptsError("IP address mode must be set")
	ErrUnknownIPAddrMode = InvalidOptsError("unknown IP address mode")
	ErrMissingProvURLs   = InvalidOptsError("provisioning server URL list must not be empty")
	ErrInvalidProvURLs   = InvalidOptsError("missing or unsupported scheme in provisioning URLs")
	ErrMissingIPAddr     = InvalidOptsError("IP address must not be empty when static IP mode is set")
	ErrMissingGateway    = InvalidOptsError("default gateway must not be empty when static IP mode is set")
	ErrMissingID         = InvalidOptsError("ID must not be empty when a URL contains '$ID'")
	ErrInvalidID         = InvalidOptsError("invalid ID string, max 64 characters [a-z,A-Z,0-9,-,_]")
	ErrMissingAuth       = InvalidOptsError("Auth must not be empty when a URL contains '$AUTH'")
	ErrInvalidAuth       = InvalidOptsError("invalid auth string, max 64 characters [a-z,A-Z,0-9,-,_]")

	ErrMissingBootMode = InvalidOptsError("boot mode must be set")
	ErrUnknownBootMode = InvalidOptsError("unknown boot mode")
)

// BootMode controlls where to load the OS from
type BootMode int

const (
	BootModeUnset BootMode = iota
	LocalBoot
	NetworkBoot
)

// String implements fmt.Stringer
func (b BootMode) String() string {
	switch b {
	case BootModeUnset:
		return "unset"
	case LocalBoot:
		return "local"
	case NetworkBoot:
		return "network"
	default:
		return "unknown"
	}
}

// IPAddrMode sets the method for network setup
type IPAddrMode int

const (
	IPUnset IPAddrMode = iota
	IPStatic
	IPDynamic
)

// String implements fmt.Stringer
func (n IPAddrMode) String() string {
	switch n {
	case IPUnset:
		return "unset"
	case IPStatic:
		return "static"
	case IPDynamic:
		return "DHCP"
	default:
		return "unknown"
	}
}

// securityCfg contains security critical configurations.
type securityCfg struct {
	ValidSignatureThreshold uint
	BootMode
	UsePkgCache bool
}

// hostCfg groups host specific configurations.
type hostCfg struct {
	IPAddrMode
	HostIP           *netlink.Addr
	DefaultGateway   *net.IP
	DNSServer        *net.IP
	NetworkInterface *net.HardwareAddr
	ProvisioningURLs []*url.URL
	ID               string
	Auth             string
}

// scValidators is a set of functions to validate securityCfg
var scValidators = []validator{
	checkBootMode,
}

// hcValidators is a set of functions to validate hostCfg
var hcValidators = []validator{
	checkNetworkMode,
	checkHostIP,
	checkGateway,
	checkProvisioningURLs,
	checkID,
	checkAuth,
}

func checkNetworkMode(o *Opts) error {
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

func checkBootMode(o *Opts) error {
	if o.BootMode == BootModeUnset {
		return ErrMissingBootMode
	}
	if o.BootMode > NetworkBoot {
		return ErrUnknownBootMode
	}
	return nil
}
