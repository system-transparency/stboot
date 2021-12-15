package opts

import (
	"fmt"
	"net"
	"net/url"

	"github.com/vishvananda/netlink"
)

const OptsVersion int = 0

type InvalidError string

func (e InvalidError) Error() string {
	return string(e)
}

type ParseError struct {
	wrongType interface{}
	key       string
	err       error
}

func (p *ParseError) Error() string {
	if p.wrongType != nil {
		return fmt.Sprintf("value of JSON key %q has wrong type %T", p.key, p.wrongType)
	}
	return fmt.Sprintf("parsing value of JSON key %q failed: %v", p.key, p.err)
}

type validator func(*Opts) error

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
		return "dhcp"
	default:
		return "unknown"
	}
}

type Opts struct {
	Version int

	// Security critical configuration
	ValidSignatureThreshold uint
	BootMode
	UsePkgCache bool

	// Host specific configuration
	IPAddrMode
	HostIP           *netlink.Addr
	DefaultGateway   *net.IP
	DNSServer        *net.IP
	NetworkInterface *net.HardwareAddr
	ProvisioningURLs []*url.URL
	ID               string
	Auth             string
}
