package main

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/vishvananda/netlink"
)

const HostConfigVersion int = 1

//go:generate jsonenums -type=networkmode
type networkmode int

// networkmode values defines where to load a OS package from.
const (
	Static networkmode = iota
	DHCP
)

func (n networkmode) String() string {
	return []string{"static", "dhcp"}[n]
}

// HostConfig contains configuration data for a System Transparency host.
type HostConfig struct {
	Version          int         `json:"version"`
	NetworkMode      networkmode `json:"network_mode"`
	HostIP           string      `json:"host_ip"`
	DefaultGateway   string      `json:"gateway"`
	DNSServer        net.IP      `json:"dns"`
	ProvisioningURLs []string    `json:"provisioning_urls"`
	ID               string      `json:"identity"`
	Auth             string      `json:"authentication"`

	isValidBasic   bool
	isValidNetwork bool

	hostIP           *netlink.Addr
	defaultGateway   *net.IP
	provisioningURLs []*url.URL
}

// Validate checks the integrety of hc. network controlls, if the
// network related settings are checked.
func (hc *HostConfig) Validate(network bool) error {
	if !hc.isValidBasic {
		// version
		if hc.Version != HostConfigVersion {
			return fmt.Errorf("version missmatch, want %d, got %d", HostConfigVersion, hc.Version)
		}
		hc.isValidBasic = true
	}
	if network && !hc.isValidNetwork {
		// identity is optional
		if hc.ID != "" {
			if len(hc.ID) > 64 {
				return fmt.Errorf("identity: too long, max. 64 characters!")
			}
			for _, c := range hc.ID {
				if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
					return fmt.Errorf("identity: invalid char %c ", c)
				}
			}
		}
		// authentication is optional
		if hc.Auth != "" {
			if len(hc.Auth) > 64 {
				return fmt.Errorf("authentication: too long, max. 64 characters!")
			}
			for _, c := range hc.Auth {
				if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
					return fmt.Errorf("authentication: invalid char %c ", c)
				}
			}
		}
		// absolute provisioning URLs
		if len(hc.ProvisioningURLs) == 0 {
			return fmt.Errorf("missing provisioning URLs")
		}
		for _, u := range hc.ProvisioningURLs {
			if strings.Contains(u, "$ID") && hc.ID == "" {
				return fmt.Errorf("provisioning URLs: identity not provided in host config for replacing $ID in %s", u)
			}
			if strings.Contains(u, "$AUTH") && hc.Auth == "" {
				return fmt.Errorf("provisioning URLs: authentication not provided in host config for replacing $AUTH in %s", u)
			}
			u = strings.ReplaceAll(u, "$ID", hc.ID)
			u = strings.ReplaceAll(u, "$AUTH", hc.Auth)
			url, err := url.Parse(u)
			if err != nil {
				return fmt.Errorf("provisioning URLs: %v", err)
			}
			s := url.Scheme
			if s == "" || s != "http" && s != "https" {
				return fmt.Errorf("provisioning URL: missing or unsupported scheme in %s", url.String())
			}
			hc.provisioningURLs = append(hc.provisioningURLs, url)
		}
		// host ip and default gateway are required in case of static network mode
		if hc.NetworkMode == Static {
			a, err := netlink.ParseAddr(hc.HostIP)
			if err != nil {
				return fmt.Errorf("host ip: %v", err)
			}
			hc.hostIP = a
			g := net.ParseIP(hc.DefaultGateway)
			if g == nil {
				return fmt.Errorf("default gateway: valid textual representation: got %s want e.g. 192.0.2.1, 2001:db8::68, or ::ffff:192.0.2.1", hc.defaultGateway)
			}
			hc.defaultGateway = &g
		}
		hc.isValidNetwork = true
	}
	return nil
}

func (hc *HostConfig) ParseHostIP() (*netlink.Addr, error) {
	if err := hc.Validate(true); err != nil {
		return nil, fmt.Errorf("invalid config: %v", err)
	}
	return hc.hostIP, nil
}

func (hc *HostConfig) ParseDefaultGateway() (*net.IP, error) {
	if err := hc.Validate(true); err != nil {
		return nil, fmt.Errorf("invalid config: %v", err)
	}
	return hc.defaultGateway, nil
}

func (hc *HostConfig) ParseProvisioningURLs() ([]*url.URL, error) {
	if err := hc.Validate(true); err != nil {
		return nil, fmt.Errorf("invalid config: %v", err)
	}
	return hc.provisioningURLs, nil
}
