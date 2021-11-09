// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/vishvananda/netlink"
)

const HostCfgVersion int = 1

var (
	ErrHostCfgVersionMissmatch = InvalidError("version missmatch, want version " + fmt.Sprint(HostCfgVersion))
	ErrMissingIPAddrMode       = InvalidError("IP address mode must be set")
	ErrUnknownIPAddrMode       = InvalidError("unknown IP address mode")
	ErrMissingProvURLs         = InvalidError("provisioning server URL list must not be empty")
	ErrInvalidProvURLs         = InvalidError("missing or unsupported scheme in provisioning URLs")
	ErrMissingIPAddr           = InvalidError("IP address must not be empty when static IP mode is set")
	ErrMissingGateway          = InvalidError("default gateway must not be empty when static IP mode is set")
	ErrMissingID               = InvalidError("ID must not be empty when a URL contains '$ID'")
	ErrInvalidID               = InvalidError("invalid ID string, max 64 characters [a-z,A-Z,0-9,-,_]")
	ErrMissingAuth             = InvalidError("Auth must not be empty when a URL contains '$AUTH'")
	ErrInvalidAuth             = InvalidError("invalid auth string, max 64 characters [a-z,A-Z,0-9,-,_]")
)

type IPAddrMode int

const (
	UnsetIPAddrMode IPAddrMode = iota
	StaticIP
	DynamicIP
)

func (n IPAddrMode) String() string {
	switch n {
	case UnsetIPAddrMode:
		return "unset"
	case StaticIP:
		return "static"
	case DynamicIP:
		return "dhcp"
	default:
		return "unknown"
	}
}

// HostCfg contains configuration data for a System Transparency host.
type HostCfg struct {
	Version int
	IPAddrMode
	HostIP           *netlink.Addr
	DefaultGateway   *net.IP
	DNSServer        *net.IP
	NetworkInterface *net.HardwareAddr
	ProvisioningURLs []*url.URL
	ID               string
	Auth             string
}

var hcValidators = []hcValidator{
	checkHostCfgVersion,
	checkNetworkMode,
	checkHostIP,
	checkGateway,
	checkProvisioningURLs,
	checkID,
	checkAuth,
}

func checkHostCfgVersion(c *HostCfg) error {
	if c.Version != HostCfgVersion {
		return ErrHostCfgVersionMissmatch
	}
	return nil
}

func checkNetworkMode(c *HostCfg) error {
	if c.IPAddrMode == UnsetIPAddrMode {
		return ErrMissingIPAddrMode
	}
	if c.IPAddrMode > DynamicIP {
		return ErrUnknownIPAddrMode
	}
	return nil
}

func checkHostIP(c *HostCfg) error {
	if c.IPAddrMode == StaticIP && c.HostIP == nil {
		return ErrMissingIPAddr
	}
	return nil
}

func checkGateway(c *HostCfg) error {
	if c.IPAddrMode == StaticIP && c.DefaultGateway == nil {
		return ErrMissingGateway
	}
	return nil
}

func checkProvisioningURLs(c *HostCfg) error {
	if len(c.ProvisioningURLs) == 0 {
		return ErrMissingProvURLs
	}
	for _, u := range c.ProvisioningURLs {
		s := u.Scheme
		if s == "" || s != "http" && s != "https" {
			return ErrInvalidProvURLs
		}
	}
	return nil
}

func checkID(c *HostCfg) error {
	var isUsed bool
	for _, u := range c.ProvisioningURLs {
		if isUsed = strings.Contains(u.String(), "$ID"); isUsed {
			break
		}
	}
	if isUsed {
		if c.ID == "" {
			return ErrMissingID
		} else if !hasAllowdChars(c.ID) {
			return ErrInvalidID
		}
	}
	return nil
}

func checkAuth(c *HostCfg) error {
	var isUsed bool
	for _, u := range c.ProvisioningURLs {
		if isUsed = strings.Contains(u.String(), "$AUTH"); isUsed {
			break
		}
	}
	if isUsed {
		if c.Auth == "" {
			return ErrMissingAuth
		} else if !hasAllowdChars(c.Auth) {
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
