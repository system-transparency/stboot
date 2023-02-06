// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package host exposes functionality to interact with the host mashine.
package host

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"regexp"
	"strings"

	"github.com/vishvananda/netlink"
	"system-transparency.org/stboot/internal/jsonutil"
	"system-transparency.org/stboot/stlog"
)

var (
	ErrMissingJSONKey           = errors.New("missing JSON key")
	ErrMissingIPAddrMode        = errors.New("field IP address mode must be set")
	ErrUnknownIPAddrMode        = errors.New("unknown IP address mode")
	ErrUnknownBondingMode       = errors.New("unknown bonding mode")
	ErrMissingBondName          = errors.New("bond name must be set")
	ErrInvalidBondMode          = errors.New("bond mode is unknown")
	ErrMissingNetworkInterfaces = errors.New("one or more network interfaces must be set")
	ErrMissingProvURLs          = errors.New("provisioning server URL list must not be empty")
	ErrInvalidProvURLs          = errors.New("missing or unsupported scheme in provisioning URLs")
	ErrMissingIPAddr            = errors.New("field IP address must not be empty when static IP mode is set")
	ErrMissingGateway           = errors.New("default gateway must not be empty when static IP mode is set")
	ErrMissingID                = errors.New("field ID must not be empty when a URL contains '$ID'")
	ErrInvalidID                = errors.New("invalid ID string, min 1 char, allowed chars are [a-z,A-Z,0-9,-,_]")
	ErrMissingAuth              = errors.New("field Auth must be set when a URL contains '$AUTH'")
	ErrInvalidAuth              = errors.New("invalid auth string, min 1 char, allowed chars are [a-z,A-Z,0-9,-,_]")
)

// IPAddrMode sets the method for network setup.
type IPAddrMode int

const (
	IPUnset IPAddrMode = iota
	IPStatic
	IPDynamic
)

// String implements fmt.Stringer.
func (i IPAddrMode) String() string {
	return [...]string{"unset", "static", "dhcp"}[i]
}

// MarshalJSON implements json.Marshaler.
func (i IPAddrMode) MarshalJSON() ([]byte, error) {
	if i != IPUnset {
		return json.Marshal(i.String())
	}

	return []byte(jsonutil.Null), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (i *IPAddrMode) UnmarshalJSON(data []byte) error {
	if string(data) == jsonutil.Null {
		*i = IPUnset
	} else {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}

		toID := map[string]IPAddrMode{
			"static": IPStatic,
			"dhcp":   IPDynamic,
		}
		mode, ok := toID[str]
		if !ok {
			return &json.UnmarshalTypeError{
				Value: fmt.Sprintf("string %q", str),
				Type:  reflect.TypeOf(i),
			}
		}
		*i = mode
	}

	return nil
}

// BondingMode sets the mode for bonding.
type BondingMode int

const (
	BondingUnset BondingMode = iota
	BondingBalanceRR
	BondingActiveBackup
	BondingBalanceXOR
	BondingBroadcast
	Bonding8023AD
	BondingBalanceTLB
	BondingBalanceALB
	BondingUnknown
)

func StringToBondingMode(str string) BondingMode {
	bondString := map[string]BondingMode{
		"":              BondingUnset,
		"balance-rr":    BondingBalanceRR,
		"active-backup": BondingActiveBackup,
		"balance-xor":   BondingBalanceXOR,
		"broadcast":     BondingBroadcast,
		"802.3ad":       Bonding8023AD,
		"balance-tlb":   BondingBalanceTLB,
		"balance-alb":   BondingBalanceALB,
	}

	if mode, ok := bondString[str]; ok {
		return mode
	}

	return BondingUnknown
}

// String implements fmt.Stringer.
func (b BondingMode) String() string {
	return [...]string{"",
		"balance-rr",
		"active-backup",
		"balance-xor",
		"broadcast",
		"802.3ad",
		"balance-tlb",
		"balance-alb"}[b]
}

// MarshalJSON implements json.Marshaler.
func (b BondingMode) MarshalJSON() ([]byte, error) {
	if b != BondingUnset {
		return json.Marshal(b.String())
	}

	return []byte(jsonutil.Null), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *BondingMode) UnmarshalJSON(data []byte) error {
	if string(data) == jsonutil.Null {
		*b = BondingUnset
	} else {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}

		mode := StringToBondingMode(str)
		if mode == BondingUnknown {
			return &json.UnmarshalTypeError{
				Value: fmt.Sprintf("string %q", str),
				Type:  reflect.TypeOf(b),
			}
		}
		*b = mode
	}

	return nil
}

// Config stores host specific configuration.
type Config struct {
	IPAddrMode        *IPAddrMode       `json:"network_mode"`
	HostIP            *netlink.Addr     `json:"host_ip"`
	DefaultGateway    *net.IP           `json:"gateway"`
	DNSServer         *net.IP           `json:"dns"`
	NetworkInterface  *net.HardwareAddr `json:"network_interface"`
	ProvisioningURLs  *[]*url.URL       `json:"provisioning_urls"`
	ID                *string           `json:"identity"`
	Auth              *string           `json:"authentication"`
	NetworkInterfaces *[]*string        `json:"network_interfaces"`
	BondingMode       BondingMode       `json:"bonding_mode"`
	BondName          *string           `json:"bond_name"`
}

type config struct {
	IPAddrMode        *IPAddrMode      `json:"network_mode"`
	HostIP            *netlinkAddr     `json:"host_ip"`
	DefaultGateway    *netIP           `json:"gateway"`
	DNSServer         *netIP           `json:"dns"`
	NetworkInterface  *netHardwareAddr `json:"network_interface"`
	ProvisioningURLs  *[]*urlURL       `json:"provisioning_urls"`
	ID                *string          `json:"identity"`
	Auth              *string          `json:"authentication"`
	NetworkInterfaces *[]*string       `json:"network_interfaces"`
	BondingMode       BondingMode      `json:"bonding_mode"`
	BondName          *string          `json:"bond_name"`
}

// MarshalJSON implements json.Marshaler.
func (c Config) MarshalJSON() ([]byte, error) {
	alias := config{
		IPAddrMode:        c.IPAddrMode,
		HostIP:            (*netlinkAddr)(c.HostIP),
		DefaultGateway:    (*netIP)(c.DefaultGateway),
		DNSServer:         (*netIP)(c.DNSServer),
		NetworkInterface:  (*netHardwareAddr)(c.NetworkInterface),
		ProvisioningURLs:  urls2alias(c.ProvisioningURLs),
		ID:                c.ID,
		Auth:              c.Auth,
		NetworkInterfaces: c.NetworkInterfaces,
		BondingMode:       c.BondingMode,
		BondName:          c.BondName,
	}

	return json.Marshal(alias)
}

// UnmarshalJSON implements json.Unmarshaler.
//
// All fields of Config need to be present in JSON.
func (c *Config) UnmarshalJSON(data []byte) error {
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(data, &jsonMap); err != nil {
		return err
	}

	tags := jsonutil.Tags(c)
	for _, tag := range tags {
		if _, ok := jsonMap[tag]; !ok {
			stlog.Debug("All fields of host config are expected to be set or unset. Missing json key %q", tag)

			return ErrMissingJSONKey
		}
	}

	alias := config{}
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}

	c.IPAddrMode = alias.IPAddrMode
	c.HostIP = (*netlink.Addr)(alias.HostIP)
	c.DefaultGateway = (*net.IP)(alias.DefaultGateway)
	c.DNSServer = (*net.IP)(alias.DNSServer)
	c.NetworkInterface = (*net.HardwareAddr)(alias.NetworkInterface)
	c.ProvisioningURLs = alias2urls(alias.ProvisioningURLs)
	c.ID = alias.ID
	c.Auth = alias.Auth
	c.NetworkInterfaces = alias.NetworkInterfaces
	c.BondingMode = alias.BondingMode
	c.BondName = alias.BondName

	if err := c.validate(); err != nil {
		*c = Config{}

		return fmt.Errorf("unmarshal host config: %w", err)
	}

	return nil
}

func (c *Config) validate() error {
	var validationSet = []func(*Config) error{
		checkIPAddrMode,
		checkHostIP,
		checkGateway,
		checkProvisioningURLs,
		checkID,
		checkAuth,
		checkBonding,
	}

	for _, f := range validationSet {
		if err := f(c); err != nil {
			return err
		}
	}

	return nil
}

func checkIPAddrMode(cfg *Config) error {
	if cfg.IPAddrMode == nil || *cfg.IPAddrMode == IPUnset {
		return ErrMissingIPAddrMode
	}

	return nil
}

func checkHostIP(cfg *Config) error {
	if *cfg.IPAddrMode == IPStatic && cfg.HostIP == nil {
		return ErrMissingIPAddr
	}

	return nil
}

func checkGateway(cfg *Config) error {
	if *cfg.IPAddrMode == IPStatic && cfg.DefaultGateway == nil {
		return ErrMissingGateway
	}

	return nil
}

func checkProvisioningURLs(cfg *Config) error {
	if cfg.ProvisioningURLs != nil {
		if len(*cfg.ProvisioningURLs) == 0 {
			return ErrMissingProvURLs
		}

		for _, u := range *cfg.ProvisioningURLs {
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

func checkID(cfg *Config) error {
	var used bool

	if cfg.ProvisioningURLs != nil {
		for _, u := range *cfg.ProvisioningURLs {
			if used = strings.Contains(u.String(), "$ID"); used {
				break
			}
		}
	}

	if used {
		if cfg.ID == nil {
			return ErrMissingID
		} else if !hasAllowedChars(*cfg.ID) {
			return ErrInvalidID
		}
	}

	return nil
}

func checkAuth(cfg *Config) error {
	var used bool

	if cfg.ProvisioningURLs != nil {
		for _, u := range *cfg.ProvisioningURLs {
			if used = strings.Contains(u.String(), "$AUTH"); used {
				break
			}
		}
	}

	if used {
		if cfg.Auth == nil {
			return ErrMissingAuth
		} else if !hasAllowedChars(*cfg.Auth) {
			return ErrInvalidAuth
		}
	}

	return nil
}

func checkBonding(cfg *Config) error {
	if cfg.BondingMode == BondingUnset {
		return nil
	}

	if cfg.BondingMode == BondingUnknown {
		return ErrInvalidBondMode
	}

	if cfg.BondName == nil || *cfg.BondName == "" {
		return ErrMissingBondName
	}

	if cfg.NetworkInterfaces == nil || len(*cfg.NetworkInterfaces) == 0 {
		return ErrMissingNetworkInterfaces
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

func urls2alias(input *[]*url.URL) *[]*urlURL {
	if input == nil {
		return nil
	}

	ret := make([]*urlURL, len(*input))
	for i := range ret {
		if (*input)[i] != nil {
			u := *(*input)[i]
			cast := urlURL(u)
			ret[i] = &cast
		}
	}

	return &ret
}

func alias2urls(input *[]*urlURL) *[]*url.URL {
	if input == nil {
		return nil
	}

	ret := make([]*url.URL, len(*input))
	for i := range ret {
		if (*input)[i] != nil {
			u := *(*input)[i]
			cast := url.URL(u)
			ret[i] = &cast
		}
	}

	return &ret
}

type netlinkAddr netlink.Addr

func (n netlinkAddr) MarshalJSON() ([]byte, error) {
	return json.Marshal(netlink.Addr(n).String())
}

func (n *netlinkAddr) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	ipAddr, err := netlink.ParseAddr(str)
	if err != nil {
		return &json.UnmarshalTypeError{
			Value: fmt.Sprintf("string %q", str),
			Type:  reflect.TypeOf(ipAddr),
		}
	}

	*n = netlinkAddr(*ipAddr)

	return nil
}

type netIP net.IP

func (n netIP) MarshalJSON() ([]byte, error) {
	return json.Marshal(net.IP(n).String())
}

func (n *netIP) UnmarshalJSON(data []byte) error {
	if string(data) == jsonutil.Null {
		*n = nil
	} else {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		ipAddr := net.ParseIP(str)
		if ipAddr == nil {
			return &json.UnmarshalTypeError{
				Value: fmt.Sprintf("string %q", str),
				Type:  reflect.TypeOf(ipAddr),
			}
		}
		*n = netIP(ipAddr)
	}

	return nil
}

type netHardwareAddr net.HardwareAddr

func (n netHardwareAddr) MarshalJSON() ([]byte, error) {
	return json.Marshal(net.HardwareAddr(n).String())
}

func (n *netHardwareAddr) UnmarshalJSON(data []byte) error {
	if string(data) == jsonutil.Null {
		*n = nil
	} else {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		hwa, err := net.ParseMAC(str)
		if err != nil {
			return &json.UnmarshalTypeError{
				Value: fmt.Sprintf("string %q", str),
				Type:  reflect.TypeOf(hwa),
			}
		}
		*n = netHardwareAddr(hwa)
	}

	return nil
}

type urlURL url.URL

func (u urlURL) MarshalJSON() ([]byte, error) {
	return json.Marshal((*url.URL)(&u).String())
}

func (u *urlURL) UnmarshalJSON(data []byte) error {
	if string(data) == jsonutil.Null {
		*u = urlURL{}
	} else {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		uri, err := url.ParseRequestURI(str)
		if err != nil {
			return &json.UnmarshalTypeError{
				Value: fmt.Sprintf("string %q", str),
				Type:  reflect.TypeOf(uri),
			}
		}
		*u = urlURL(*uri)
	}

	return nil
}
