// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package host exposes functionality to interact with the host mashine.
package host

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"system-transparency.org/stboot/internal/jsonutil"
)

func TestIPAddrModeString(t *testing.T) {
	tests := []struct {
		name string
		mode IPAddrMode
		want string
	}{
		{
			name: "String for default value",
			mode: IPUnset,
			want: "unset",
		},
		{
			name: "String for 'IPStatic'",
			mode: IPStatic,
			want: "static",
		},
		{
			name: "String for 'IPDynamic'",
			mode: IPDynamic,
			want: "dhcp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.mode.String()
			assert(t, nil, nil, got, tt.want)
		})
	}
}

func TestIPAddrModeMarshal(t *testing.T) {
	tests := []struct {
		name string
		mode IPAddrMode
		want string
	}{
		{
			name: "IPUnset",
			mode: IPUnset,
			want: `null`,
		},
		{
			name: "IPStatic",
			mode: IPStatic,
			want: `"static"`,
		},
		{
			name: "IPDynamic",
			mode: IPDynamic,
			want: `"dhcp"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.mode.MarshalJSON()
			assert(t, err, nil, string(got), tt.want)
		})
	}
}

func TestIPAddrModeUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    IPAddrMode
		errType error
	}{
		{
			name:    jsonutil.Null,
			json:    `null`,
			want:    IPUnset,
			errType: nil,
		},
		{
			name:    "static",
			json:    `"static"`,
			want:    IPStatic,
			errType: nil,
		},
		{
			name:    "dhcp",
			json:    `"dhcp"`,
			want:    IPDynamic,
			errType: nil,
		},
		{
			name:    "wrong type",
			json:    `1`,
			want:    IPUnset,
			errType: &json.UnmarshalTypeError{},
		},
		{
			name:    "invalid string",
			json:    `"foo"`,
			want:    IPUnset,
			errType: &json.UnmarshalTypeError{},
		},
		{
			name:    "invalid empty string",
			json:    `""`,
			want:    IPUnset,
			errType: &json.UnmarshalTypeError{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got IPAddrMode
			err := got.UnmarshalJSON([]byte(tt.json))
			assert(t, err, tt.errType, got, tt.want)
		})
	}
}

func TestConfigMarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		c    Config
		want string
	}{
		{
			name: "Unset Config",
			c:    Config{},
			want: `{
				"network_mode":null,
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"network_interfaces":null,
				"provisioning_urls":null,
				"identity":null,
				"authentication":null,
				"bonding_mode":null,
				"bond_name":null
				}`,
		},
		{
			name: "All fields set",
			c: Config{
				IPAddrMode:        ipam2ipam(t, IPStatic),
				HostIP:            s2cidr(t, "127.0.0.1/24"),
				DefaultGateway:    s2ip(t, "127.0.0.1"),
				DNSServer:         s2ipArray(t, "127.0.0.1"),
				ProvisioningURLs:  s2urlArray(t, "http://foo.com/bar", "https://foo.com/bar"),
				ID:                s2s(t, "someID"),
				Auth:              s2s(t, "1234"),
				NetworkInterfaces: s2sNetworkInterfaces(t, [][2]string{{"eth0", "00:00:5e:00:53:01"}}),
				BondingMode:       BondingBalanceRR,
				BondName:          s2s(t, "bond0"),
			},
			want: `{
				"network_mode":"static",
				"host_ip":"127.0.0.1/24",
				"gateway":"127.0.0.1",
				"dns":["127.0.0.1"],
				"network_interfaces":[{"interface_name": "eth0", "mac_address": "00:00:5e:00:53:01" }],
				"provisioning_urls":["http://foo.com/bar", "https://foo.com/bar"],
				"identity":"someID",
				"authentication":"1234",
				"bonding_mode":"balance-rr",
				"bond_name":"bond0"
				}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.c.MarshalJSON()
			want := strings.Join(strings.Fields(tt.want), "")
			assert(t, err, nil, string(got), want)
		})
	}
}

func TestConfigUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    Config
		errType error
	}{
		{
			name: "Minimal for dhcp",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"provisioning_urls":["http://server.com"],
				"identity":null,
				"authentication":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want: Config{
				IPAddrMode:       ipam2ipam(t, IPDynamic),
				ProvisioningURLs: s2urlArray(t, "http://server.com"),
			},
			errType: nil,
		},
		{
			name: "Minimalh for static IP",
			json: `{
				"network_mode":"static",
				"host_ip":"127.0.0.1/24",
				"gateway":"127.0.0.1",
				"dns":null,
				"provisioning_urls":["http://server.com"],
				"identity":null,
				"authentication":null,
				"timestamp":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want: Config{
				IPAddrMode:       ipam2ipam(t, IPStatic),
				HostIP:           s2cidr(t, "127.0.0.1/24"),
				DefaultGateway:   s2ip(t, "127.0.0.1"),
				ProvisioningURLs: s2urlArray(t, "http://server.com"),
			},
			errType: nil,
		}, {
			name: "All set 1",
			json: `{
				"network_mode":"static",
				"host_ip":"127.0.0.1/24",
				"gateway":"127.0.0.1",
				"dns":["127.0.0.1"],
				"provisioning_urls":["http://server.com"],
				"identity":"some_id",
				"authentication":"1234",
				"timestamp":1,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want: Config{
				IPAddrMode:       ipam2ipam(t, IPStatic),
				HostIP:           s2cidr(t, "127.0.0.1/24"),
				DefaultGateway:   s2ip(t, "127.0.0.1"),
				DNSServer:        s2ipArray(t, "127.0.0.1"),
				ProvisioningURLs: s2urlArray(t, "http://server.com"),
				ID:               s2s(t, "some_id"),
				Auth:             s2s(t, "1234"),
			},
			errType: nil,
		},
		{
			name: "All set 2",
			json: `{
				"network_mode":"static",
				"host_ip":"127.0.0.1/24",
				"gateway":"127.0.0.1",
				"dns":["127.0.0.1"],
				"provisioning_urls":["http://server-a.com", "https://server-b.com"],
				"identity":"some-id",
				"authentication":"1234_",
				"timestamp":1,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want: Config{
				IPAddrMode:       ipam2ipam(t, IPStatic),
				HostIP:           s2cidr(t, "127.0.0.1/24"),
				DefaultGateway:   s2ip(t, "127.0.0.1"),
				DNSServer:        s2ipArray(t, "127.0.0.1"),
				ProvisioningURLs: s2urlArray(t, "http://server-a.com", "https://server-b.com"),
				ID:               s2s(t, "some-id"),
				Auth:             s2s(t, "1234_"),
			},
			errType: nil,
		},
		{
			name: "All unset",
			json: `{
				"network_mode":null,
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"provisioning_urls":null,
				"identity":null,
				"authentication":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name:    "Bad JSON",
			json:    `bad json`,
			want:    Config{},
			errType: &json.SyntaxError{},
		},
		{
			name: "Unset IPAddrMode",
			json: `{
				"network_mode":null,
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"provisioning_urls":null,
				"identity":null,
				"authentication":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name: "Unset ProvisioningURLs",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"provisioning_urls":null,
				"identity":null,
				"authentication":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name: "Empty ProvisioningURLs",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"provisioning_urls":[],
				"identity":null,
				"authentication":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name: "Unallowed scheme in ProvisioningURLs",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"provisioning_urls":["ftp://server.com"],
				"identity":null,
				"authentication":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name: "IPAddrMode=static but unset HostIP",
			json: `{
				"network_mode":"static",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"provisioning_urls":["http://server.com"],
				"identity":null,
				"authentication":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name: "IPAddrMode=static but unset DefaultGateway",
			json: `{
				"network_mode":"static",
				"host_ip":"127.0.0.1/24",
				"gateway":null,
				"dns":null,
				"provisioning_urls":["http://server.com"],
				"identity":null,
				"authentication":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name: "$ID used in ProvisioningURLs but ID unset",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"provisioning_urls":["http://server.com/$ID/foo"],
				"identity":null,
				"authentication":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name: "Unallowed cahr in ID 1",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"provisioning_urls":["http://server.com/$ID/foo"],
				"identity":"@",
				"authentication":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name: "Unallowed cahr in ID 2",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"provisioning_urls":["http://server.com/$ID/foo"],
				"identity":".",
				"authentication":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name: "Unallowed cahr in ID 3",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"provisioning_urls":["http://server.com/$ID/foo"],
				"identity":"/",
				"authentication":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name: "ID too long",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"provisioning_urls":["http://server.com/$ID/foo"],
				"identity":"ThisIsTooLong_(>64_Bytes)________________________________________",
				"authentication":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name: "$AUTH used in ProvisioningURLs but Auth unset",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"provisioning_urls":["http://server.com/$AUTH/foo"],
				"identity":null,
				"authentication":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name: "Unallowed cahr in Auth 1",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"provisioning_urls":["http://server.com/$AUTH/foo"],
				"identity":null,
				"authentication":"@",
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name: "Unallowed cahr in Auth 2",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"provisioning_urls":["http://server.com/$AUTH/foo"],
				"identity":null,
				"authentication":".",
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name: "Unallowed cahr in Auth 3",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"provisioning_urls":["http://server.com/$AUTH/foo"],
				"identity":null,
				"authentication":"/",
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name: "Auth too long",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"provisioning_urls":["http://server.com/$AUTH/foo"],
				"identity":null,
				"authentication":"ThisIsTooLong_(>64_Bytes)________________________________________",
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name: "Missing field network_mode",
			json: `{
				"host_ip":"127.0.0.1/24",
				"gateway":"127.0.0.1",
				"dns":"127.0.0.1",
				"provisioning_urls":["http://server.com"],
				"identity":"some_id",
				"authentication":"1234",
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name: "Missing field host_ip",
			json: `{
				"network_mode":"static",
				"gateway":"127.0.0.1",
				"dns":"127.0.0.1",
				"provisioning_urls":["http://server.com"],
				"identity":"some_id",
				"authentication":"1234",
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name: "Missing field gateway",
			json: `{
				"network_mode":"static",
				"host_ip":"127.0.0.1/24",
				"dns":"127.0.0.1",
				"provisioning_urls":["http://server.com"],
				"identity":"some_id",
				"authentication":"1234",
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name: "Missing field dns",
			json: `{
				"network_mode":"static",
				"host_ip":"127.0.0.1/24",
				"gateway":"127.0.0.1",
				"provisioning_urls":["http://server.com"],
				"identity":"some_id",
				"authentication":"1234",
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name: "Missing field network_interfaces",
			json: `{
				"network_mode":"static",
				"host_ip":"127.0.0.1/24",
				"gateway":"127.0.0.1",
				"dns":"127.0.0.1",
				"provisioning_urls":["http://server.com"],
				"identity":"some_id",
				"authentication":"1234",
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name: "Missing field provisioning_urls",
			json: `{
				"network_mode":"static",
				"host_ip":"127.0.0.1/24",
				"gateway":"127.0.0.1",
				"dns":"127.0.0.1",
				"network_interface":"00:00:5e:00:53:01",
				"identity":"some_id",
				"authentication":"1234",
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name: "Missing field identity",
			json: `{
				"network_mode":"static",
				"host_ip":"127.0.0.1/24",
				"gateway":"127.0.0.1",
				"dns":"127.0.0.1",
				"network_interface":"00:00:5e:00:53:01",
				"provisioning_urls":["http://server.com"],
				"authentication":"1234",
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name: "Missing field authentication",
			json: `{
				"network_mode":"static",
				"host_ip":"127.0.0.1/24",
				"gateway":"127.0.0.1",
				"dns":"127.0.0.1",
				"network_interface":"00:00:5e:00:53:01",
				"provisioning_urls":["http://server.com"],
				"identity":"some_id",
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    Config{},
			errType: errors.New(""),
		},
		{
			name: "Optional field",
			json: `{
				"version": 0,
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"network_interface":null,
				"provisioning_urls":["http://server.com"],
				"identity":null,
				"authentication":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want: Config{
				IPAddrMode:       ipam2ipam(t, IPDynamic),
				ProvisioningURLs: s2urlArray(t, "http://server.com"),
			},
			errType: nil,
		},
		{
			name: "Bad bonding field",
			json: `{
				"version": 0,
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"network_interface":null,
				"provisioning_urls":["http://server.com"],
				"identity":null,
				"authentication":null,
				"network_interfaces":null,
				"bonding_mode":"invalid",
				"bond_name":null
			}`,
			want:    Config{},
			errType: ErrInvalidBondMode,
		},
		{
			name: "Bad bond name field",
			json: `{
				"version": 0,
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"network_interface":null,
				"provisioning_urls":["http://server.com"],
				"identity":null,
				"authentication":null,
				"network_interfaces":null,
				"bonding_mode":"balance-rr",
				"bond_name":null
			}`,
			want:    Config{},
			errType: ErrMissingBondName,
		},
		{
			name: "No network interfaces",
			json: `{
				"version": 0,
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"network_interface":null,
				"provisioning_urls":["http://server.com"],
				"identity":null,
				"authentication":null,
				"network_interfaces":null,
				"bonding_mode":"balance-rr",
				"bond_name":"bond0"
			}`,
			want:    Config{},
			errType: ErrMissingNetworkInterfaces,
		},
		{
			name: "Valid bonding configuration with DHCP",
			json: `{
				"version": 0,
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"provisioning_urls":["http://server.com"],
				"identity":null,
				"authentication":null,
				"network_interfaces":[{"interface_name": "eth0", "mac_address": "00:00:5e:00:53:01"},{"interface_name": "eth1", "mac_address": "00:00:5e:00:53:02"}],
				"bonding_mode":"balance-rr",
				"bond_name":"bond0"
			}`,
			want: Config{
				IPAddrMode:        ipam2ipam(t, IPDynamic),
				ProvisioningURLs:  s2urlArray(t, "http://server.com"),
				BondName:          s2s(t, "bond0"),
				BondingMode:       BondingBalanceRR,
				NetworkInterfaces: s2sNetworkInterfaces(t, [][2]string{{"eth0", "00:00:5e:00:53:01"}, {"eth1", "00:00:5e:00:53:02"}}),
			},
			errType: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Config
			err := got.UnmarshalJSON([]byte(tt.json))

			assert(t, err, tt.errType, got, tt.want)
		})
	}
}

func TestNetlinkAddrModeMarshal(t *testing.T) {
	tests := []struct {
		name string
		addr netlinkAddr
		want string
	}{
		{
			name: "Valid IPv4 CIDR",
			addr: netlinkAddr(*s2cidr(t, "192.0.2.0/24")),
			want: `"192.0.2.0/24"`,
		},
		{
			name: "Valid IPv6 CIDR ",
			addr: netlinkAddr(*s2cidr(t, "2001:db8::/32")),
			want: `"2001:db8::/32"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.addr.MarshalJSON()
			assert(t, err, nil, string(got), tt.want)
		})
	}
}

func TestNetlinkAddrUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    netlinkAddr
		errType error
	}{
		{
			name:    jsonutil.Null,
			json:    `null`,
			want:    netlinkAddr{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			name:    "IPv4",
			json:    `"192.0.2.0/24"`,
			want:    netlinkAddr(*s2cidr(t, "192.0.2.0/24")),
			errType: nil,
		},
		{
			name:    "IPv6",
			json:    `"2001:db8::/32"`,
			want:    netlinkAddr(*s2cidr(t, "2001:db8::/32")),
			errType: nil,
		},
		{
			name:    "Missing mask",
			json:    `"192.0.2.0"`,
			want:    netlinkAddr{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			name:    "Invalid type",
			json:    `192`,
			want:    netlinkAddr{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			name:    "Invalid string",
			json:    `"192-0-2-0"`,
			want:    netlinkAddr{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			name:    "Empty string",
			json:    `""`,
			want:    netlinkAddr{},
			errType: &json.UnmarshalTypeError{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got netlinkAddr
			err := got.UnmarshalJSON([]byte(tt.json))
			assert(t, err, tt.errType, got, tt.want)
		})
	}
}

func TestNetIPMarshal(t *testing.T) {
	tests := []struct {
		name string
		ip   netIP
		want string
	}{
		{
			name: "IPv4",
			ip:   netIP(*s2ip(t, "192.0.2.0")),
			want: `"192.0.2.0"`,
		},
		{
			name: "IPv6",
			ip:   netIP(*s2ip(t, "2001:db8::")),
			want: `"2001:db8::"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.ip.MarshalJSON()
			assert(t, err, nil, string(got), tt.want)
		})
	}
}

func TestNetIPUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    netIP
		errType error
	}{
		{
			name:    jsonutil.Null,
			json:    `null`,
			want:    nil,
			errType: nil,
		},
		{
			name:    "IPv4",
			json:    `"192.0.2.0"`,
			want:    netIP(*s2ip(t, "192.0.2.0")),
			errType: nil,
		},
		{
			name:    "IPv6",
			json:    `"2001:db8::"`,
			want:    netIP(*s2ip(t, "2001:db8::")),
			errType: nil,
		},
		{
			name:    "Invalid type",
			json:    `192`,
			want:    nil,
			errType: &json.UnmarshalTypeError{},
		},
		{
			name:    "Invalid string",
			json:    `"192-0-2-0"`,
			want:    nil,
			errType: &json.UnmarshalTypeError{},
		},
		{
			name:    "Empty string",
			json:    `""`,
			want:    nil,
			errType: &json.UnmarshalTypeError{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got netIP
			err := got.UnmarshalJSON([]byte(tt.json))
			assert(t, err, tt.errType, got, tt.want)
		})
	}
}

func TestNetHardwareAddrMarshal(t *testing.T) {
	tests := []struct {
		name string
		addr netHardwareAddr
		want string
	}{
		{
			name: "Valid",
			addr: netHardwareAddr(*s2mac(t, "00:00:5e:00:53:01")),
			want: `"00:00:5e:00:53:01"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.addr.MarshalJSON()
			assert(t, err, nil, string(got), tt.want)
		})
	}
}

func TestNetHardwareAddrUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    netHardwareAddr
		errType error
	}{
		{
			name:    jsonutil.Null,
			json:    `null`,
			want:    nil,
			errType: nil,
		},
		{
			name:    "Valid colon",
			json:    `"00:00:5e:00:53:01"`,
			want:    netHardwareAddr(*s2mac(t, "00:00:5e:00:53:01")),
			errType: nil,
		},
		{
			name:    "Valid dash",
			json:    `"00-00-5e-00-53-01"`,
			want:    netHardwareAddr(*s2mac(t, "00-00-5e-00-53-01")),
			errType: nil,
		},
		{
			name:    "Invalid type",
			json:    `0`,
			want:    nil,
			errType: &json.UnmarshalTypeError{},
		},
		{
			name:    "Invalid string",
			json:    `"00005e005301"`,
			want:    nil,
			errType: &json.UnmarshalTypeError{},
		},
		{
			name:    "Empty string",
			json:    `""`,
			want:    nil,
			errType: &json.UnmarshalTypeError{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got netHardwareAddr
			err := got.UnmarshalJSON([]byte(tt.json))
			assert(t, err, tt.errType, got, tt.want)
		})
	}
}

func TestUrlURLMarshal(t *testing.T) {
	tests := []struct {
		name string
		u    urlURL
		want string
	}{
		{
			name: "Valid",
			u:    urlURL(*s2url(t, "http://server.com")),
			want: `"http://server.com"`,
		},
		{
			name: "Valid with variable",
			u:    urlURL(*s2url(t, "http://server.com/$ID/foo")),
			want: `"http://server.com/$ID/foo"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.u.MarshalJSON()
			assert(t, err, nil, string(got), tt.want)
		})
	}
}

func TestUrlURLUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    urlURL
		errType error
	}{
		{
			name:    jsonutil.Null,
			json:    `null`,
			want:    urlURL{},
			errType: nil,
		},
		{
			name:    "Valid",
			json:    `"http://server.com"`,
			want:    urlURL(*s2url(t, "http://server.com")),
			errType: nil,
		},
		{
			name:    "Valid with variable",
			json:    `"http://server.com/$ID/foo"`,
			want:    urlURL(*s2url(t, "http://server.com/$ID/foo")),
			errType: nil,
		},
		{
			name:    "Missing scheme",
			json:    `"server.com"`,
			want:    urlURL{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			name:    "Invalid type",
			json:    `0`,
			want:    urlURL{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			name:    "Invalid string",
			json:    `"00005e005301"`,
			want:    urlURL{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			name:    "Empty string",
			json:    `""`,
			want:    urlURL{},
			errType: &json.UnmarshalTypeError{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got urlURL
			err := got.UnmarshalJSON([]byte(tt.json))
			assert(t, err, tt.errType, got, tt.want)
		})
	}
}

func assert(t *testing.T, gotErr error, wantErrType, got, want interface{}) {
	t.Helper()

	if wantErrType != nil {
		if gotErr == nil {
			t.Fatal("expect an error")
		}

		ok := errors.As(gotErr, &wantErrType)
		if !ok {
			t.Fatalf("%+v does not wrap expected %+v", gotErr, wantErrType)
		}
	} else if gotErr != nil {
		t.Fatalf("unexpected error: %v", gotErr)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func s2cidr(t *testing.T, s string) *netlink.Addr {
	t.Helper()

	ip, err := netlink.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}

	return ip
}

func s2ip(t *testing.T, s string) *net.IP {
	t.Helper()

	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("error parsing %s to net.IP", s)
	}

	return &ip
}

func s2ipArray(t *testing.T, s ...string) *[]*net.IP {
	t.Helper()

	a := []*net.IP{}

	if len(s) == 0 {
		t.Fatal("no string provided")
	}

	for _, str := range s {
		i := s2ip(t, str)
		a = append(a, i)
	}

	return &a
}

func s2mac(t *testing.T, s string) *net.HardwareAddr {
	t.Helper()

	mac, err := net.ParseMAC(s)
	if err != nil {
		t.Fatal(err)
	}

	return &mac
}

func s2url(t *testing.T, s string) *url.URL {
	t.Helper()

	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}

	return u
}

func s2urlArray(t *testing.T, s ...string) *[]*url.URL {
	t.Helper()

	a := []*url.URL{}

	if len(s) == 0 {
		t.Fatal("no string provided")
	}

	for _, str := range s {
		u := s2url(t, str)
		a = append(a, u)
	}

	return &a
}

func s2s(t *testing.T, s string) *string {
	t.Helper()

	return &s
}

//lint:ignore U1000 might be useful
func s2sArray(t *testing.T, s ...string) *[]*string {
	t.Helper()

	a := []*string{}

	if len(s) == 0 {
		t.Fatal("no string provided")
	}

	for _, str := range s {
		u := s2s(t, str)
		a = append(a, u)
	}

	return &a
}

func ipam2ipam(t *testing.T, m IPAddrMode) *IPAddrMode {
	t.Helper()

	return &m
}

func s2sNetworkInterfaces(t *testing.T, s [][2]string) *[]*NetworkInterface {
	t.Helper()

	var n []*NetworkInterface //nolint:prealloc
	for _, i := range s {
		n = append(n, &NetworkInterface{
			InterfaceName: s2s(t, i[0]),
			MACAddress:    s2mac(t, i[1]),
		})
	}

	return &n
}
