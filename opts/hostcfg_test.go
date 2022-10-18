package opts

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"
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
			name:    JSONNull,
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

func TestHostCfgMarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		h    HostCfg
		want string
	}{
		{
			name: "Unset HostCfg",
			h:    HostCfg{},
			want: `{
				"network_mode":null,
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"network_interface":null,
				"provisioning_urls":null,
				"identity":null,
				"authentication":null,
				"timestamp":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
				}`,
		},
		{
			name: "All fields set",
			h: HostCfg{
				IPAddrMode:        IPStatic,
				HostIP:            s2cidr(t, "127.0.0.1/24"),
				DefaultGateway:    s2ip(t, "127.0.0.1"),
				DNSServer:         s2ip(t, "127.0.0.1"),
				NetworkInterface:  s2mac(t, "00:00:5e:00:53:01"),
				ProvisioningURLs:  s2urlArray(t, "http://foo.com/bar", "https://foo.com/bar"),
				ID:                s2s(t, "someID"),
				Auth:              s2s(t, "1234"),
				Timestamp:         i2time(t, 1639307532),
				NetworkInterfaces: s2sArray(t, "eth0", "eth1"),
				BondingMode:       BondingBalancedRR,
				BondName:          s2s(t, "bond0"),
			},
			want: `{
				"network_mode":"static",
				"host_ip":"127.0.0.1/24",
				"gateway":"127.0.0.1",
				"dns":"127.0.0.1",
				"network_interface":"00:00:5e:00:53:01",
				"provisioning_urls":["http://foo.com/bar", "https://foo.com/bar"],
				"identity":"someID",
				"authentication":"1234",
				"timestamp":1639307532,
				"network_interfaces":["eth0", "eth1"],
				"bonding_mode":"balanced-rr",
				"bond_name":"bond0"
				}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.MarshalJSON()
			want := strings.Join(strings.Fields(tt.want), "")
			assert(t, err, nil, string(got), want)
		})
	}
}

func TestHostCfgUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    HostCfg
		errType error
	}{
		{
			name: "Minimal for dhcp",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"network_interface":null,
				"provisioning_urls":["http://server.com"],
				"identity":null,
				"authentication":null,
				"timestamp":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want: HostCfg{
				IPAddrMode:       IPDynamic,
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
				"network_interface":null,
				"provisioning_urls":["http://server.com"],
				"identity":null,
				"authentication":null,
				"timestamp":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want: HostCfg{
				IPAddrMode:       IPStatic,
				HostIP:           s2cidr(t, "127.0.0.1/24"),
				DefaultGateway:   s2ip(t, "127.0.0.1"),
				ProvisioningURLs: s2urlArray(t, "http://server.com"),
			},
			errType: nil,
		},
		{
			name: "All set 1",
			json: `{
				"network_mode":"static",
				"host_ip":"127.0.0.1/24",
				"gateway":"127.0.0.1",
				"dns":"127.0.0.1",
				"network_interface":"00:00:5e:00:53:01",
				"provisioning_urls":["http://server.com"],
				"identity":"some_id",
				"authentication":"1234",
				"timestamp":1,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want: HostCfg{
				IPAddrMode:       IPStatic,
				HostIP:           s2cidr(t, "127.0.0.1/24"),
				DefaultGateway:   s2ip(t, "127.0.0.1"),
				DNSServer:        s2ip(t, "127.0.0.1"),
				NetworkInterface: s2mac(t, "00:00:5e:00:53:01"),
				ProvisioningURLs: s2urlArray(t, "http://server.com"),
				ID:               s2s(t, "some_id"),
				Auth:             s2s(t, "1234"),
				Timestamp:        i2time(t, 1),
			},
			errType: nil,
		},
		{
			name: "All set 2",
			json: `{
				"network_mode":"static",
				"host_ip":"127.0.0.1/24",
				"gateway":"127.0.0.1",
				"dns":"127.0.0.1",
				"network_interface":"00:00:5e:00:53:01",
				"provisioning_urls":["http://server-a.com", "https://server-b.com"],
				"identity":"some-id",
				"authentication":"1234_",
				"timestamp":1,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want: HostCfg{
				IPAddrMode:       IPStatic,
				HostIP:           s2cidr(t, "127.0.0.1/24"),
				DefaultGateway:   s2ip(t, "127.0.0.1"),
				DNSServer:        s2ip(t, "127.0.0.1"),
				NetworkInterface: s2mac(t, "00:00:5e:00:53:01"),
				ProvisioningURLs: s2urlArray(t, "http://server-a.com", "https://server-b.com"),
				ID:               s2s(t, "some-id"),
				Auth:             s2s(t, "1234_"),
				Timestamp:        i2time(t, 1),
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
				"network_interface":null,
				"provisioning_urls":null,
				"identity":null,
				"authentication":null,
				"timestamp":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: Error(""),
		},
		{
			name:    "Bad JSON",
			json:    `bad json`,
			want:    HostCfg{},
			errType: &json.SyntaxError{},
		},
		{
			name: "Unset IPAddrMode",
			json: `{
				"network_mode":null,
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"network_interface":null,
				"provisioning_urls":null,
				"identity":null,
				"authentication":null,
				"timestamp":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: Error(""),
		},
		{
			name: "Unset ProvisioningURLs",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"network_interface":null,
				"provisioning_urls":null,
				"identity":null,
				"authentication":null,
				"timestamp":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: Error(""),
		},
		{
			name: "Empty ProvisioningURLs",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"network_interface":null,
				"provisioning_urls":[],
				"identity":null,
				"authentication":null,
				"timestamp":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: Error(""),
		},
		{
			name: "Unallowed scheme in ProvisioningURLs",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"network_interface":null,
				"provisioning_urls":["ftp://server.com"],
				"identity":null,
				"authentication":null,
				"timestamp":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: Error(""),
		},
		{
			name: "IPAddrMode=static but unset HostIP",
			json: `{
				"network_mode":"static",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"network_interface":null,
				"provisioning_urls":["http://server.com"],
				"identity":null,
				"authentication":null,
				"timestamp":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: Error(""),
		},
		{
			name: "IPAddrMode=static but unset DefaultGateway",
			json: `{
				"network_mode":"static",
				"host_ip":"127.0.0.1/24",
				"gateway":null,
				"dns":null,
				"network_interface":null,
				"provisioning_urls":["http://server.com"],
				"identity":null,
				"authentication":null,
				"timestamp":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: Error(""),
		},
		{
			name: "$ID used in ProvisioningURLs but ID unset",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"network_interface":null,
				"provisioning_urls":["http://server.com/$ID/foo"],
				"identity":null,
				"authentication":null,
				"timestamp":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: Error(""),
		},
		{
			name: "Unallowed cahr in ID 1",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"network_interface":null,
				"provisioning_urls":["http://server.com/$ID/foo"],
				"identity":"@",
				"authentication":null,
				"timestamp":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: Error(""),
		},
		{
			name: "Unallowed cahr in ID 2",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"network_interface":null,
				"provisioning_urls":["http://server.com/$ID/foo"],
				"identity":".",
				"authentication":null,
				"timestamp":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: Error(""),
		},
		{
			name: "Unallowed cahr in ID 3",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"network_interface":null,
				"provisioning_urls":["http://server.com/$ID/foo"],
				"identity":"/",
				"authentication":null,
				"timestamp":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: Error(""),
		},
		{
			name: "ID too long",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"network_interface":null,
				"provisioning_urls":["http://server.com/$ID/foo"],
				"identity":"ThisIsTooLong_(>64_Bytes)________________________________________",
				"authentication":null,
				"timestamp":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: Error(""),
		},
		{
			name: "$AUTH used in ProvisioningURLs but Auth unset",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"network_interface":null,
				"provisioning_urls":["http://server.com/$AUTH/foo"],
				"identity":null,
				"authentication":null,
				"timestamp":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: Error(""),
		},
		{
			name: "Unallowed cahr in Auth 1",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"network_interface":null,
				"provisioning_urls":["http://server.com/$AUTH/foo"],
				"identity":null,
				"authentication":"@",
				"timestamp":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: Error(""),
		},
		{
			name: "Unallowed cahr in Auth 2",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"network_interface":null,
				"provisioning_urls":["http://server.com/$AUTH/foo"],
				"identity":null,
				"authentication":".",
				"timestamp":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: Error(""),
		},
		{
			name: "Unallowed cahr in Auth 3",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"network_interface":null,
				"provisioning_urls":["http://server.com/$AUTH/foo"],
				"identity":null,
				"authentication":"/",
				"timestamp":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: Error(""),
		},
		{
			name: "Auth too long",
			json: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"network_interface":null,
				"provisioning_urls":["http://server.com/$AUTH/foo"],
				"identity":null,
				"authentication":"ThisIsTooLong_(>64_Bytes)________________________________________",
				"timestamp":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: Error(""),
		},
		{
			name: "Missing field network_mode",
			json: `{
				"host_ip":"127.0.0.1/24",
				"gateway":"127.0.0.1",
				"dns":"127.0.0.1",
				"network_interface":"00:00:5e:00:53:01",
				"provisioning_urls":["http://server.com"],
				"identity":"some_id",
				"authentication":"1234",
				"timestamp":1,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: ErrNonNil,
		},
		{
			name: "Missing field host_ip",
			json: `{
				"network_mode":"static",
				"gateway":"127.0.0.1",
				"dns":"127.0.0.1",
				"network_interface":"00:00:5e:00:53:01",
				"provisioning_urls":["http://server.com"],
				"identity":"some_id",
				"authentication":"1234",
				"timestamp":1,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: ErrNonNil,
		},
		{
			name: "Missing field gateway",
			json: `{
				"network_mode":"static",
				"host_ip":"127.0.0.1/24",
				"dns":"127.0.0.1",
				"network_interface":"00:00:5e:00:53:01",
				"provisioning_urls":["http://server.com"],
				"identity":"some_id",
				"authentication":"1234",
				"timestamp":1,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: ErrNonNil,
		},
		{
			name: "Missing field dns",
			json: `{
				"network_mode":"static",
				"host_ip":"127.0.0.1/24",
				"gateway":"127.0.0.1",
				"network_interface":"00:00:5e:00:53:01",
				"provisioning_urls":["http://server.com"],
				"identity":"some_id",
				"authentication":"1234",
				"timestamp":1,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: ErrNonNil,
		},
		{
			name: "Missing field network_interface",
			json: `{
				"network_mode":"static",
				"host_ip":"127.0.0.1/24",
				"gateway":"127.0.0.1",
				"dns":"127.0.0.1",
				"provisioning_urls":["http://server.com"],
				"identity":"some_id",
				"authentication":"1234",
				"timestamp":1,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: ErrNonNil,
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
				"timestamp":1,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: ErrNonNil,
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
				"timestamp":1,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: ErrNonNil,
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
				"timestamp":1,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: ErrNonNil,
		},
		{
			name: "Missing field timestamp",
			json: `{
				"network_mode":"static",
				"host_ip":"127.0.0.1/24",
				"gateway":"127.0.0.1",
				"dns":"127.0.0.1",
				"network_interface":"00:00:5e:00:53:01",
				"provisioning_urls":["http://server.com"],
				"identity":"some_id",
				"authentication":"1234"
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want:    HostCfg{},
			errType: ErrNonNil,
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
				"timestamp":null,
				"network_interfaces":null,
				"bonding_mode":null,
				"bond_name":null
			}`,
			want: HostCfg{
				IPAddrMode:       IPDynamic,
				ProvisioningURLs: s2urlArray(t, "http://server.com"),
			},
			errType: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got HostCfg
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
			name:    JSONNull,
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
			name:    JSONNull,
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
			name:    JSONNull,
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
			name:    JSONNull,
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

func TestTimeTimeMarshal(t *testing.T) {
	tests := []struct {
		name string
		t    timeTime
		want string
	}{
		{
			name: "Valid",
			t:    timeTime(*i2time(t, 1)),
			want: `1`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.t.MarshalJSON()
			assert(t, err, nil, string(got), tt.want)
		})
	}
}

func TestTimeTimeUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    timeTime
		errType error
	}{
		{
			name:    JSONNull,
			json:    `null`,
			want:    timeTime{},
			errType: nil,
		},
		{
			name:    "Valid",
			json:    `1`,
			want:    timeTime(time.Unix(1, 0)),
			errType: nil,
		},
		{
			name:    "Zero",
			json:    `0`,
			want:    timeTime(time.Unix(0, 0)),
			errType: nil,
		},
		{
			name:    "Invalid type",
			json:    `"0"`,
			want:    timeTime{},
			errType: &json.UnmarshalTypeError{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got timeTime
			err := got.UnmarshalJSON([]byte(tt.json))
			assert(t, err, tt.errType, got, tt.want)
		})
	}
}

func TestHostCfgJSONLoad(t *testing.T) {
	goodJSON, err := os.ReadFile("testdata/host_good_all_set.json")
	if err != nil {
		t.Fatal(err)
	}

	badJSON, err := os.ReadFile("testdata/host_bad_unset.json")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		loader  HostCfgJSON
		errType error
	}{
		{
			name: "Successful loading",
			loader: HostCfgJSON{
				Reader: bytes.NewBuffer(goodJSON),
			},
			errType: nil,
		},
		{
			name:    "No source",
			loader:  HostCfgJSON{},
			errType: ErrNonNil,
		},
		{
			name: "Bad source",
			loader: HostCfgJSON{
				Reader: bytes.NewBufferString("bad"),
			},
			errType: &json.SyntaxError{},
		},
		{
			name: "Bad content",
			loader: HostCfgJSON{
				Reader: bytes.NewBuffer(badJSON),
			},
			errType: Error(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.loader.Load(&Opts{})
			assert(t, err, tt.errType, nil, nil)
		})
	}
}

func TestHostCfgFileLoad(t *testing.T) {
	goodJSON := "testdata/host_good_all_set.json"
	badJSON := "testdata/host_bad_unset.json"

	tests := []struct {
		name    string
		loader  HostCfgFile
		errType error
	}{
		{
			name: "Successful loading",
			loader: HostCfgFile{
				Name: goodJSON,
			},
			errType: nil,
		},
		{
			name:    "No file provided",
			loader:  HostCfgFile{},
			errType: &fs.PathError{},
		},
		{
			name: "Bad file",
			loader: HostCfgFile{
				Name: "not/exist",
			},
			errType: &fs.PathError{},
		},
		{
			name: "Bad content",
			loader: HostCfgFile{
				Name: badJSON,
			},
			errType: Error(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.loader.Load(&Opts{})
			assert(t, err, tt.errType, nil, nil)
		})
	}
}
