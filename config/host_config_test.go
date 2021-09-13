package config

import (
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

type StubHostCfgParser struct {
	hc *HostCfg
}

func (s StubHostCfgParser) Parse() (*HostCfg, error) {
	return s.hc, nil
}

func TestLoadHostCfg(t *testing.T) {

	invalidURL1, _ := url.Parse("foo.com/bar")
	invalidURL2, _ := url.Parse("ftp://foo.com/bar")
	validURL1, _ := url.Parse("http://foo.com/bar")
	validURL2, _ := url.Parse("https://foo.com/bar")
	urlWithID, _ := url.Parse("http://foo.com/$ID/bar")
	urlWithIDandAuth, _ := url.Parse("http://foo.com/$ID/$AUTH/bar")
	gw := net.ParseIP("127.0.0.1")
	ip, _ := netlink.ParseAddr("127.0.0.1/24")

	validHostCfgTests := []struct {
		name string
		cfg  *HostCfg
	}{
		{
			name: "Minimum valid config with dynamic IP address",
			cfg: &HostCfg{
				Version:          HostCfgVersion,
				IPAddrMode:       DynamicIP,
				ProvisioningURLs: []*url.URL{validURL1},
			},
		},
		{
			name: "Minimum valid config with static IP address",
			cfg: &HostCfg{
				Version:          HostCfgVersion,
				IPAddrMode:       StaticIP,
				HostIP:           ip,
				DefaultGateway:   &gw,
				ProvisioningURLs: []*url.URL{validURL1},
			},
		},
	}

	for _, tt := range validHostCfgTests {
		t.Run(tt.name, func(t *testing.T) {
			p := StubHostCfgParser{tt.cfg}
			_, err := LoadHostCfg(p)

			assertNoError(t, err)
		})
	}

	invalidHostCfgTests := []struct {
		name string
		cfg  *HostCfg
		want error
	}{
		{
			name: "Missing version",
			cfg: &HostCfg{
				IPAddrMode:       DynamicIP,
				ProvisioningURLs: []*url.URL{validURL1},
			},
			want: ErrHostCfgVersionMissmatch,
		},
		{
			name: "Version missmatch",
			cfg: &HostCfg{
				Version:          HostCfgVersion + 1,
				IPAddrMode:       DynamicIP,
				ProvisioningURLs: []*url.URL{validURL1},
			},
			want: ErrHostCfgVersionMissmatch,
		},
		{
			name: "Missing IP address mode",
			cfg: &HostCfg{
				Version:          HostCfgVersion,
				ProvisioningURLs: []*url.URL{validURL1},
			},
			want: ErrMissingIPAddrMode,
		},
		{
			name: "Unknown IP address mode",
			cfg: &HostCfg{
				Version:          HostCfgVersion,
				IPAddrMode:       3,
				ProvisioningURLs: []*url.URL{validURL1},
			},
			want: ErrUnknownIPAddrMode,
		},
		{
			name: "Missing IP address",
			cfg: &HostCfg{
				Version:          HostCfgVersion,
				IPAddrMode:       StaticIP,
				ProvisioningURLs: []*url.URL{validURL1},
				DefaultGateway:   &gw,
			},
			want: ErrMissingIPAddr,
		},
		{
			name: "Missing gateway",
			cfg: &HostCfg{
				Version:          HostCfgVersion,
				IPAddrMode:       StaticIP,
				ProvisioningURLs: []*url.URL{validURL1},
				HostIP:           ip,
			},
			want: ErrMissingGateway,
		},
		{
			name: "Missing URLs",
			cfg: &HostCfg{
				Version:    HostCfgVersion,
				IPAddrMode: DynamicIP,
			},
			want: ErrMissingProvURLs,
		},
		{
			name: "Invalid URLs 1",
			cfg: &HostCfg{
				Version:          HostCfgVersion,
				IPAddrMode:       DynamicIP,
				ProvisioningURLs: []*url.URL{validURL1, invalidURL1},
			},
			want: ErrInvalidProvURLs,
		},
		{
			name: "Invalid URLs 2",
			cfg: &HostCfg{
				Version:          HostCfgVersion,
				IPAddrMode:       DynamicIP,
				ProvisioningURLs: []*url.URL{validURL2, invalidURL2},
			},
			want: ErrInvalidProvURLs,
		},
		{
			name: "Missing ID",
			cfg: &HostCfg{
				Version:          HostCfgVersion,
				IPAddrMode:       DynamicIP,
				ProvisioningURLs: []*url.URL{urlWithID},
			},
			want: ErrMissingID,
		},
		{
			name: "Invalid ID 1",
			cfg: &HostCfg{
				Version:          HostCfgVersion,
				IPAddrMode:       DynamicIP,
				ProvisioningURLs: []*url.URL{urlWithID},
				ID:               "abc/1",
			},
			want: ErrInvalidID,
		},
		{
			name: "Invalid ID 2",
			cfg: &HostCfg{
				Version:          HostCfgVersion,
				IPAddrMode:       DynamicIP,
				ProvisioningURLs: []*url.URL{urlWithID},
				ID:               "abc:1",
			},
			want: ErrInvalidID,
		},
		{
			name: "Invalid ID 3",
			cfg: &HostCfg{
				Version:          HostCfgVersion,
				IPAddrMode:       DynamicIP,
				ProvisioningURLs: []*url.URL{urlWithID},
				ID:               "abc@1",
			},
			want: ErrInvalidID,
		},
		{
			name: "Invalid ID 4",
			cfg: &HostCfg{
				Version:          HostCfgVersion,
				IPAddrMode:       DynamicIP,
				ProvisioningURLs: []*url.URL{urlWithID},
				ID:               strings.Repeat("a", 65),
			},
			want: ErrInvalidID,
		},
		{
			name: "Missing Auth",
			cfg: &HostCfg{
				Version:          HostCfgVersion,
				IPAddrMode:       DynamicIP,
				ProvisioningURLs: []*url.URL{urlWithIDandAuth},
				ID:               "abc",
			},
			want: ErrMissingAuth,
		},
		{
			name: "Invalid Auth 1",
			cfg: &HostCfg{
				Version:          HostCfgVersion,
				IPAddrMode:       DynamicIP,
				ProvisioningURLs: []*url.URL{urlWithIDandAuth},
				ID:               "abc",
				Auth:             "abc/1",
			},
			want: ErrInvalidAuth,
		},
		{
			name: "Invalid Auth 2",
			cfg: &HostCfg{
				Version:          HostCfgVersion,
				IPAddrMode:       DynamicIP,
				ProvisioningURLs: []*url.URL{urlWithIDandAuth},
				ID:               "abc",
				Auth:             "abc:1",
			},
			want: ErrInvalidAuth,
		},
		{
			name: "Invalid Auth 3",
			cfg: &HostCfg{
				Version:          HostCfgVersion,
				IPAddrMode:       DynamicIP,
				ProvisioningURLs: []*url.URL{urlWithIDandAuth},
				ID:               "abc",
				Auth:             "abc@1",
			},
			want: ErrInvalidAuth,
		},
		{
			name: "Invalid Auth 4",
			cfg: &HostCfg{
				Version:          HostCfgVersion,
				IPAddrMode:       DynamicIP,
				ProvisioningURLs: []*url.URL{urlWithIDandAuth},
				ID:               "abc",
				Auth:             strings.Repeat("a", 65),
			},
			want: ErrInvalidAuth,
		},
	}

	for _, tt := range invalidHostCfgTests {
		t.Run(tt.name, func(t *testing.T) {
			p := StubHostCfgParser{tt.cfg}
			_, err := LoadHostCfg(p)

			assertError(t, err, tt.want)
		})
	}
}

func assertError(t testing.TB, got, want error) {
	t.Helper()
	if got == nil {
		t.Fatal("expected an error")
	}

	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func assertNoError(t testing.TB, got error) {
	t.Helper()
	if got != nil {
		t.Errorf("didn't expect an error but got: %v", got)
	}
}

func TestIPAddrMode(t *testing.T) {
	tests := []struct {
		name string
		mode IPAddrMode
		want string
	}{
		{
			name: "String for default value",
			mode: UnsetIPAddrMode,
			want: "unset",
		},
		{
			name: "String for 'StaticIP'",
			mode: StaticIP,
			want: "static",
		},
		{
			name: "String for 'DynamicIP'",
			mode: DynamicIP,
			want: "dynamic",
		},
		{
			name: "String for unknown value",
			mode: 3,
			want: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.mode.String()
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
