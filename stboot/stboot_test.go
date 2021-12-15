package stboot

import (
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestInvalidOptsError(t *testing.T) {
	msg := "some error message"
	err := InvalidOptsError(msg)

	got := err.Error()
	if got != msg {
		t.Errorf("got %q, want %q", got, msg)
	}
}

func TestBootMode(t *testing.T) {
	tests := []struct {
		name string
		mode BootMode
		want string
	}{
		{
			name: "String for default value",
			mode: BootModeUnset,
			want: "unset",
		},
		{
			name: "String for 'LocalBoot'",
			mode: LocalBoot,
			want: "local",
		},
		{
			name: "String for 'NetworkBoot'",
			mode: NetworkBoot,
			want: "network",
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

func TestIPAddrMode(t *testing.T) {
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
			want: "DHCP",
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

func TestSecurityCfgValidation(t *testing.T) {
	validSecurityCfgTests := []struct {
		name string
		cfg  securityCfg
	}{
		{
			name: "Minimum valid config with implicit defaults",
			cfg: securityCfg{
				BootMode: LocalBoot,
			},
		},
		{
			name: "Minimum valid config with explicit values",
			cfg: securityCfg{
				ValidSignatureThreshold: 1,
				BootMode:                NetworkBoot,
				UsePkgCache:             true,
			},
		},
	}

	invalidSecurityCfgTests := []struct {
		name string
		cfg  securityCfg
		want error
	}{
		{
			name: "Empty boot mode",
			cfg:  securityCfg{},
			want: ErrMissingBootMode,
		},
		{
			name: "Unknown boot mode",
			cfg: securityCfg{
				BootMode: 3,
			},
			want: ErrUnknownBootMode,
		},
	}

	for _, tt := range validSecurityCfgTests {
		t.Run(tt.name, func(t *testing.T) {
			o := Opts{securityCfg: tt.cfg}
			err := o.validate(scValidators...)

			assertNoError(t, err)
		})
	}

	for _, tt := range invalidSecurityCfgTests {
		t.Run(tt.name, func(t *testing.T) {
			o := Opts{securityCfg: tt.cfg}
			err := o.validate(scValidators...)

			assertError(t, err, tt.want)
		})
	}
}

func TestHostCfgValidation(t *testing.T) {

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
		cfg  hostCfg
	}{
		{
			name: "Minimum valid config with dynamic IP address",
			cfg: hostCfg{
				IPAddrMode:       IPDynamic,
				ProvisioningURLs: []*url.URL{validURL1},
			},
		},
		{
			name: "Minimum valid config with static IP address",
			cfg: hostCfg{
				IPAddrMode:       IPStatic,
				HostIP:           ip,
				DefaultGateway:   &gw,
				ProvisioningURLs: []*url.URL{validURL1},
			},
		},
	}

	invalidHostCfgTests := []struct {
		name string
		cfg  hostCfg
		want error
	}{
		{
			name: "Missing IP address mode",
			cfg: hostCfg{
				ProvisioningURLs: []*url.URL{validURL1},
			},
			want: ErrMissingIPAddrMode,
		},
		{
			name: "Unknown IP address mode",
			cfg: hostCfg{
				IPAddrMode:       3,
				ProvisioningURLs: []*url.URL{validURL1},
			},
			want: ErrUnknownIPAddrMode,
		},
		{
			name: "Missing IP address",
			cfg: hostCfg{
				IPAddrMode:       IPStatic,
				ProvisioningURLs: []*url.URL{validURL1},
				DefaultGateway:   &gw,
			},
			want: ErrMissingIPAddr,
		},
		{
			name: "Missing gateway",
			cfg: hostCfg{
				IPAddrMode:       IPStatic,
				ProvisioningURLs: []*url.URL{validURL1},
				HostIP:           ip,
			},
			want: ErrMissingGateway,
		},
		{
			name: "Missing URLs",
			cfg: hostCfg{
				IPAddrMode: IPDynamic,
			},
			want: ErrMissingProvURLs,
		},
		{
			name: "Invalid URLs 1",
			cfg: hostCfg{
				IPAddrMode:       IPDynamic,
				ProvisioningURLs: []*url.URL{validURL1, invalidURL1},
			},
			want: ErrInvalidProvURLs,
		},
		{
			name: "Invalid URLs 2",
			cfg: hostCfg{
				IPAddrMode:       IPDynamic,
				ProvisioningURLs: []*url.URL{validURL2, invalidURL2},
			},
			want: ErrInvalidProvURLs,
		},
		{
			name: "Missing ID",
			cfg: hostCfg{
				IPAddrMode:       IPDynamic,
				ProvisioningURLs: []*url.URL{urlWithID},
			},
			want: ErrMissingID,
		},
		{
			name: "Invalid ID 1",
			cfg: hostCfg{
				IPAddrMode:       IPDynamic,
				ProvisioningURLs: []*url.URL{urlWithID},
				ID:               "abc/1",
			},
			want: ErrInvalidID,
		},
		{
			name: "Invalid ID 2",
			cfg: hostCfg{
				IPAddrMode:       IPDynamic,
				ProvisioningURLs: []*url.URL{urlWithID},
				ID:               "abc:1",
			},
			want: ErrInvalidID,
		},
		{
			name: "Invalid ID 3",
			cfg: hostCfg{
				IPAddrMode:       IPDynamic,
				ProvisioningURLs: []*url.URL{urlWithID},
				ID:               "abc@1",
			},
			want: ErrInvalidID,
		},
		{
			name: "Invalid ID 4",
			cfg: hostCfg{
				IPAddrMode:       IPDynamic,
				ProvisioningURLs: []*url.URL{urlWithID},
				ID:               strings.Repeat("a", 65),
			},
			want: ErrInvalidID,
		},
		{
			name: "Missing Auth",
			cfg: hostCfg{
				IPAddrMode:       IPDynamic,
				ProvisioningURLs: []*url.URL{urlWithIDandAuth},
				ID:               "abc",
			},
			want: ErrMissingAuth,
		},
		{
			name: "Invalid Auth 1",
			cfg: hostCfg{
				IPAddrMode:       IPDynamic,
				ProvisioningURLs: []*url.URL{urlWithIDandAuth},
				ID:               "abc",
				Auth:             "abc/1",
			},
			want: ErrInvalidAuth,
		},
		{
			name: "Invalid Auth 2",
			cfg: hostCfg{
				IPAddrMode:       IPDynamic,
				ProvisioningURLs: []*url.URL{urlWithIDandAuth},
				ID:               "abc",
				Auth:             "abc:1",
			},
			want: ErrInvalidAuth,
		},
		{
			name: "Invalid Auth 3",
			cfg: hostCfg{
				IPAddrMode:       IPDynamic,
				ProvisioningURLs: []*url.URL{urlWithIDandAuth},
				ID:               "abc",
				Auth:             "abc@1",
			},
			want: ErrInvalidAuth,
		},
		{
			name: "Invalid Auth 4",
			cfg: hostCfg{
				IPAddrMode:       IPDynamic,
				ProvisioningURLs: []*url.URL{urlWithIDandAuth},
				ID:               "abc",
				Auth:             strings.Repeat("a", 65),
			},
			want: ErrInvalidAuth,
		},
	}

	for _, tt := range validHostCfgTests {
		t.Run(tt.name, func(t *testing.T) {
			o := Opts{hostCfg: tt.cfg}
			err := o.validate(hcValidators...)

			assertNoError(t, err)
		})
	}

	for _, tt := range invalidHostCfgTests {
		t.Run(tt.name, func(t *testing.T) {
			o := Opts{hostCfg: tt.cfg}
			err := o.validate(hcValidators...)

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
