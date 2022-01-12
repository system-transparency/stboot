package opts

import (
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestSecurityCfgValidation(t *testing.T) {
	validOptsTests := []struct {
		name string
		opts *Opts
	}{
		{
			name: "Minimum valid config with implicit defaults",
			opts: &Opts{
				Security: Security{
					BootMode: LocalBoot,
				},
			},
		},
		{
			name: "Minimum valid config with explicit values",
			opts: &Opts{
				Security: Security{
					ValidSignatureThreshold: 1,
					BootMode:                NetworkBoot,
					UsePkgCache:             true,
				},
			},
		},
	}

	invalidOptsTests := []struct {
		name string
		opts *Opts
		want error
	}{
		{
			name: "Empty boot mode",
			opts: &Opts{},
			want: ErrMissingBootMode,
		},
		{
			name: "Unknown boot mode",
			opts: &Opts{
				Security: Security{
					BootMode: 3,
				},
			},
			want: ErrUnknownBootMode,
		},
	}

	for _, tt := range validOptsTests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate(t, tt.opts, sValids...)

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}

	for _, tt := range invalidOptsTests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate(t, tt.opts, sValids...)

			if err == nil {
				t.Fatal("expect an error")
			}
			if err != tt.want {
				t.Errorf("got %q, want %q", err, tt.want)
			}

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

	validOptsTests := []struct {
		name string
		opts *Opts
	}{
		{
			name: "Minimum valid config with dynamic IP address",
			opts: &Opts{
				HostCfg: HostCfg{
					IPAddrMode:       IPDynamic,
					ProvisioningURLs: []*url.URL{validURL1},
				},
			},
		},
		{
			name: "Minimum valid config with static IP address",
			opts: &Opts{
				HostCfg: HostCfg{
					IPAddrMode:       IPStatic,
					HostIP:           ip,
					DefaultGateway:   &gw,
					ProvisioningURLs: []*url.URL{validURL1},
				},
			},
		},
	}

	invalidOptsTests := []struct {
		name string
		opts *Opts
		want error
	}{
		{
			name: "Missing IP address mode",
			opts: &Opts{
				HostCfg: HostCfg{
					ProvisioningURLs: []*url.URL{validURL1},
				},
			},
			want: ErrMissingIPAddrMode,
		},
		{
			name: "Unknown IP address mode",
			opts: &Opts{
				HostCfg: HostCfg{
					IPAddrMode:       3,
					ProvisioningURLs: []*url.URL{validURL1},
				},
			},
			want: ErrUnknownIPAddrMode,
		},
		{
			name: "Missing IP address",
			opts: &Opts{
				HostCfg: HostCfg{
					IPAddrMode:       IPStatic,
					ProvisioningURLs: []*url.URL{validURL1},
					DefaultGateway:   &gw,
				},
			},
			want: ErrMissingIPAddr,
		},
		{
			name: "Missing gateway",
			opts: &Opts{
				HostCfg: HostCfg{
					IPAddrMode:       IPStatic,
					ProvisioningURLs: []*url.URL{validURL1},
					HostIP:           ip,
				},
			},
			want: ErrMissingGateway,
		},
		{
			name: "Missing URLs",
			opts: &Opts{
				HostCfg: HostCfg{
					IPAddrMode: IPDynamic,
				},
			},
			want: ErrMissingProvURLs,
		},
		{
			name: "Invalid URLs 1",
			opts: &Opts{
				HostCfg: HostCfg{
					IPAddrMode:       IPDynamic,
					ProvisioningURLs: []*url.URL{validURL1, invalidURL1},
				},
			},
			want: ErrInvalidProvURLs,
		},
		{
			name: "Invalid URLs 2",
			opts: &Opts{
				HostCfg: HostCfg{
					IPAddrMode:       IPDynamic,
					ProvisioningURLs: []*url.URL{validURL2, invalidURL2},
				},
			},
			want: ErrInvalidProvURLs,
		},
		{
			name: "Missing ID",
			opts: &Opts{
				HostCfg: HostCfg{
					IPAddrMode:       IPDynamic,
					ProvisioningURLs: []*url.URL{urlWithID},
				},
			},
			want: ErrMissingID,
		},
		{
			name: "Invalid ID 1",
			opts: &Opts{
				HostCfg: HostCfg{
					IPAddrMode:       IPDynamic,
					ProvisioningURLs: []*url.URL{urlWithID},
					ID:               "abc/1",
				},
			},
			want: ErrInvalidID,
		},
		{
			name: "Invalid ID 2",
			opts: &Opts{
				HostCfg: HostCfg{
					IPAddrMode:       IPDynamic,
					ProvisioningURLs: []*url.URL{urlWithID},
					ID:               "abc:1",
				},
			},
			want: ErrInvalidID,
		},
		{
			name: "Invalid ID 3",
			opts: &Opts{
				HostCfg: HostCfg{
					IPAddrMode:       IPDynamic,
					ProvisioningURLs: []*url.URL{urlWithID},
					ID:               "abc@1",
				},
			},
			want: ErrInvalidID,
		},
		{
			name: "Invalid ID 4",
			opts: &Opts{
				HostCfg: HostCfg{
					IPAddrMode:       IPDynamic,
					ProvisioningURLs: []*url.URL{urlWithID},
					ID:               strings.Repeat("a", 65),
				},
			},
			want: ErrInvalidID,
		},
		{
			name: "Missing Auth",
			opts: &Opts{
				HostCfg: HostCfg{
					IPAddrMode:       IPDynamic,
					ProvisioningURLs: []*url.URL{urlWithIDandAuth},
					ID:               "abc",
				},
			},
			want: ErrMissingAuth,
		},
		{
			name: "Invalid Auth 1",
			opts: &Opts{
				HostCfg: HostCfg{
					IPAddrMode:       IPDynamic,
					ProvisioningURLs: []*url.URL{urlWithIDandAuth},
					ID:               "abc",
					Auth:             "abc/1",
				},
			},
			want: ErrInvalidAuth,
		},
		{
			name: "Invalid Auth 2",
			opts: &Opts{
				HostCfg: HostCfg{
					IPAddrMode:       IPDynamic,
					ProvisioningURLs: []*url.URL{urlWithIDandAuth},
					ID:               "abc",
					Auth:             "abc:1",
				},
			},
			want: ErrInvalidAuth,
		},
		{
			name: "Invalid Auth 3",
			opts: &Opts{
				HostCfg: HostCfg{
					IPAddrMode:       IPDynamic,
					ProvisioningURLs: []*url.URL{urlWithIDandAuth},
					ID:               "abc",
					Auth:             "abc@1",
				},
			},
			want: ErrInvalidAuth,
		},
		{
			name: "Invalid Auth 4",
			opts: &Opts{
				HostCfg: HostCfg{
					IPAddrMode:       IPDynamic,
					ProvisioningURLs: []*url.URL{urlWithIDandAuth},
					ID:               "abc",
					Auth:             strings.Repeat("a", 65),
				},
			},
			want: ErrInvalidAuth,
		},
	}

	for _, tt := range validOptsTests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate(t, tt.opts, hValids...)

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}

	for _, tt := range invalidOptsTests {
		t.Run(tt.name, func(t *testing.T) {
			err := validate(t, tt.opts, hValids...)

			if err == nil {
				t.Fatal("expect an error")
			}
			if err != tt.want {
				t.Errorf("got %q, want %q", err, tt.want)
			}

		})
	}
}

func validate(t *testing.T, o *Opts, v ...validator) error {
	t.Helper()
	for _, f := range v {
		if err := f(o); err != nil {
			return err
		}
	}
	return nil
}
