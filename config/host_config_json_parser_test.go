package config

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"testing"

	"github.com/vishvananda/netlink"
)

const (
	goodIPString   = "172.0.0.1"
	goodCIDRString = "127.0.0.1/24"
	goodMACString  = "00:00:5e:00:53:01"
	goodURLString  = "http://server.com"
)

func TestHostCfgJSONParser(t *testing.T) {
	v := valuesFromGoodStrings(t)

	goodTests := []struct {
		name string
		json string
		want *HostCfg
	}{
		{
			name: "Version field",
			json: fmt.Sprintf(`{"%s": 1}`, HostCfgVersionJSONKey),
			want: &HostCfg{Version: 1},
		},
		{
			name: "Network mode field 1",
			json: fmt.Sprintf(`{"%s": "%s"}`, NetworkModeJSONKey, StaticIP.String()),
			want: &HostCfg{IPAddrMode: StaticIP},
		},
		{
			name: "Network mode field 2",
			json: fmt.Sprintf(`{"%s": "%s"}`, NetworkModeJSONKey, DynamicIP.String()),
			want: &HostCfg{IPAddrMode: DynamicIP},
		},
		{
			name: "Host IP field",
			json: fmt.Sprintf(`{"%s": "%s"}`, HostIPJSONKey, goodCIDRString),
			want: &HostCfg{HostIP: v.cidr},
		},
		{
			name: "Gateway field",
			json: fmt.Sprintf(`{"%s": "%s"}`, DefaultGatewayJSONKey, goodIPString),
			want: &HostCfg{DefaultGateway: v.ip},
		},
		{
			name: "DNS Server field",
			json: fmt.Sprintf(`{"%s": "%s"}`, DNSServerJSONKey, goodIPString),
			want: &HostCfg{DNSServer: v.ip},
		},
		{
			name: "Network interface field",
			json: fmt.Sprintf(`{"%s": "%s"}`, NetworkInterfaceJSONKey, goodMACString),
			want: &HostCfg{NetworkInterface: v.mac},
		},
		{
			name: "Provisioning URLs field 1",
			json: fmt.Sprintf(`{"%s": ["%s"]}`, ProvisioningURLsJSONKey, goodURLString),
			want: &HostCfg{ProvisioningURLs: []*url.URL{v.provURL}},
		},
		{
			name: "Provisioning URLs field 2",
			json: fmt.Sprintf(`{"%s": ["%s", "%s"]}`, ProvisioningURLsJSONKey, goodURLString, goodURLString),
			want: &HostCfg{ProvisioningURLs: []*url.URL{v.provURL, v.provURL}},
		},
		{
			name: "Identity field",
			json: fmt.Sprintf(`{"%s": "some id"}`, IdJSONKey),
			want: &HostCfg{ID: "some id"},
		},
		{
			name: "Authentication field",
			json: fmt.Sprintf(`{"%s": "some auth"}`, AuthJSONKey),
			want: &HostCfg{Auth: "some auth"},
		},
		{
			name: "No fields",
			json: `{}`,
			want: &HostCfg{},
		},
		{
			name: "Empty fields",
			json: fmt.Sprintf(`{"%s": 0, "%s": "", "%s": "", "%s": "", "%s": "", "%s": "", "%s": [], "%s": "", "%s": ""}`, HostCfgVersionJSONKey, NetworkModeJSONKey, HostIPJSONKey, DefaultGatewayJSONKey, DNSServerJSONKey, NetworkInterfaceJSONKey, ProvisioningURLsJSONKey, IdJSONKey, AuthJSONKey),
			want: &HostCfg{},
		},
	}

	badValueTests := []struct {
		name string
		json string
		key  string
	}{
		{
			name: "Bad network mode string",
			json: fmt.Sprintf(`{"%s": "some string"}`, NetworkModeJSONKey),
			key:  NetworkModeJSONKey,
		},
		{
			name: "Bad host IP address string",
			json: fmt.Sprintf(`{"%s": "some string"}`, HostIPJSONKey),
			key:  HostIPJSONKey,
		},
		{
			name: "Bad gateway IP address string",
			json: fmt.Sprintf(`{"%s": "some string"}`, DefaultGatewayJSONKey),
			key:  DefaultGatewayJSONKey,
		},
		{
			name: "Bad DNS server IP address string",
			json: fmt.Sprintf(`{"%s": "some string"}`, DNSServerJSONKey),
			key:  DNSServerJSONKey,
		},
		{
			name: "Bad network interface address string",
			json: fmt.Sprintf(`{"%s": "some string"}`, NetworkInterfaceJSONKey),
			key:  NetworkInterfaceJSONKey,
		},
		{
			name: "Bad provisioning url string",
			json: fmt.Sprintf(`{"%s": ["missing.scheme/in/url"]}`, ProvisioningURLsJSONKey),
			key:  ProvisioningURLsJSONKey,
		},
	}

	badTypeTests := []struct {
		name string
		json string
	}{
		{
			name: "Bad version type",
			json: fmt.Sprintf(`{"%s": "one"}`, HostCfgVersionJSONKey),
		},
		{
			name: "Bad network mode type",
			json: fmt.Sprintf(`{"%s": 1}`, NetworkModeJSONKey),
		},
		{
			name: "Bad host IP type",
			json: fmt.Sprintf(`{"%s": 1}`, HostIPJSONKey),
		},
		{
			name: "Bad default gateway type",
			json: fmt.Sprintf(`{"%s": 1}`, DefaultGatewayJSONKey),
		},
		{
			name: "Bad DNS type",
			json: fmt.Sprintf(`{"%s": 1}`, DNSServerJSONKey),
		},
		{
			name: "Bad network interface type",
			json: fmt.Sprintf(`{"%s": 1}`, NetworkInterfaceJSONKey),
		},
		{
			name: "Bad provisioning url type",
			json: fmt.Sprintf(`{"%s": 1}`, ProvisioningURLsJSONKey),
		},
		{
			name: "Bad provisioning url type 2",
			json: fmt.Sprintf(`{"%s": [1, 1]}`, ProvisioningURLsJSONKey),
		},
		{
			name: "Bad id type",
			json: fmt.Sprintf(`{"%s": 1}`, IdJSONKey),
		},
		{
			name: "Bad auth type",
			json: fmt.Sprintf(`{"%s": 1}`, AuthJSONKey),
		},
	}

	for _, tt := range goodTests {
		t.Run(tt.name, func(t *testing.T) {
			j := HostCfgJSONParser{bytes.NewBufferString(tt.json)}

			got, err := j.Parse()

			assertNoError(t, err)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}

	for _, tt := range badTypeTests {
		t.Run(tt.name, func(t *testing.T) {
			j := HostCfgJSONParser{bytes.NewBufferString(tt.json)}

			_, err := j.Parse()

			assertTypeError(t, err)
		})
	}

	for _, tt := range badValueTests {
		t.Run(tt.name, func(t *testing.T) {
			j := HostCfgJSONParser{bytes.NewBufferString(tt.json)}

			_, err := j.Parse()

			assertParseError(t, err, tt.key)
		})
	}
}

type badReader struct{}

func (r *badReader) Read(b []byte) (n int, err error) {
	return 0, errors.New("bad read")
}

func TestBadHostCfgJSONParser(t *testing.T) {

	t.Run("Invalid JSON", func(t *testing.T) {
		j := HostCfgJSONParser{bytes.NewBufferString("bad json")}

		_, err := j.Parse()

		if err == nil {
			t.Error("expect error but got none")
		}
	})

	t.Run("Bad reader", func(t *testing.T) {
		j := HostCfgJSONParser{&badReader{}}

		_, err := j.Parse()

		if err == nil {
			t.Error("expect error but got none")
		}
	})
}

func assertTypeError(t *testing.T, err error) {
	t.Helper()
	if _, ok := err.(*TypeError); !ok {
		t.Errorf("want TypeError, got %T", err)
	}
}

func assertParseError(t *testing.T, err error, key string) {
	t.Helper()
	e, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("want ParseError, got %T", err)
	}
	if e.Key != key {
		t.Errorf("want ParseError for JSON key %q, but got: %v", key, err)
	}
}

type values struct {
	ip      *net.IP
	cidr    *netlink.Addr
	mac     *net.HardwareAddr
	provURL *url.URL
}

func valuesFromGoodStrings(t *testing.T) *values {
	t.Helper()

	i := net.ParseIP(goodIPString)
	if i == nil {
		t.Fatal("internal test error: invalid net.IP")
	}

	c, err := netlink.ParseAddr(goodCIDRString)
	if err != nil {
		t.Fatalf("internal test error: %v", err)
	}

	m, err := net.ParseMAC(goodMACString)
	if err != nil {
		t.Fatalf("internal test error: %v", err)
	}

	p, err := url.Parse(goodURLString)
	if err != nil {
		t.Fatalf("internal test error: %v", err)
	}

	v := &values{
		ip:      &i,
		cidr:    c,
		mac:     &m,
		provURL: p,
	}
	return v
}
