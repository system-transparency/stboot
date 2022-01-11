package opts

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"reflect"
	"testing"

	"github.com/vishvananda/netlink"
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
			want: "",
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
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
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
			name: "Marshal empty value",
			mode: IPUnset,
			want: `""`,
		},
		{
			name: "Marshal 'IPStatic'",
			mode: IPStatic,
			want: `"static"`,
		},
		{
			name: "Marshal 'IPDynamic'",
			mode: IPDynamic,
			want: `"dhcp"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.mode.MarshalJSON()

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

const (
	goodIPString   = "127.0.0.1"
	goodCIDRString = "127.0.0.1/24"
	goodMACString  = "00:00:5e:00:53:01"
	goodURLString  = "http://server.com"
)

func TestHostCfgUnmarshalJSON(t *testing.T) {
	cidrGood, err := netlink.ParseAddr(goodCIDRString)
	if err != nil {
		t.Fatal(err)
	}
	ipGood := net.ParseIP(goodIPString)
	macGood, err := net.ParseMAC(goodMACString)
	if err != nil {
		t.Fatal(err)
	}
	urlGood, err := url.Parse(goodURLString)
	if err != nil {
		t.Fatalf("internal test error: %v", err)
	}

	tests := []struct {
		json    string
		want    HostCfg
		errType error
	}{
		// version field is not used but accepted ATM.
		{
			json:    "testdata/host_version.json",
			want:    HostCfg{},
			errType: nil,
		},
		{
			json:    "testdata/host_network_mode_good_1.json",
			want:    HostCfg{IPAddrMode: IPStatic},
			errType: nil,
		},
		{
			json:    "testdata/host_network_mode_good_2.json",
			want:    HostCfg{IPAddrMode: IPDynamic},
			errType: nil,
		},
		{
			json:    "testdata/host_network_mode_bad_type.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/host_network_mode_bad_value.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/host_ip_good.json",
			want:    HostCfg{HostIP: cidrGood},
			errType: nil,
		},
		{
			json:    "testdata/host_ip_bad_type.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/host_ip_bad_value.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/host_gateway_good.json",
			want:    HostCfg{DefaultGateway: &ipGood},
			errType: nil,
		},
		{
			json:    "testdata/host_gateway_bad_type.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/host_gateway_bad_value.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/host_dns_good.json",
			want:    HostCfg{DNSServer: &ipGood},
			errType: nil,
		},
		{
			json:    "testdata/host_dns_bad_type.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/host_dns_bad_value.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/host_interface_good.json",
			want:    HostCfg{NetworkInterface: &macGood},
			errType: nil,
		},
		{
			json:    "testdata/host_interface_bad_type.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/host_interface_bad_value.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/host_urls_good.json",
			want:    HostCfg{ProvisioningURLs: []*url.URL{urlGood, urlGood}},
			errType: nil,
		},
		{
			json:    "testdata/host_urls_bad_type.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/host_urls_bad_value_1.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/host_urls_bad_value_2.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/host_identity_good.json",
			want:    HostCfg{ID: "hostname"},
			errType: nil,
		},
		{
			json:    "testdata/host_identity_bad_type.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/host_auth_good.json",
			want:    HostCfg{Auth: "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"},
			errType: nil,
		},
		{
			json:    "testdata/host_auth_bad_type.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/host_good_unset.json",
			want:    HostCfg{},
			errType: nil,
		},
		{
			json:    "testdata/host_good_empty.json",
			want:    HostCfg{},
			errType: nil,
		},
		{
			json:    "testdata/host_good_additional_key.json",
			want:    HostCfg{},
			errType: nil,
		},
		{
			json:    "testdata/host_missing_1.json",
			want:    HostCfg{},
			errType: errors.New(""),
		},
		{
			json:    "testdata/host_missing_2.json",
			want:    HostCfg{},
			errType: errors.New(""),
		},
		{
			json:    "testdata/host_missing_3.json",
			want:    HostCfg{},
			errType: errors.New(""),
		},
		{
			json:    "testdata/host_missing_4.json",
			want:    HostCfg{},
			errType: errors.New(""),
		},
		{
			json:    "testdata/host_missing_5.json",
			want:    HostCfg{},
			errType: errors.New(""),
		},
		{
			json:    "testdata/host_missing_6.json",
			want:    HostCfg{},
			errType: errors.New(""),
		},
		{
			json:    "testdata/host_missing_7.json",
			want:    HostCfg{},
			errType: errors.New(""),
		},
		{
			json:    "testdata/host_missing_8.json",
			want:    HostCfg{},
			errType: errors.New(""),
		},
		{
			json:    "testdata/bad_json.json",
			want:    HostCfg{},
			errType: &json.SyntaxError{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.json, func(t *testing.T) {
			b, err := os.ReadFile(tt.json)
			if err != nil {
				t.Fatal(err)
			}

			hc := &HostCfg{}
			err = hc.UnmarshalJSON(b)

			//check error
			if tt.errType != nil {
				if err == nil {
					t.Fatal("expect an error")
				}
				t.Log(err)
				goterr, wanterr := reflect.TypeOf(err), reflect.TypeOf(tt.errType)
				if goterr != wanterr {
					t.Errorf("got %+v, want %+v", goterr, wanterr)
				}
			}

			// check return value
			got := *hc
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestBadHostCfgJSONParser(t *testing.T) {
	t.Run("Good JSON", func(t *testing.T) {
		b, err := os.ReadFile("testdata/host_good_empty.json")
		if err != nil {
			t.Fatal(err)
		}
		j := HostCfgJSONParser{bytes.NewBuffer(b)}

		opts, err := j.Parse()
		if err != nil {
			t.Fatalf("uexpected error")
		}

		want := Opts{}
		got := *opts
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}

	})

	t.Run("Invalid JSON", func(t *testing.T) {
		j := HostCfgJSONParser{bytes.NewBufferString("bad json")}

		_, err := j.Parse()

		if err == nil {
			t.Error("expect an error")
		}
	})

	t.Run("Bad reader", func(t *testing.T) {
		j := HostCfgJSONParser{&badReader{}}

		_, err := j.Parse()

		if err == nil {
			t.Error("expect an error")
		}
	})
}
