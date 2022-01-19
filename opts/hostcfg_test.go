package opts

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/url"
	"os"
	"reflect"
	"strings"
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

func TestHostCfgMarshalJSON(t *testing.T) {
	url1, _ := url.Parse("http://foo.com/bar")
	url2, _ := url.Parse("https://foo.com/bar")
	cidr, _ := netlink.ParseAddr("127.0.0.1/24")
	ip := net.ParseIP("127.0.0.1")
	mac, _ := net.ParseMAC("00:00:5e:00:53:01")

	tests := []struct {
		name string
		h    HostCfg
		want string
	}{
		{
			name: "Unset HostCfg",
			h:    HostCfg{},
			want: `{
				"network_mode":"",
				"host_ip":"",
				"gateway":"",
				"dns":"",
				"network_interface":"",
				"provisioning_urls":null,
				"identity":"",
				"authentication":""
				}`,
		},
		{
			name: "Fields with proper json.Marshaler implementation",
			h: HostCfg{
				IPAddrMode: IPDynamic,
				ID:         "someID",
				Auth:       "1234",
			},
			want: `{
				"network_mode":"dhcp",
				"host_ip":"",
				"gateway":"",
				"dns":"",
				"network_interface":"",
				"provisioning_urls":null,
				"identity":"someID",
				"authentication":"1234"
				}`,
		},
		{
			name: "Fields without json.Marshaler implementation",
			h: HostCfg{
				HostIP:           cidr,
				DefaultGateway:   &ip,
				DNSServer:        &ip,
				NetworkInterface: &mac,
				ProvisioningURLs: []*url.URL{url1, url2},
			},
			want: `{
				"network_mode":"",
				"host_ip":"127.0.0.1/24",
				"gateway":"127.0.0.1",
				"dns":"127.0.0.1",
				"network_interface":"00:00:5e:00:53:01",
				"provisioning_urls":["http://foo.com/bar", "https://foo.com/bar"],
				"identity":"",
				"authentication":""
				}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.MarshalJSON()

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			//remove all white space
			want := strings.Join(strings.Fields(tt.want), "")
			if string(got) != want {
				t.Errorf("got %s, want %s", got, want)
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
			json:    "testdata/unmarshal/host_version.json",
			want:    HostCfg{},
			errType: nil,
		},
		{
			json:    "testdata/unmarshal/host_network_mode_good_1.json",
			want:    HostCfg{IPAddrMode: IPStatic},
			errType: nil,
		},
		{
			json:    "testdata/unmarshal/host_network_mode_good_2.json",
			want:    HostCfg{IPAddrMode: IPDynamic},
			errType: nil,
		},
		{
			json:    "testdata/unmarshal/host_network_mode_bad_type.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/unmarshal/host_network_mode_bad_value.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/unmarshal/host_ip_good.json",
			want:    HostCfg{HostIP: cidrGood},
			errType: nil,
		},
		{
			json:    "testdata/unmarshal/host_ip_bad_type.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/unmarshal/host_ip_bad_value.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/unmarshal/host_gateway_good.json",
			want:    HostCfg{DefaultGateway: &ipGood},
			errType: nil,
		},
		{
			json:    "testdata/unmarshal/host_gateway_bad_type.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/unmarshal/host_gateway_bad_value.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/unmarshal/host_dns_good.json",
			want:    HostCfg{DNSServer: &ipGood},
			errType: nil,
		},
		{
			json:    "testdata/unmarshal/host_dns_bad_type.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/unmarshal/host_dns_bad_value.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/unmarshal/host_interface_good.json",
			want:    HostCfg{NetworkInterface: &macGood},
			errType: nil,
		},
		{
			json:    "testdata/unmarshal/host_interface_bad_type.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/unmarshal/host_interface_bad_value.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/unmarshal/host_urls_good.json",
			want:    HostCfg{ProvisioningURLs: []*url.URL{urlGood, urlGood}},
			errType: nil,
		},
		{
			json:    "testdata/unmarshal/host_urls_bad_type.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/unmarshal/host_urls_bad_value_1.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/unmarshal/host_urls_bad_value_2.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/unmarshal/host_identity_good.json",
			want:    HostCfg{ID: "hostname"},
			errType: nil,
		},
		{
			json:    "testdata/unmarshal/host_identity_bad_type.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/unmarshal/host_auth_good.json",
			want:    HostCfg{Auth: "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"},
			errType: nil,
		},
		{
			json:    "testdata/unmarshal/host_auth_bad_type.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/unmarshal/host_good_unset.json",
			want:    HostCfg{},
			errType: nil,
		},
		{
			json:    "testdata/unmarshal/host_good_empty.json",
			want:    HostCfg{},
			errType: nil,
		},
		{
			json:    "testdata/unmarshal/host_good_additional_key.json",
			want:    HostCfg{},
			errType: nil,
		},
		{
			json:    "testdata/unmarshal/host_missing_1_bad.json",
			want:    HostCfg{},
			errType: errors.New(""),
		},
		{
			json:    "testdata/unmarshal/host_missing_2_bad.json",
			want:    HostCfg{},
			errType: errors.New(""),
		},
		{
			json:    "testdata/unmarshal/host_missing_3_bad.json",
			want:    HostCfg{},
			errType: errors.New(""),
		},
		{
			json:    "testdata/unmarshal/host_missing_4_bad.json",
			want:    HostCfg{},
			errType: errors.New(""),
		},
		{
			json:    "testdata/unmarshal/host_missing_5_bad.json",
			want:    HostCfg{},
			errType: errors.New(""),
		},
		{
			json:    "testdata/unmarshal/host_missing_6_bad.json",
			want:    HostCfg{},
			errType: errors.New(""),
		},
		{
			json:    "testdata/unmarshal/host_missing_7_bad.json",
			want:    HostCfg{},
			errType: errors.New(""),
		},
		{
			json:    "testdata/unmarshal/host_missing_8_bad.json",
			want:    HostCfg{},
			errType: errors.New(""),
		},
		{
			json:    "testdata/unmarshal/bad_json.json",
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

func TestHotCfgJSONLoadNew(t *testing.T) {
	got := NewHostCfgJSON(&bytes.Buffer{})
	if got == nil {
		t.Fatal("expect non-nil return")
	}
	if got.src == nil {
		t.Error("expect src to be initialized")
	}
	if got.valitatorSet == nil {
		t.Error("expect valitatorSet to be initialized")
	}
}

func TestHostCfgJSONLoad(t *testing.T) {
	goodJSON, err := os.ReadFile("testdata/unmarshal/host_good_empty.json")
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
				src: bytes.NewBuffer(goodJSON),
				valitatorSet: []validator{func(*Opts) error {
					return nil
				}},
			},
			errType: nil,
		},
		{
			name:    "No source",
			loader:  HostCfgJSON{},
			errType: errors.New(""),
		},
		{
			name: "Bad source",
			loader: HostCfgJSON{
				src: bytes.NewBufferString("bad"),
			},
			errType: &json.SyntaxError{},
		},
		{
			name: "Bad content",
			loader: HostCfgJSON{
				src: bytes.NewBuffer(goodJSON),
				valitatorSet: []validator{func(*Opts) error {
					return InvalidError("dummy validation error")
				}},
			},
			errType: InvalidError(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.loader.Load(&Opts{})

			if tt.errType != nil {
				if err == nil {
					t.Fatal("expect an error")
				}
				goterr, wanterr := reflect.TypeOf(err), reflect.TypeOf(tt.errType)
				if goterr != wanterr {
					t.Errorf("got %+v, want %+v", goterr, wanterr)
				}
			}
		})
	}
}

func TestHostCfgFileNew(t *testing.T) {
	got := NewHostCfgFile("some/name")
	if got == nil {
		t.Fatal("expect non-nil return")
	}
	if reflect.DeepEqual(got.hostCfgJSON, SecurityJSON{}) {
		t.Error("expect hostCfgJSON to be initialized")
	}
}

func TestHostCfgFileLoad(t *testing.T) {
	goodJSON := "testdata/unmarshal/host_good_empty.json"
	badJSON := "testdata/unmarshal/host_missing_1_bad.json"

	tests := []struct {
		name    string
		loader  HostCfgFile
		errType error
	}{
		{
			name: "Successful loading",
			loader: HostCfgFile{
				name: goodJSON,
				hostCfgJSON: HostCfgJSON{
					valitatorSet: []validator{func(*Opts) error {
						return nil
					}},
				},
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
				name: "not/exist",
			},
			errType: &fs.PathError{},
		},
		{
			name: "Bad content",
			loader: HostCfgFile{
				name: badJSON,
			},
			errType: errors.New(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.loader.Load(&Opts{})

			if tt.errType != nil {
				if err == nil {
					t.Fatal("expect an error")
				}
				goterr, wanterr := reflect.TypeOf(err), reflect.TypeOf(tt.errType)
				if goterr != wanterr {
					t.Errorf("got %+v, want %+v", goterr, wanterr)
				}
			} else {
				if err != nil {
					t.Error("unexpected error")
				}
			}
		})
	}
}
