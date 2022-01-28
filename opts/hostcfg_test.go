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
	"time"

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
			name:    "null",
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
	url1, _ := url.Parse("http://foo.com/bar")
	url2, _ := url.Parse("https://foo.com/bar")
	cidr, _ := netlink.ParseAddr("127.0.0.1/24")
	ip := net.ParseIP("127.0.0.1")
	mac, _ := net.ParseMAC("00:00:5e:00:53:01")
	id := "someID"
	auth := "1234"
	time := time.Unix(1639307532, 0)

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
				"timestamp":null
				}`,
		},
		{
			name: "Fields with proper json.Marshaler implementation",
			h: HostCfg{
				IPAddrMode: IPDynamic,
				ID:         &id,
				Auth:       &auth,
			},
			want: `{
				"network_mode":"dhcp",
				"host_ip":null,
				"gateway":null,
				"dns":null,
				"network_interface":null,
				"provisioning_urls":null,
				"identity":"someID",
				"authentication":"1234",
				"timestamp":null
				}`,
		},
		{
			name: "Fields without json.Marshaler implementation",
			h: HostCfg{
				HostIP:           cidr,
				DefaultGateway:   &ip,
				DNSServer:        &ip,
				NetworkInterface: &mac,
				ProvisioningURLs: &[]*url.URL{url1, url2},
				Timestamp:        &time,
			},
			want: `{
				"network_mode":null,
				"host_ip":"127.0.0.1/24",
				"gateway":"127.0.0.1",
				"dns":"127.0.0.1",
				"network_interface":"00:00:5e:00:53:01",
				"provisioning_urls":["http://foo.com/bar", "https://foo.com/bar"],
				"identity":null,
				"authentication":null,
				"timestamp":1639307532
				}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.h.MarshalJSON()
			want := strings.Join(strings.Fields(tt.want), "") //remove white space
			assert(t, err, nil, string(got), want)
		})
	}
}

func TestHostCfgUnmarshalJSON(t *testing.T) {
	cidrGood, err := netlink.ParseAddr("127.0.0.1/24")
	if err != nil {
		t.Fatal(err)
	}
	ipGood := net.ParseIP("127.0.0.1")
	macGood, err := net.ParseMAC("00:00:5e:00:53:01")
	if err != nil {
		t.Fatal(err)
	}
	urlGood, err := url.Parse("http://server.com")
	if err != nil {
		t.Fatalf("internal test error: %v", err)
	}
	timeGood := time.Unix(1, 0)
	idGood := "hostname"
	authGood := "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"

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
			want:    HostCfg{ProvisioningURLs: &[]*url.URL{urlGood, urlGood}},
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
			want:    HostCfg{ID: &idGood},
			errType: nil,
		},
		{
			json:    "testdata/unmarshal/host_identity_bad_type.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/unmarshal/host_auth_good.json",
			want:    HostCfg{Auth: &authGood},
			errType: nil,
		},
		{
			json:    "testdata/unmarshal/host_auth_bad_type.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/unmarshal/host_timestamp_good.json",
			want:    HostCfg{Timestamp: &timeGood},
			errType: nil,
		},
		{
			json:    "testdata/unmarshal/host_timestamp_bad_type.json",
			want:    HostCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/unmarshal/host_good_unset.json",
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

			var got HostCfg
			err = got.UnmarshalJSON(b)

			assert(t, err, tt.errType, got, tt.want)
		})
	}
}

func TestNetlinkAddrModeMarshal(t *testing.T) {
	ipv4, err := netlink.ParseAddr("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	ipv6, err := netlink.ParseAddr("2001:db8::/32")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		addr netlinkAddr
		want string
	}{
		{
			name: "Valid IPv4 CIDR",
			addr: netlinkAddr(*ipv4),
			want: `"192.0.2.0/24"`,
		},
		{
			name: "Valid IPv6 CIDR ",
			addr: netlinkAddr(*ipv6),
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
	ipv4, err := netlink.ParseAddr("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	ipv6, err := netlink.ParseAddr("2001:db8::/32")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		json    string
		want    netlinkAddr
		errType error
	}{
		{
			name:    "null",
			json:    `null`,
			want:    netlinkAddr{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			name:    "IPv4",
			json:    `"192.0.2.0/24"`,
			want:    netlinkAddr(*ipv4),
			errType: nil,
		},
		{
			name:    "IPv6",
			json:    `"2001:db8::/32"`,
			want:    netlinkAddr(*ipv6),
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
	ipv4 := net.ParseIP("192.0.2.0")
	ipv6 := net.ParseIP("2001:db8::")
	if ipv4 == nil || ipv6 == nil {
		t.Fatal("invalid test data")
	}

	tests := []struct {
		name string
		ip   netIP
		want string
	}{
		{
			name: "IPv4",
			ip:   netIP(ipv4),
			want: `"192.0.2.0"`,
		},
		{
			name: "IPv6",
			ip:   netIP(ipv6),
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
	ipv4 := net.ParseIP("192.0.2.0")
	ipv6 := net.ParseIP("2001:db8::")
	if ipv4 == nil || ipv6 == nil {
		t.Fatal("invalid test data")
	}

	tests := []struct {
		name    string
		json    string
		want    netIP
		errType error
	}{
		{
			name:    "null",
			json:    `null`,
			want:    nil,
			errType: nil,
		},
		{
			name:    "IPv4",
			json:    `"192.0.2.0"`,
			want:    netIP(ipv4),
			errType: nil,
		},
		{
			name:    "IPv6",
			json:    `"2001:db8::"`,
			want:    netIP(ipv6),
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
	good, err := net.ParseMAC("00:00:5e:00:53:01")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		addr netHardwareAddr
		want string
	}{
		{
			name: "Valid",
			addr: netHardwareAddr(good),
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
	good1, err := net.ParseMAC("00:00:5e:00:53:01")
	if err != nil {
		t.Fatal(err)
	}
	good2, err := net.ParseMAC("00-00-5e-00-53-01")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		json    string
		want    netHardwareAddr
		errType error
	}{
		{
			name:    "null",
			json:    `null`,
			want:    nil,
			errType: nil,
		},
		{
			name:    "Valid colon",
			json:    `"00:00:5e:00:53:01"`,
			want:    netHardwareAddr(good1),
			errType: nil,
		},
		{
			name:    "Valid dash",
			json:    `"00-00-5e-00-53-01"`,
			want:    netHardwareAddr(good2),
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
	good1, err := url.Parse("http://server.com")
	if err != nil {
		t.Fatal(err)
	}
	good2, err := url.Parse("http://server.com/$ID/foo")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		u    urlURL
		want string
	}{
		{
			name: "Valid",
			u:    urlURL(*good1),
			want: `"http://server.com"`,
		},
		{
			name: "Valid with variable",
			u:    urlURL(*good2),
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
	good1, err := url.Parse("http://server.com")
	if err != nil {
		t.Fatal(err)
	}
	good2, err := url.Parse("http://server.com/$ID/foo")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		json    string
		want    urlURL
		errType error
	}{
		{
			name:    "null",
			json:    `null`,
			want:    urlURL{},
			errType: nil,
		},
		{
			name:    "Valid",
			json:    `"http://server.com"`,
			want:    urlURL(*good1),
			errType: nil,
		},
		{
			name:    "Valid with variable",
			json:    `"http://server.com/$ID/foo"`,
			want:    urlURL(*good2),
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
	good := time.Unix(1, 0)

	tests := []struct {
		name string
		t    timeTime
		want string
	}{
		{
			name: "Valid",
			t:    timeTime(good),
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
			name:    "null",
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
	goodJSON, err := os.ReadFile("testdata/unmarshal/host_good_unset.json")
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
			assert(t, err, tt.errType, nil, nil)
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
	goodJSON := "testdata/unmarshal/host_good_unset.json"
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
			assert(t, err, tt.errType, nil, nil)
		})
	}
}
