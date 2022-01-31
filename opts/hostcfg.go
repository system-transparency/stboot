package opts

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"reflect"
	"time"

	"github.com/vishvananda/netlink"
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
	} else {
		return []byte("null"), nil
	}
}

// UnmarshalJSON implements json.Unmarshaler.
func (i *IPAddrMode) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*i = IPUnset
	} else {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}

		toId := map[string]IPAddrMode{
			"static": IPStatic,
			"dhcp":   IPDynamic,
		}
		mode, ok := toId[s]
		if !ok {
			return &json.UnmarshalTypeError{
				Value: fmt.Sprintf("string %q", s),
				Type:  reflect.TypeOf(i),
			}
		}
		*i = mode
	}
	return nil
}

// HostCfg groups host specific configuration.
type HostCfg struct {
	IPAddrMode       IPAddrMode        `json:"network_mode"`
	HostIP           *netlink.Addr     `json:"host_ip"`
	DefaultGateway   *net.IP           `json:"gateway"`
	DNSServer        *net.IP           `json:"dns"`
	NetworkInterface *net.HardwareAddr `json:"network_interface"`
	ProvisioningURLs *[]*url.URL       `json:"provisioning_urls"`
	ID               *string           `json:"identity"`
	Auth             *string           `json:"authentication"`
	Timestamp        *time.Time        `json:"timestamp"`
}

type hostCfg struct {
	IPAddrMode       IPAddrMode       `json:"network_mode"`
	HostIP           *netlinkAddr     `json:"host_ip"`
	DefaultGateway   *netIP           `json:"gateway"`
	DNSServer        *netIP           `json:"dns"`
	NetworkInterface *netHardwareAddr `json:"network_interface"`
	ProvisioningURLs *[]*urlURL       `json:"provisioning_urls"`
	ID               *string          `json:"identity"`
	Auth             *string          `json:"authentication"`
	Timestamp        *timeTime        `json:"timestamp"`
}

// MarshalJSON implements json.Marshaler.
func (h HostCfg) MarshalJSON() ([]byte, error) {
	alias := hostCfg{
		IPAddrMode:       h.IPAddrMode,
		HostIP:           (*netlinkAddr)(h.HostIP),
		DefaultGateway:   (*netIP)(h.DefaultGateway),
		DNSServer:        (*netIP)(h.DNSServer),
		NetworkInterface: (*netHardwareAddr)(h.NetworkInterface),
		ProvisioningURLs: urls2alias(h.ProvisioningURLs),
		ID:               h.ID,
		Auth:             h.Auth,
		Timestamp:        (*timeTime)(h.Timestamp),
	}

	return json.Marshal(alias)
}

// UnmarshalJSON implements json.Unmarshaler.
//
// All fields of HostCfg need to be present in JSON.
func (h *HostCfg) UnmarshalJSON(data []byte) error {
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(data, &jsonMap); err != nil {
		return err
	}
	tags := jsonTags(h)
	for _, tag := range tags {
		if _, ok := jsonMap[tag]; !ok {
			return fmt.Errorf("missing json key %q", tag)
		}
	}

	alias := hostCfg{}
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	h.IPAddrMode = alias.IPAddrMode
	h.HostIP = (*netlink.Addr)(alias.HostIP)
	h.DefaultGateway = (*net.IP)(alias.DefaultGateway)
	h.DNSServer = (*net.IP)(alias.DNSServer)
	h.NetworkInterface = (*net.HardwareAddr)(alias.NetworkInterface)
	h.ProvisioningURLs = alias2urls(alias.ProvisioningURLs)
	h.ID = alias.ID
	h.Auth = alias.Auth
	h.Timestamp = (*time.Time)(alias.Timestamp)

	return nil
}

func urls2alias(in *[]*url.URL) *[]*urlURL {
	if in == nil {
		return nil
	}
	ret := make([]*urlURL, len(*in))
	for i := range ret {
		if (*in)[i] != nil {
			u := *(*in)[i]
			cast := urlURL(u)
			ret[i] = &cast
		}
	}
	return &ret
}

func alias2urls(in *[]*urlURL) *[]*url.URL {
	if in == nil {
		return nil
	}
	ret := make([]*url.URL, len(*in))
	for i := range ret {
		if (*in)[i] != nil {
			u := *(*in)[i]
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
	ip, err := netlink.ParseAddr(str)
	if err != nil {
		return &json.UnmarshalTypeError{
			Value: fmt.Sprintf("string %q", str),
			Type:  reflect.TypeOf(ip),
		}
	}
	*n = netlinkAddr(*ip)

	return nil
}

type netIP net.IP

func (n netIP) MarshalJSON() ([]byte, error) {
	return json.Marshal(net.IP(n).String())
}

func (n *netIP) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*n = nil
	} else {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		ip := net.ParseIP(str)
		if ip == nil {
			return &json.UnmarshalTypeError{
				Value: fmt.Sprintf("string %q", str),
				Type:  reflect.TypeOf(ip),
			}
		}
		*n = netIP(ip)
	}

	return nil
}

type netHardwareAddr net.HardwareAddr

func (n netHardwareAddr) MarshalJSON() ([]byte, error) {
	return json.Marshal(net.HardwareAddr(n).String())
}

func (n *netHardwareAddr) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
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
	if string(data) == "null" {
		*u = urlURL{}
	} else {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		ul, err := url.ParseRequestURI(str)
		if err != nil {
			return &json.UnmarshalTypeError{
				Value: fmt.Sprintf("string %q", str),
				Type:  reflect.TypeOf(ul),
			}
		}
		*u = urlURL(*ul)
	}
	return nil
}

type timeTime time.Time

func (t timeTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(t).Unix())
}

func (t *timeTime) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*t = timeTime{}
	} else {
		var i int64
		if err := json.Unmarshal(data, &i); err != nil {
			return err
		}
		tme := time.Unix(i, 0)
		*t = timeTime(tme)
	}

	return nil
}

// HostCfgJSON initializes Opts's HostCfg from JSON.
type HostCfgJSON struct {
	src          io.Reader
	valitatorSet []validator
}

// NewHostCfgJSON returns a new HostCfgJSON with the given io.Reader.
func NewHostCfgJSON(src io.Reader) *HostCfgJSON {
	return &HostCfgJSON{src: src, valitatorSet: hValids}
}

// Load implements Loader.
func (h *HostCfgJSON) Load(o *Opts) error {
	var hc HostCfg
	if h.src == nil {
		return errors.New("no source provided")
	}
	d := json.NewDecoder(h.src)
	if err := d.Decode(&hc); err != nil {
		return err
	}
	o.HostCfg = hc
	for _, v := range h.valitatorSet {
		if err := v(o); err != nil {
			o.HostCfg = HostCfg{}
			return err
		}
	}
	return nil
}

// HostCfgFile wraps SecurityJSON.
type HostCfgFile struct {
	name        string
	hostCfgJSON HostCfgJSON
}

// NewHostCfgFile returns a new HostCfgFile with the given name.
func NewHostCfgFile(name string) *HostCfgFile {
	return &HostCfgFile{
		name: name,
		hostCfgJSON: HostCfgJSON{
			valitatorSet: hValids,
		},
	}
}

// Load implements Loader.
func (h *HostCfgFile) Load(o *Opts) error {
	f, err := os.Open(h.name)
	if err != nil {
		return err
	}
	defer f.Close()
	h.hostCfgJSON.src = f
	if err := h.hostCfgJSON.Load(o); err != nil {
		return err
	}
	return nil
}
