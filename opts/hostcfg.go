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
	return [...]string{"", "static", "dhcp"}[i]
}

// MarshalJSON implements json.Marshaler.
func (i IPAddrMode) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.String())
}

// UnmarshalJSON implements json.Unmarshaler.
func (i *IPAddrMode) UnmarshalJSON(data []byte) error {
	toId := map[string]IPAddrMode{
		"":       IPUnset,
		"static": IPStatic,
		"dhcp":   IPDynamic,
	}

	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}

	ip, ok := toId[s]
	if !ok {
		return &json.UnmarshalTypeError{
			Value: fmt.Sprintf("string %q", s),
			Type:  reflect.TypeOf(i),
		}
	}
	*i = ip
	return nil
}

// SecurityCfg groups host specific configuration.
type HostCfg struct {
	IPAddrMode       IPAddrMode        `json:"network_mode"`
	HostIP           *netlink.Addr     `json:"host_ip"`
	DefaultGateway   *net.IP           `json:"gateway"`
	DNSServer        *net.IP           `json:"dns"`
	NetworkInterface *net.HardwareAddr `json:"network_interface"`
	ProvisioningURLs []*url.URL        `json:"provisioning_urls"`
	ID               string            `json:"identity"`
	Auth             string            `json:"authentication"`
}

// MarshalJSON implements json.Marshaler.
func (h HostCfg) MarshalJSON() ([]byte, error) {
	var (
		hostIP           string
		defaultGateway   string
		dnsServer        string
		networkInterface string
		provisioningURLs []string
	)

	if h.HostIP != nil {
		hostIP = h.HostIP.String()
	}
	if h.DefaultGateway != nil {
		defaultGateway = h.DefaultGateway.String()
	}
	if h.DNSServer != nil {
		dnsServer = h.DNSServer.String()
	}
	if h.NetworkInterface != nil {
		networkInterface = h.NetworkInterface.String()
	}
	for _, u := range h.ProvisioningURLs {
		provisioningURLs = append(provisioningURLs, u.String())
	}

	easy := struct {
		IPAddrMode       IPAddrMode `json:"network_mode"`
		HostIP           string     `json:"host_ip"`
		DefaultGateway   string     `json:"gateway"`
		DNSServer        string     `json:"dns"`
		NetworkInterface string     `json:"network_interface"`
		ProvisioningURLs []string   `json:"provisioning_urls"`
		ID               string     `json:"identity"`
		Auth             string     `json:"authentication"`
	}{
		IPAddrMode:       h.IPAddrMode,
		HostIP:           hostIP,
		DefaultGateway:   defaultGateway,
		DNSServer:        dnsServer,
		NetworkInterface: networkInterface,
		ProvisioningURLs: provisioningURLs,
		ID:               h.ID,
		Auth:             h.Auth,
	}
	return json.Marshal(easy)
}

// UnmarshalJSON implements json.Unmarshaler.
func (h *HostCfg) UnmarshalJSON(data []byte) error {
	var maybeCfg map[string]interface{}
	if err := json.Unmarshal(data, &maybeCfg); err != nil {
		return err
	}

	// check for missing json tags
	tags, _ := jsonTags(h)
	for _, tag := range tags {
		if _, ok := maybeCfg[tag]; !ok {
			return fmt.Errorf("missing json key %q", tag)
		}
	}

	// marshaling the fields implemting a proper json.Unmarshaler
	easy := struct {
		IPAddrMode IPAddrMode `json:"network_mode"`
		ID         string     `json:"identity"`
		Auth       string     `json:"authentication"`
	}{}

	if err := json.Unmarshal(data, &easy); err != nil {
		return err
	}

	h.IPAddrMode = easy.IPAddrMode
	h.ID = easy.ID
	h.Auth = easy.Auth

	// marshaling the more complex fields
	tricky := struct {
		HostIP           string   `json:"host_ip"`
		DefaultGateway   string   `json:"gateway"`
		DNSServer        string   `json:"dns"`
		NetworkInterface string   `json:"network_interface"`
		ProvisioningURLs []string `json:"provisioning_urls"`
	}{}
	if err := json.Unmarshal(data, &tricky); err != nil {
		return err
	}

	if tricky.HostIP != "" {
		ip, err := netlink.ParseAddr(tricky.HostIP)
		if err != nil {
			return &json.UnmarshalTypeError{
				Value: fmt.Sprintf("string %q", tricky.HostIP),
				Type:  reflect.TypeOf(h.HostIP),
			}
		}
		h.HostIP = ip
	}

	if tricky.DefaultGateway != "" {
		gw := net.ParseIP(tricky.DefaultGateway)
		if gw == nil {
			return &json.UnmarshalTypeError{
				Value: fmt.Sprintf("string %q", tricky.DefaultGateway),
				Type:  reflect.TypeOf(h.DefaultGateway),
			}
		}
		h.DefaultGateway = &gw
	}

	if tricky.DNSServer != "" {
		dns := net.ParseIP(tricky.DNSServer)
		if dns == nil {
			return &json.UnmarshalTypeError{
				Value: fmt.Sprintf("string %q", tricky.DNSServer),
				Type:  reflect.TypeOf(h.DNSServer),
			}
		}
		h.DNSServer = &dns
	}

	if tricky.NetworkInterface != "" {
		mac, err := net.ParseMAC(tricky.NetworkInterface)
		if err != nil {
			return &json.UnmarshalTypeError{
				Value: fmt.Sprintf("string %q", tricky.NetworkInterface),
				Type:  reflect.TypeOf(h.NetworkInterface),
			}
		}
		h.NetworkInterface = &mac
	}

	urls := []*url.URL{}
	for i, urlStr := range tricky.ProvisioningURLs {
		if urlStr != "" {
			u, err := url.ParseRequestURI(urlStr)
			if err != nil {
				return &json.UnmarshalTypeError{
					Value: fmt.Sprintf("string %q", tricky.ProvisioningURLs[i]),
					Type:  reflect.TypeOf(h.ProvisioningURLs).Elem().Elem(),
				}
			}
			urls = append(urls, u)
		}
	}
	if len(urls) > 0 {
		h.ProvisioningURLs = urls
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
