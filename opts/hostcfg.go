package opts

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/system-transparency/stboot/stlog"
	"github.com/vishvananda/netlink"
)

const (
	ErrMissingJSONKey = Error("missing JSON key")
	ErrNoSrcProvided  = Error("no source provided")

	ErrMissingIPAddrMode        = Error("IP address mode must be set")
	ErrUnknownIPAddrMode        = Error("unknown IP address mode")
	ErrUnknownBondingMode       = Error("unknown bonding mode")
	ErrMissingBondName          = Error("bond name must be set")
	ErrMissingNetworkInterfaces = Error("one or more network interfaces must be set")
	ErrMissingProvURLs          = Error("provisioning server URL list must not be empty")
	ErrInvalidProvURLs          = Error("missing or unsupported scheme in provisioning URLs")
	ErrMissingIPAddr            = Error("IP address must not be empty when static IP mode is set")
	ErrMissingGateway           = Error("default gateway must not be empty when static IP mode is set")
	ErrMissingID                = Error("ID must not be empty when a URL contains '$ID'")
	ErrInvalidID                = Error("invalid ID string, min 1 char, allowed chars are [a-z,A-Z,0-9,-,_]")
	ErrMissingAuth              = Error("Auth must be set when a URL contains '$AUTH'")
	ErrInvalidAuth              = Error("invalid auth string, min 1 char, allowed chars are [a-z,A-Z,0-9,-,_]")
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
	}

	return []byte(JSONNull), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (i *IPAddrMode) UnmarshalJSON(data []byte) error {
	if string(data) == JSONNull {
		*i = IPUnset
	} else {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}

		toID := map[string]IPAddrMode{
			"static": IPStatic,
			"dhcp":   IPDynamic,
		}
		mode, ok := toID[str]
		if !ok {
			return &json.UnmarshalTypeError{
				Value: fmt.Sprintf("string %q", str),
				Type:  reflect.TypeOf(i),
			}
		}
		*i = mode
	}

	return nil
}

// BondingMode sets the mode for bonding.
type BondingMode int

const (
	BondingUnset BondingMode = iota
	BondingBalancedRR
)

// String implements fmt.Stringer.
func (i BondingMode) String() string {
	return [...]string{"", "balanced-rr"}[i]
}

// MarshalJSON implements json.Marshaler.
func (i BondingMode) MarshalJSON() ([]byte, error) {
	if i != BondingUnset {
		return json.Marshal(i.String())
	}

	return []byte(JSONNull), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (i *BondingMode) UnmarshalJSON(data []byte) error {
	if string(data) == JSONNull {
		*i = BondingUnset
	} else {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}

		toID := map[string]BondingMode{
			"":            BondingUnset,
			"balanced-rr": BondingBalancedRR,
		}
		mode, ok := toID[str]
		if !ok {
			return &json.UnmarshalTypeError{
				Value: fmt.Sprintf("string %q", str),
				Type:  reflect.TypeOf(i),
			}
		}
		*i = mode
	}

	return nil
}

// HostCfg groups host specific configuration.
type HostCfg struct {
	IPAddrMode        IPAddrMode        `json:"network_mode"`
	HostIP            *netlink.Addr     `json:"host_ip"`
	DefaultGateway    *net.IP           `json:"gateway"`
	DNSServer         *net.IP           `json:"dns"`
	NetworkInterface  *net.HardwareAddr `json:"network_interface"`
	ProvisioningURLs  *[]*url.URL       `json:"provisioning_urls"`
	ID                *string           `json:"identity"`
	Auth              *string           `json:"authentication"`
	Timestamp         *time.Time        `json:"timestamp"`
	NetworkInterfaces *[]*string        `json:"network_interfaces"`
	BondingMode       BondingMode       `json:"bonding_mode"`
	BondName          *string           `json:"bond_name"`
}

type hostCfg struct {
	IPAddrMode        IPAddrMode       `json:"network_mode"`
	HostIP            *netlinkAddr     `json:"host_ip"`
	DefaultGateway    *netIP           `json:"gateway"`
	DNSServer         *netIP           `json:"dns"`
	NetworkInterface  *netHardwareAddr `json:"network_interface"`
	ProvisioningURLs  *[]*urlURL       `json:"provisioning_urls"`
	ID                *string          `json:"identity"`
	Auth              *string          `json:"authentication"`
	Timestamp         *timeTime        `json:"timestamp"`
	NetworkInterfaces *[]*string       `json:"network_interfaces"`
	BondingMode       BondingMode      `json:"bonding_mode"`
	BondName          *string          `json:"bond_name"`
}

// MarshalJSON implements json.Marshaler.
func (h HostCfg) MarshalJSON() ([]byte, error) {
	alias := hostCfg{
		IPAddrMode:        h.IPAddrMode,
		HostIP:            (*netlinkAddr)(h.HostIP),
		DefaultGateway:    (*netIP)(h.DefaultGateway),
		DNSServer:         (*netIP)(h.DNSServer),
		NetworkInterface:  (*netHardwareAddr)(h.NetworkInterface),
		ProvisioningURLs:  urls2alias(h.ProvisioningURLs),
		ID:                h.ID,
		Auth:              h.Auth,
		Timestamp:         (*timeTime)(h.Timestamp),
		NetworkInterfaces: h.NetworkInterfaces,
		BondingMode:       h.BondingMode,
		BondName:          h.BondName,
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
			stlog.Debug("All fields of host config are expected to be set or unset. Missing json key %q", tag)

			return ErrMissingJSONKey
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
	h.NetworkInterfaces = alias.NetworkInterfaces
	h.BondingMode = alias.BondingMode
	h.BondName = alias.BondName

	if err := h.validate(); err != nil {
		*h = HostCfg{}

		return fmt.Errorf("unmarshal host config: %w", err)
	}

	return nil
}

func (h *HostCfg) validate() error {
	var validationSet = []func(*HostCfg) error{
		checkIPAddrMode,
		checkHostIP,
		checkGateway,
		checkProvisioningURLs,
		checkID,
		checkAuth,
		checkBonding,
	}

	for _, f := range validationSet {
		if err := f(h); err != nil {
			return err
		}
	}

	return nil
}

func checkIPAddrMode(cfg *HostCfg) error {
	if cfg.IPAddrMode == IPUnset {
		return ErrMissingIPAddrMode
	}

	return nil
}

func checkHostIP(cfg *HostCfg) error {
	if cfg.IPAddrMode == IPStatic && cfg.HostIP == nil {
		return ErrMissingIPAddr
	}

	return nil
}

func checkGateway(cfg *HostCfg) error {
	if cfg.IPAddrMode == IPStatic && cfg.DefaultGateway == nil {
		return ErrMissingGateway
	}

	return nil
}

func checkProvisioningURLs(cfg *HostCfg) error {
	if cfg.ProvisioningURLs != nil {
		if len(*cfg.ProvisioningURLs) == 0 {
			return ErrMissingProvURLs
		}

		for _, u := range *cfg.ProvisioningURLs {
			s := u.Scheme
			if s == "" || s != "http" && s != "https" {
				return ErrInvalidProvURLs
			}
		}
	} else {
		return ErrMissingProvURLs
	}

	return nil
}

func checkID(cfg *HostCfg) error {
	var used bool

	if cfg.ProvisioningURLs != nil {
		for _, u := range *cfg.ProvisioningURLs {
			if used = strings.Contains(u.String(), "$ID"); used {
				break
			}
		}
	}

	if used {
		if cfg.ID == nil {
			return ErrMissingID
		} else if !hasAllowedChars(*cfg.ID) {
			return ErrInvalidID
		}
	}

	return nil
}

func checkAuth(cfg *HostCfg) error {
	var used bool

	if cfg.ProvisioningURLs != nil {
		for _, u := range *cfg.ProvisioningURLs {
			if used = strings.Contains(u.String(), "$AUTH"); used {
				break
			}
		}
	}

	if used {
		if cfg.Auth == nil {
			return ErrMissingAuth
		} else if !hasAllowedChars(*cfg.Auth) {
			return ErrInvalidAuth
		}
	}

	return nil
}

func checkBonding(cfg *HostCfg) error {
	if cfg.BondingMode == BondingUnset {
		return nil
	}

	if *cfg.BondName == "" {
		return ErrMissingBondName
	}

	if len(*cfg.NetworkInterfaces) == 0 {
		return ErrMissingNetworkInterfaces
	}

	return nil
}

func hasAllowedChars(str string) bool {
	const maxLen = 64
	if len(str) > maxLen {
		return false
	}

	return regexp.MustCompile(`^[A-Za-z-_]+$`).MatchString(str)
}

func urls2alias(input *[]*url.URL) *[]*urlURL {
	if input == nil {
		return nil
	}

	ret := make([]*urlURL, len(*input))
	for i := range ret {
		if (*input)[i] != nil {
			u := *(*input)[i]
			cast := urlURL(u)
			ret[i] = &cast
		}
	}

	return &ret
}

func alias2urls(input *[]*urlURL) *[]*url.URL {
	if input == nil {
		return nil
	}

	ret := make([]*url.URL, len(*input))
	for i := range ret {
		if (*input)[i] != nil {
			u := *(*input)[i]
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

	ipAddr, err := netlink.ParseAddr(str)
	if err != nil {
		return &json.UnmarshalTypeError{
			Value: fmt.Sprintf("string %q", str),
			Type:  reflect.TypeOf(ipAddr),
		}
	}

	*n = netlinkAddr(*ipAddr)

	return nil
}

type netIP net.IP

func (n netIP) MarshalJSON() ([]byte, error) {
	return json.Marshal(net.IP(n).String())
}

func (n *netIP) UnmarshalJSON(data []byte) error {
	if string(data) == JSONNull {
		*n = nil
	} else {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		ipAddr := net.ParseIP(str)
		if ipAddr == nil {
			return &json.UnmarshalTypeError{
				Value: fmt.Sprintf("string %q", str),
				Type:  reflect.TypeOf(ipAddr),
			}
		}
		*n = netIP(ipAddr)
	}

	return nil
}

type netHardwareAddr net.HardwareAddr

func (n netHardwareAddr) MarshalJSON() ([]byte, error) {
	return json.Marshal(net.HardwareAddr(n).String())
}

func (n *netHardwareAddr) UnmarshalJSON(data []byte) error {
	if string(data) == JSONNull {
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
	if string(data) == JSONNull {
		*u = urlURL{}
	} else {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}
		uri, err := url.ParseRequestURI(str)
		if err != nil {
			return &json.UnmarshalTypeError{
				Value: fmt.Sprintf("string %q", str),
				Type:  reflect.TypeOf(uri),
			}
		}
		*u = urlURL(*uri)
	}

	return nil
}

type timeTime time.Time

func (t timeTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(t).Unix())
}

func (t *timeTime) UnmarshalJSON(data []byte) error {
	if string(data) == JSONNull {
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
	io.Reader
}

// Load implements Loader.
func (h *HostCfgJSON) Load(opts *Opts) error {
	var hostCfg HostCfg

	if h.Reader == nil {
		return ErrNoSrcProvided
	}

	d := json.NewDecoder(h.Reader)
	if err := d.Decode(&hostCfg); err != nil {
		return err
	}

	opts.HostCfg = hostCfg

	return nil
}

// HostCfgFile wraps SecurityJSON.
type HostCfgFile struct {
	Name string
}

// Load implements Loader.
func (h *HostCfgFile) Load(opts *Opts) error {
	file, err := os.Open(h.Name)
	if err != nil {
		return fmt.Errorf("load host config: %w", err)
	}
	defer file.Close()

	j := HostCfgJSON{file}
	if err := j.Load(opts); err != nil {
		return err
	}

	return nil
}
