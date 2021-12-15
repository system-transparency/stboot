package opts

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"

	"github.com/vishvananda/netlink"
)

const (
	HostCfgVersionJSONKey   = "version"
	NetworkModeJSONKey      = "network_mode"
	HostIPJSONKey           = "host_ip"
	DefaultGatewayJSONKey   = "gateway"
	DNSServerJSONKey        = "dns"
	NetworkInterfaceJSONKey = "network_interface"
	ProvisioningURLsJSONKey = "provisioning_urls"
	IdJSONKey               = "identity"
	AuthJSONKey             = "authentication"
)

type hostCfgParser func(map[string]interface{}, *Opts) error

var hostCfgParsers = []hostCfgParser{
	parseHostKeys,
	parseHostCfgVersion,
	parseNetworkMode,
	parseHostIP,
	parseDefaultGateway,
	parseDNSServer,
	parseNetworkInterface,
	parseProvisioningURLs,
	parseID,
	parseAuth,
}

type HostCfgJSONParser struct {
	r io.Reader
}

func (hp *HostCfgJSONParser) Parse() (*Opts, error) {
	jsonBlob, err := io.ReadAll(hp.r)
	if err != nil {
		return nil, err
	}

	var raw map[string]interface{}
	if err = json.Unmarshal(jsonBlob, &raw); err != nil {
		return nil, err
	}

	opts := &Opts{}
	for _, p := range hostCfgParsers {
		if err := p(raw, opts); err != nil {
			return nil, err
		}
	}
	return opts, nil
}

func parseHostKeys(r map[string]interface{}, c *Opts) error {
	for key := range r {
		switch key {
		case HostCfgVersionJSONKey:
			continue
		case NetworkModeJSONKey:
			continue
		case HostIPJSONKey:
			continue
		case DefaultGatewayJSONKey:
			continue
		case DNSServerJSONKey:
			continue
		case NetworkInterfaceJSONKey:
			continue
		case ProvisioningURLsJSONKey:
			continue
		case IdJSONKey:
			continue
		case AuthJSONKey:
			continue
		default:
			return &ParseError{key: key, err: fmt.Errorf("bad key")}
		}
	}
	return nil
}

func parseHostCfgVersion(r map[string]interface{}, c *Opts) error {
	key := HostCfgVersionJSONKey
	if val, found := r[key]; found {
		if ver, ok := val.(float64); ok {
			if int(ver) != OptsVersion {
				return &ParseError{key: key, err: fmt.Errorf("version mismatch, got %d want %d", int(ver), OptsVersion)}
			}
			return nil
		} else {
			return &ParseError{key: key, wrongType: val}
		}
	}
	return &ParseError{key: key, err: fmt.Errorf("missing key")}
}

func parseNetworkMode(r map[string]interface{}, c *Opts) error {
	key := NetworkModeJSONKey
	if val, found := r[key]; found {
		if m, ok := val.(string); ok {
			switch m {
			case "", IPUnset.String():
				c.IPAddrMode = IPUnset
			case IPStatic.String():
				c.IPAddrMode = IPStatic
			case IPDynamic.String():
				c.IPAddrMode = IPDynamic
			default:
				return &ParseError{key: key, err: fmt.Errorf("unknown network mode %q", m)}
			}
			return nil
		} else {
			return &ParseError{key: key, wrongType: val}
		}
	}
	return &ParseError{key: key, err: fmt.Errorf("missing key")}
}

func parseHostIP(r map[string]interface{}, c *Opts) error {
	key := HostIPJSONKey
	if val, found := r[key]; found {
		if ipStr, ok := val.(string); ok {
			if ipStr != "" {
				ip, err := netlink.ParseAddr(ipStr)
				if err != nil {
					return &ParseError{key: key, err: err}
				}
				c.HostIP = ip
			}
			return nil
		} else {
			return &ParseError{key: key, wrongType: val}
		}
	}
	return &ParseError{key: key, err: fmt.Errorf("missing key")}
}

func parseDefaultGateway(r map[string]interface{}, c *Opts) error {
	key := DefaultGatewayJSONKey
	if val, found := r[key]; found {
		if ipStr, ok := val.(string); ok {
			if ipStr != "" {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					return &ParseError{key: key, err: fmt.Errorf("invalid textual representation of IP address: %s", ipStr)}
				}
				c.DefaultGateway = &ip
			}
			return nil
		} else {
			return &ParseError{key: key, wrongType: val}
		}
	}
	return &ParseError{key: key, err: fmt.Errorf("missing key")}
}

func parseDNSServer(r map[string]interface{}, c *Opts) error {
	key := DNSServerJSONKey
	if val, found := r[key]; found {
		if ipStr, ok := val.(string); ok {
			if ipStr != "" {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					return &ParseError{key: key, err: fmt.Errorf("invalid textual representation of IP address: %s", ipStr)}
				}
				c.DNSServer = &ip
			}
			return nil
		} else {
			return &ParseError{key: key, wrongType: val}
		}
	}
	return &ParseError{key: key, err: fmt.Errorf("missing key")}
}

func parseNetworkInterface(r map[string]interface{}, c *Opts) error {
	key := NetworkInterfaceJSONKey
	if val, found := r[key]; found {
		if macStr, ok := val.(string); ok {
			if macStr != "" {
				mac, err := net.ParseMAC(macStr)
				if err != nil {
					return &ParseError{key: key, err: err}
				}
				c.NetworkInterface = &mac
			}
			return nil
		} else {
			return &ParseError{key: key, wrongType: val}
		}
	}
	return &ParseError{key: key, err: fmt.Errorf("missing key")}
}

func parseProvisioningURLs(r map[string]interface{}, c *Opts) error {
	key := ProvisioningURLsJSONKey
	if val, found := r[key]; found {
		if array, ok := val.([]interface{}); ok {
			urls := make([]*url.URL, 0)
			for _, v := range array {
				if urlStr, ok := v.(string); ok {
					if urlStr != "" {
						u, err := url.ParseRequestURI(urlStr)
						if err != nil {
							return &ParseError{key: key, err: err}
						}
						urls = append(urls, u)
						c.ProvisioningURLs = urls
					}
				} else {
					return &ParseError{key: key, wrongType: v}
				}
			}
			return nil
		} else {
			return &ParseError{key: key, wrongType: val}
		}
	}
	return &ParseError{key: key, err: fmt.Errorf("missing key")}
}

func parseID(r map[string]interface{}, c *Opts) error {
	key := IdJSONKey
	if val, found := r[key]; found {
		if id, ok := val.(string); ok {
			c.ID = id
			return nil
		} else {
			return &ParseError{key: key, wrongType: val}
		}
	}
	return &ParseError{key: key, err: fmt.Errorf("missing key")}
}

func parseAuth(r map[string]interface{}, c *Opts) error {
	key := AuthJSONKey
	if val, found := r[key]; found {
		if a, ok := val.(string); ok {
			c.Auth = a
			return nil
		} else {
			return &ParseError{key: key, wrongType: val}
		}
	}
	return &ParseError{key: key, err: fmt.Errorf("missing key")}
}
