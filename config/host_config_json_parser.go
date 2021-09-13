package config

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

type TypeError struct {
	Key   string
	Value interface{}
}

func (t *TypeError) Error() string {
	return fmt.Sprintf("value of JSON key %s has wrong type %T", t.Key, t.Value)
}

type ParseError struct {
	Key string
	Err error
}

func (p *ParseError) Error() string {
	return fmt.Sprintf("parsing value of JSON key %s failed: %v", p.Key, p.Err)
}

type rawCfg map[string]interface{}

type hostCfgParser func(rawCfg, *HostCfg) error

var hostCfgParsers = []hostCfgParser{
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

func (hp *HostCfgJSONParser) Parse() (*HostCfg, error) {
	jsonBlob, err := io.ReadAll(hp.r)
	if err != nil {
		return nil, err
	}

	var raw rawCfg
	if err = json.Unmarshal(jsonBlob, &raw); err != nil {
		return nil, err
	}

	cfg := &HostCfg{}
	for _, p := range hostCfgParsers {
		if err := p(raw, cfg); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

func parseHostCfgVersion(r rawCfg, c *HostCfg) error {
	key := HostCfgVersionJSONKey
	if val, found := r[key]; found {
		if ver, ok := val.(float64); ok {
			c.Version = int(ver)
		} else {
			return &TypeError{key, val}
		}
	}
	return nil
}

func parseNetworkMode(r rawCfg, c *HostCfg) error {
	key := NetworkModeJSONKey
	if val, found := r[key]; found {
		if m, ok := val.(string); ok {
			switch m {
			case "", UnsetIPAddrMode.String():
				c.IPAddrMode = UnsetIPAddrMode
			case StaticIP.String():
				c.IPAddrMode = StaticIP
			case DynamicIP.String():
				c.IPAddrMode = DynamicIP
			default:
				return &ParseError{key, fmt.Errorf("unknown network mode %q", m)}
			}
		} else {
			return &TypeError{key, val}
		}
	}
	return nil
}

func parseHostIP(r rawCfg, c *HostCfg) error {
	key := HostIPJSONKey
	if val, found := r[key]; found {
		if ipStr, ok := val.(string); ok {
			if ipStr != "" {
				ip, err := netlink.ParseAddr(ipStr)
				if err != nil {
					return &ParseError{key, err}
				}
				c.HostIP = ip
			}
		} else {
			return &TypeError{key, val}
		}
	}
	return nil
}

func parseDefaultGateway(r rawCfg, c *HostCfg) error {
	key := DefaultGatewayJSONKey
	if val, found := r[key]; found {
		if ipStr, ok := val.(string); ok {
			if ipStr != "" {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					return &ParseError{key, fmt.Errorf("invalid textual representation of IP address: %s", ipStr)}
				}
				c.DefaultGateway = &ip
			}
		} else {
			return &TypeError{key, val}
		}
	}
	return nil
}

func parseDNSServer(r rawCfg, c *HostCfg) error {
	key := DNSServerJSONKey
	if val, found := r[key]; found {
		if ipStr, ok := val.(string); ok {
			if ipStr != "" {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					return &ParseError{key, fmt.Errorf("invalid textual representation of IP address: %s", ipStr)}
				}
				c.DNSServer = &ip
			}
		} else {
			return &TypeError{key, val}
		}
	}
	return nil
}

func parseNetworkInterface(r rawCfg, c *HostCfg) error {
	key := NetworkInterfaceJSONKey
	if val, found := r[key]; found {
		if macStr, ok := val.(string); ok {
			if macStr != "" {
				mac, err := net.ParseMAC(macStr)
				if err != nil {
					return &ParseError{key, err}
				}
				c.NetworkInterface = &mac
			}
		} else {
			return &TypeError{key, val}
		}
	}
	return nil
}

func parseProvisioningURLs(r rawCfg, c *HostCfg) error {
	key := ProvisioningURLsJSONKey
	if val, found := r[key]; found {
		if array, ok := val.([]interface{}); ok {
			urls := make([]*url.URL, 0)
			for _, v := range array {
				if urlStr, ok := v.(string); ok {
					if urlStr != "" {
						u, err := url.ParseRequestURI(urlStr)
						if err != nil {
							return &ParseError{key, err}
						}
						urls = append(urls, u)
						c.ProvisioningURLs = urls
					}
				} else {
					return &TypeError{key, v}
				}
			}
		} else {
			return &TypeError{key, val}
		}
	}
	return nil
}

func parseID(r rawCfg, c *HostCfg) error {
	key := IdJSONKey
	if val, found := r[key]; found {
		if id, ok := val.(string); ok {
			c.ID = id
		} else {
			return &TypeError{key, val}
		}
	}
	return nil
}

func parseAuth(r rawCfg, c *HostCfg) error {
	key := AuthJSONKey
	if val, found := r[key]; found {
		if a, ok := val.(string); ok {
			c.Auth = a
		} else {
			return &TypeError{key, val}
		}
	}
	return nil
}
