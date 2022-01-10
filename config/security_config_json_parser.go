package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	SecurityCfgVersionJSONKey      = "version"
	ValidSignatureThresholdJSONKey = "min_valid_sigs_required"
	BootModeJSONKey                = "boot_mode"
	UsePkgCacheJSONKey             = "use_ospkg_cache"
	AttestationServiceKey          = "attestation_service"
	AttestationTokenKey            = "attestation_token"
)

type securityCfgParser func(rawCfg, *SecurityCfg) error

var securityCfgParsers = []securityCfgParser{
	parseSecurityKeys,
	parseSecurityCfgVersion,
	parseValidSignatureThreshold,
	parseBootMode,
	parseUsePkgCache,
	parseAttestationService,
	parseAttestationToken,
}

type SecurityCfgJSONParser struct {
	r io.Reader
}

func (sp *SecurityCfgJSONParser) Parse() (*SecurityCfg, error) {
	jsonBlob, err := io.ReadAll(sp.r)
	if err != nil {
		return nil, err
	}

	var raw rawCfg
	if err = json.Unmarshal(jsonBlob, &raw); err != nil {
		return nil, err
	}

	cfg := &SecurityCfg{}
	for _, p := range securityCfgParsers {
		if err := p(raw, cfg); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

func parseSecurityKeys(r rawCfg, c *SecurityCfg) error {
	for key := range r {
		switch key {
		case SecurityCfgVersionJSONKey:
			continue
		case ValidSignatureThresholdJSONKey:
			continue
		case BootModeJSONKey:
			continue
		case UsePkgCacheJSONKey:
			continue
		case AttestationServiceKey:
			continue
		case AttestationTokenKey:
			continue
		default:
			return &ParseError{key, errors.New("bad key")}
		}
	}
	return nil
}

func parseSecurityCfgVersion(r rawCfg, c *SecurityCfg) error {
	key := SecurityCfgVersionJSONKey
	if val, found := r[key]; found {
		if ver, ok := val.(float64); ok {
			c.Version = int(ver)
			return nil
		} else {
			return &TypeError{key, val}
		}
	}
	return &ParseError{key, errors.New("missing key")}
}

func parseValidSignatureThreshold(r rawCfg, c *SecurityCfg) error {
	key := ValidSignatureThresholdJSONKey
	if val, found := r[key]; found {
		if th, ok := val.(float64); ok {
			if int(th) < 0 {
				return &ParseError{key, errors.New("value is negative")}
			}
			c.ValidSignatureThreshold = uint(th)
			return nil
		} else {
			return &TypeError{key, val}
		}
	}
	return &ParseError{key, errors.New("missing key")}
}

func parseBootMode(r rawCfg, c *SecurityCfg) error {
	key := BootModeJSONKey
	if val, found := r[key]; found {
		if m, ok := val.(string); ok {
			switch m {
			case "", UnsetBootMode.String():
				c.BootMode = UnsetBootMode
			case LocalBoot.String():
				c.BootMode = LocalBoot
			case NetworkBoot.String():
				c.BootMode = NetworkBoot
			default:
				return &ParseError{key, fmt.Errorf("unknown boot mode %q", m)}
			}
			return nil
		} else {
			return &TypeError{key, val}
		}
	}
	return &ParseError{key, errors.New("missing key")}
}

func parseUsePkgCache(r rawCfg, c *SecurityCfg) error {
	key := UsePkgCacheJSONKey
	if val, found := r[key]; found {
		if b, ok := val.(bool); ok {
			c.UsePkgCache = b
			return nil
		} else {
			return &TypeError{key, val}
		}
	}
	return &ParseError{key, errors.New("missing key")}
}

func parseAttestationService(r rawCfg, c *SecurityCfg) error {
	key := AttestationServiceKey
	if val, found := r[key]; found {
		if s, ok := val.(string); ok {
			switch s {
			case Immune.String():
				c.AttestationService = Immune
			default:
				return &ParseError{key, fmt.Errorf("unknown attestation service %q", s)}
			}
			return nil
		} else {
			return &TypeError{key, val}
		}
	}
	return &ParseError{key, errors.New("missing key")}
}

func parseAttestationToken(r rawCfg, c *SecurityCfg) error {
	key := AttestationTokenKey
	if val, found := r[key]; found {
		if t, ok := val.(string); ok {
			switch c.AttestationService {
			case Immune:
				if len(t) == AttestationTokenLen {
					_, err := base64.StdEncoding.DecodeString(t)
					if err == nil {
						c.AttestationToken = t
					} else {
						return &ParseError{key, fmt.Errorf("unknown attestation token %q", t)}
					}
				} else {
					return &ParseError{key, fmt.Errorf("unknown attestation token %q", t)}
				}
			default:
				return &ParseError{key, fmt.Errorf("unknown attestation token %q", t)}
			}
			return nil
		} else {
			return &TypeError{key, val}
		}
	}
	return &ParseError{key, errors.New("missing key")}
}
