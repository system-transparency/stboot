package opts

import (
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
)

type securityCfgParser func(map[string]interface{}, *Opts) error

var securityCfgParsers = []securityCfgParser{
	parseSecurityKeys,
	parseSecurityCfgVersion,
	parseValidSignatureThreshold,
	parseBootMode,
	parseUsePkgCache,
}

type SecurityCfgJSONParser struct {
	r io.Reader
}

func (sp *SecurityCfgJSONParser) Parse() (*Opts, error) {
	jsonBlob, err := io.ReadAll(sp.r)
	if err != nil {
		return nil, err
	}

	var raw map[string]interface{}
	if err = json.Unmarshal(jsonBlob, &raw); err != nil {
		return nil, err
	}

	opts := &Opts{}
	for _, p := range securityCfgParsers {
		if err := p(raw, opts); err != nil {
			return nil, err
		}
	}
	return opts, nil
}

func parseSecurityKeys(raw map[string]interface{}, o *Opts) error {
	for key := range raw {
		switch key {
		case SecurityCfgVersionJSONKey:
			continue
		case ValidSignatureThresholdJSONKey:
			continue
		case BootModeJSONKey:
			continue
		case UsePkgCacheJSONKey:
			continue
		default:
			return &ParseError{key: key, err: errors.New("bad key")}
		}
	}
	return nil
}

func parseSecurityCfgVersion(raw map[string]interface{}, o *Opts) error {
	key := SecurityCfgVersionJSONKey
	if val, found := raw[key]; found {
		if ver, ok := val.(float64); ok {
			if int(ver) != OptsVersion {
				return &ParseError{key: key, err: fmt.Errorf("version mismatch, got %d want %d", int(ver), OptsVersion)}
			}
			return nil
		} else {
			return &ParseError{key: key, wrongType: val}
		}
	}
	return &ParseError{key: key, err: errors.New("missing key")}
}

func parseValidSignatureThreshold(raw map[string]interface{}, o *Opts) error {
	key := ValidSignatureThresholdJSONKey
	if val, found := raw[key]; found {
		if th, ok := val.(float64); ok {
			if int(th) < 0 {
				return &ParseError{key: key, err: errors.New("value is negative")}
			}
			o.ValidSignatureThreshold = uint(th)
			return nil
		} else {
			return &ParseError{key: key, wrongType: val}
		}
	}
	return &ParseError{key: key, err: errors.New("missing key")}
}

func parseBootMode(raw map[string]interface{}, o *Opts) error {
	key := BootModeJSONKey
	if val, found := raw[key]; found {
		if m, ok := val.(string); ok {
			switch m {
			case "", BootModeUnset.String():
				o.BootMode = BootModeUnset
			case LocalBoot.String():
				o.BootMode = LocalBoot
			case NetworkBoot.String():
				o.BootMode = NetworkBoot
			default:
				return &ParseError{key: key, err: fmt.Errorf("unknown boot mode %q", m)}
			}
			return nil
		} else {
			return &ParseError{key: key, wrongType: val}
		}
	}
	return &ParseError{key: key, err: errors.New("missing key")}
}

func parseUsePkgCache(raw map[string]interface{}, o *Opts) error {
	key := UsePkgCacheJSONKey
	if val, found := raw[key]; found {
		if b, ok := val.(bool); ok {
			o.UsePkgCache = b
			return nil
		} else {
			return &ParseError{key: key, wrongType: val}
		}
	}
	return &ParseError{key: key, err: errors.New("missing key")}
}
