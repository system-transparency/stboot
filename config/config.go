package config

import "io"

type InvalidError string

func (e InvalidError) Error() string {
	return string(e)
}

type HostCfgParser interface {
	Parse() (*HostCfg, error)
}

type SecurityCfgParser interface {
	Parse() (*SecurityCfg, error)
}

type hcValidator func(*HostCfg) error

type scValidator func(*SecurityCfg) error

func LoadHostConfigFromJSON(r io.Reader) (*HostCfg, error) {
	return LoadHostCfg(&HostCfgJSONParser{r})
}

// LoadHostCfg returns a HostCfg using the provided parser
func LoadHostCfg(p HostCfgParser) (*HostCfg, error) {
	c, _ := p.Parse()

	for _, v := range hcValidators {
		if err := v(c); err != nil {
			return nil, err
		}
	}

	return c, nil
}

func LoadSecurityConfigFromJSON(r io.Reader) (*SecurityCfg, error) {
	return LoadSecurityCfg(&SecurityCfgJSONParser{r})
}

// LoadSecuritCfg returns a SecurityCfg using the provided parser
func LoadSecurityCfg(p SecurityCfgParser) (*SecurityCfg, error) {
	c, _ := p.Parse()

	for _, v := range scValidators {
		if err := v(c); err != nil {
			return nil, err
		}
	}

	return c, nil
}
