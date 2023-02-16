package trust

import (
	"encoding/json"
	"errors"
	"fmt"

	"system-transparency.org/stboot/ospkg"
)

var ErrInvalidPolicy = errors.New("invalid policy")

// Policy holds security configuration.
type Policy struct {
	OSPKGSignatureThreshold int            `json:"ospkg_signature_threshold"`
	BootMode                ospkg.BootMode `json:"boot_mode"`
}

// policy is used as an alias in Policy.UnmarshalJSON.
type policy struct {
	OSPKGSignatureThreshold int            `json:"ospkg_signature_threshold"`
	BootMode                ospkg.BootMode `json:"boot_mode"`
}

// UnmarshalJSON implements json.Unmarshaler. It initializes p from a JSON data
// byte stream.
// If unmarshaling fails, a json.UnmarshalTypeError is returned.
// In case of further inter-field invalidities or other rules, that are not met,
// the reurned error wrapps ErrInvalidPolicy.
func (p *Policy) UnmarshalJSON(data []byte) error {
	alias := policy{}
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}

	p.OSPKGSignatureThreshold = alias.OSPKGSignatureThreshold
	p.BootMode = alias.BootMode

	if err := p.validate(); err != nil {
		*p = Policy{}

		return fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}

	return nil
}

func (p *Policy) validate() error {
	var validationSet = []func() error{
		p.checkOSPKGSignatureThreshold,
		p.checkBootMode,
	}

	for _, f := range validationSet {
		if err := f(); err != nil {
			return err
		}
	}

	return nil
}

func (p *Policy) checkOSPKGSignatureThreshold() error {
	if p.OSPKGSignatureThreshold < 1 {
		return errors.New("os package signature threshold must be > 0")
	}

	return nil
}

func (p *Policy) checkBootMode() error {
	if !p.BootMode.IsValid() {
		return fmt.Errorf("invalid boot mode %d", p.BootMode)
	}

	return nil
}
