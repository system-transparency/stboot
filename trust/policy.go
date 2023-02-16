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
	SignatureThreshold int               `json:"ospkg_signature_threshold"`
	FetchMethod        ospkg.FetchMethod `json:"ospkg_fetch_method"`
}

// policy is used as an alias in Policy.UnmarshalJSON.
type policy struct {
	SignatureThreshold int               `json:"ospkg_signature_threshold"`
	FetchMethod        ospkg.FetchMethod `json:"ospkg_fetch_method"`
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

	p.SignatureThreshold = alias.SignatureThreshold
	p.FetchMethod = alias.FetchMethod

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
	if p.SignatureThreshold < 1 {
		return errors.New("os package signature threshold must be > 0")
	}

	return nil
}

func (p *Policy) checkBootMode() error {
	if !p.FetchMethod.IsValid() {
		return fmt.Errorf("invalid boot mode %d", p.FetchMethod)
	}

	return nil
}
