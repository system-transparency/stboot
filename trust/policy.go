package trust

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"system-transparency.org/stboot/internal/jsonutil"
	"system-transparency.org/stboot/ospkg"
	"system-transparency.org/stboot/stlog"
)

var (
	ErrMissingJSONKey   = errors.New("missing JSON key")
	ErrMissingBootMode  = errors.New("boot mode must be set")
	ErrUnknownBootMode  = errors.New("unknown boot mode")
	ErrInvalidThreshold = errors.New("treshold for valid signatures must be > 0")
)

// Policy holds security configuration.
type Policy struct {
	ValidSignatureThreshold uint           `json:"min_valid_sigs_required"`
	BootMode                ospkg.BootMode `json:"boot_mode"`
}

// UnmarshalJSON implements json.Unmarshaler.
//
// All fields of Policy need to be present in JSON and unknow fiedlds
// are not allowed. Validity is checked according to SecurityValidation.
func (p *Policy) UnmarshalJSON(data []byte) error {
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(data, &jsonMap); err != nil {
		return err
	}

	tags := jsonutil.Tags(p)
	for _, tag := range tags {
		if _, ok := jsonMap[tag]; !ok {
			stlog.Debug("All of security config are expected to be set or unset. Missing json key %q", tag)

			return ErrMissingJSONKey
		}
	}

	type Alias Policy

	var pol struct {
		Version int
		Alias
	}

	d := json.NewDecoder(bytes.NewBuffer(data))
	d.DisallowUnknownFields()

	if err := d.Decode(&pol); err != nil {
		return err
	}

	if err := (*Policy)(&pol.Alias).validate(); err != nil {
		return fmt.Errorf("unmarshall security config: %w", err)
	}

	*p = Policy(pol.Alias)

	return nil
}

func (p *Policy) validate() error {
	var validationSet = []func(*Policy) error{
		checkValidSignatureThreshold,
		checkBootMode,
	}

	for _, f := range validationSet {
		if err := f(p); err != nil {
			return err
		}
	}

	return nil
}

func checkValidSignatureThreshold(p *Policy) error {
	if p.ValidSignatureThreshold < 1 {
		return ErrInvalidThreshold
	}

	return nil
}

func checkBootMode(p *Policy) error {
	if p.BootMode != ospkg.NetworkBoot {
		return ErrUnknownBootMode
	}

	return nil
}
