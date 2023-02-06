package trust

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"system-transparency.org/stboot/internal/jsonutil"
	"system-transparency.org/stboot/stlog"
)

var (
	ErrMissingJSONKey   = errors.New("missing JSON key")
	ErrMissingBootMode  = errors.New("boot mode must be set")
	ErrUnknownBootMode  = errors.New("unknown boot mode")
	ErrInvalidThreshold = errors.New("treshold for valid signatures must be > 0")
)

// BootMode controls where to load the OS from.
type BootMode int

const (
	BootModeUnset BootMode = iota
	NetworkBoot
)

// String implements fmt.Stringer.
func (b BootMode) String() string {
	return [...]string{"unset", "network"}[b]
}

// MarshalJSON implements json.Marshaler.
func (b BootMode) MarshalJSON() ([]byte, error) {
	if b != BootModeUnset {
		return json.Marshal(b.String())
	}

	return []byte(jsonutil.Null), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *BootMode) UnmarshalJSON(data []byte) error {
	if string(data) == jsonutil.Null {
		*b = BootModeUnset
	} else {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}

		toID := map[string]BootMode{
			"network": NetworkBoot,
		}
		bootMode, ok := toID[str]
		if !ok {
			return &json.UnmarshalTypeError{
				Value: fmt.Sprintf("string %q", str),
				Type:  reflect.TypeOf(b),
			}
		}
		*b = bootMode
	}

	return nil
}

// Policy holds security configuration.
type Policy struct {
	ValidSignatureThreshold uint     `json:"min_valid_sigs_required"`
	BootMode                BootMode `json:"boot_mode"`
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
	if p.BootMode == BootModeUnset {
		return ErrMissingBootMode
	}

	return nil
}
