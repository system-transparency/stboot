package opts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"

	"git.glasklar.is/system-transparency/core/stboot/internal/jsonutil"
	"git.glasklar.is/system-transparency/core/stboot/stlog"
)

const (
	ErrMissingBootMode  = Error("boot mode must be set")
	ErrUnknownBootMode  = Error("unknown boot mode")
	ErrInvalidThreshold = Error("Treshold for valid signatures must be > 0")
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

// Security groups security configuration.
type Security struct {
	ValidSignatureThreshold uint     `json:"min_valid_sigs_required"`
	BootMode                BootMode `json:"boot_mode"`
}

// UnmarshalJSON implements json.Unmarshaler.
//
// All fields of Security need to be present in JSON and unknow fiedlds
// are not allowed. Validity is checked according to SecurityValidation.
func (s *Security) UnmarshalJSON(data []byte) error {
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(data, &jsonMap); err != nil {
		return err
	}

	tags := jsonutil.Tags(s)
	for _, tag := range tags {
		if _, ok := jsonMap[tag]; !ok {
			stlog.Debug("All of security config are expected to be set or unset. Missing json key %q", tag)

			return ErrMissingJSONKey
		}
	}

	type Alias Security

	var sec struct {
		Version int
		Alias
	}

	d := json.NewDecoder(bytes.NewBuffer(data))
	d.DisallowUnknownFields()

	if err := d.Decode(&sec); err != nil {
		return err
	}

	if err := (*Security)(&sec.Alias).validate(); err != nil {
		return fmt.Errorf("unmarshall security config: %w", err)
	}

	*s = Security(sec.Alias)

	return nil
}

func (s *Security) validate() error {
	var validationSet = []func(*Security) error{
		checkValidSignatureThreshold,
		checkBootMode,
	}

	for _, f := range validationSet {
		if err := f(s); err != nil {
			return err
		}
	}

	return nil
}

func checkValidSignatureThreshold(cfg *Security) error {
	if cfg.ValidSignatureThreshold < 1 {
		return ErrInvalidThreshold
	}

	return nil
}

func checkBootMode(cfg *Security) error {
	if cfg.BootMode == BootModeUnset {
		return ErrMissingBootMode
	}

	return nil
}
