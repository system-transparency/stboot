package opts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
)

// BootMode controls where to load the OS from.
type BootMode int

const (
	BootModeUnset BootMode = iota
	LocalBoot
	NetworkBoot
)

// String implements fmt.Stringer.
func (b BootMode) String() string {
	return [...]string{"unset", "local", "network"}[b]
}

// MarshalJSON implements json.Marshaler.
func (b BootMode) MarshalJSON() ([]byte, error) {
	if b != BootModeUnset {
		return json.Marshal(b.String())
	} else {
		return []byte(JSONNull), nil
	}
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *BootMode) UnmarshalJSON(data []byte) error {
	if string(data) == JSONNull {
		*b = BootModeUnset
	} else {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}

		toId := map[string]BootMode{
			"local":   LocalBoot,
			"network": NetworkBoot,
		}
		bm, ok := toId[s]
		if !ok {
			return &json.UnmarshalTypeError{
				Value: fmt.Sprintf("string %q", s),
				Type:  reflect.TypeOf(b),
			}
		}
		*b = bm
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

	tags := jsonTags(s)
	for _, tag := range tags {
		if _, ok := jsonMap[tag]; !ok {
			return fmt.Errorf("missing json key %q", tag)
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

	if err := SecurityValidation().Validate(&Opts{Security: Security(sec.Alias)}); err != nil {
		return err
	}

	*s = Security(sec.Alias)

	return nil
}

// SecurityCfgJSON initialzes Opts's Security from JSON.
type SecurityJSON struct {
	io.Reader
}

// Load implements Loader.
func (s *SecurityJSON) Load(o *Opts) error {
	var sc Security

	if s.Reader == nil {
		return errors.New("no source provided")
	}

	d := json.NewDecoder(s.Reader)
	if err := d.Decode(&sc); err != nil {
		return err
	}

	o.Security = sc

	return nil
}

// SecurityFile wrapps SecurityJSON.
type SecurityFile struct {
	Name string
}

// Load implements Loader.
func (s *SecurityFile) Load(o *Opts) error {
	f, err := os.Open(s.Name)
	if err != nil {
		return err
	}
	defer f.Close()

	j := SecurityJSON{f}
	if err := j.Load(o); err != nil {
		return err
	}

	return nil
}
