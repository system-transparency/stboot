package opts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"

	"github.com/system-transparency/stboot/stlog"
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
	}

	return []byte(JSONNull), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *BootMode) UnmarshalJSON(data []byte) error {
	if string(data) == JSONNull {
		*b = BootModeUnset
	} else {
		var str string
		if err := json.Unmarshal(data, &str); err != nil {
			return err
		}

		toID := map[string]BootMode{
			"local":   LocalBoot,
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

	tags := jsonTags(s)
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

	if err := SecurityValidation().Validate(&Opts{Security: Security(sec.Alias)}); err != nil {
		return fmt.Errorf("unmarshall security config: %w", err)
	}

	*s = Security(sec.Alias)

	return nil
}

// SecurityCfgJSON initialzes Opts's Security from JSON.
type SecurityJSON struct {
	io.Reader
}

// Load implements Loader.
func (s *SecurityJSON) Load(opts *Opts) error {
	var security Security

	if s.Reader == nil {
		return ErrNoSrcProvided
	}

	d := json.NewDecoder(s.Reader)
	if err := d.Decode(&security); err != nil {
		return err
	}

	opts.Security = security

	return nil
}

// SecurityFile wrapps SecurityJSON.
type SecurityFile struct {
	Name string
}

// Load implements Loader.
func (s *SecurityFile) Load(opts *Opts) error {
	file, err := os.Open(s.Name)
	if err != nil {
		return fmt.Errorf("load security config: %w", err)
	}
	defer file.Close()

	j := SecurityJSON{file}
	if err := j.Load(opts); err != nil {
		return err
	}

	return nil
}
