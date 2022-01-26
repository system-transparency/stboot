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
	return [...]string{"", "local", "network"}[b]
}

// MarshalJSON implements json.Marshaler.
func (b BootMode) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.String())
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *BootMode) UnmarshalJSON(data []byte) error {
	toId := map[string]BootMode{
		"":        BootModeUnset,
		"local":   LocalBoot,
		"network": NetworkBoot,
	}

	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	bm, ok := toId[s]
	if !ok {
		return &json.UnmarshalTypeError{
			Value: fmt.Sprintf("string %q", s),
			Type:  reflect.TypeOf(b),
		}
	}
	*b = bm
	return nil
}

// Security groups security configuration.
type Security struct {
	ValidSignatureThreshold uint     `json:"min_valid_sigs_required"`
	BootMode                BootMode `json:"boot_mode"`
}

// UnmarshalJSON implements json.Unmarshaler.
func (s *Security) UnmarshalJSON(data []byte) error {
	var maybeCfg map[string]interface{}
	if err := json.Unmarshal(data, &maybeCfg); err != nil {
		return err
	}

	// check for missing json tags
	tags := jsonTags(s)
	for _, tag := range tags {
		if _, ok := maybeCfg[tag]; !ok {
			return fmt.Errorf("missing json key %q", tag)
		}
	}

	type SecurityAlias Security
	var sc struct {
		Version int
		SecurityAlias
	}
	d := json.NewDecoder(bytes.NewBuffer(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&sc); err != nil {
		return err
	}

	*s = Security(sc.SecurityAlias)
	return nil
}

// SecurityCfgJSON initialzes Opts's HostCfg from JSON.
type SecurityJSON struct {
	src          io.Reader
	valitatorSet []validator
}

// NewSecurityJSON returns a new SecurityJSON with the given io.Reader.
func NewSecurityJSON(src io.Reader) *SecurityJSON {
	return &SecurityJSON{src: src, valitatorSet: sValids}
}

// Load implements Loader.
func (s *SecurityJSON) Load(o *Opts) error {
	var sc Security
	if s.src == nil {
		return errors.New("no source provided")
	}
	d := json.NewDecoder(s.src)
	if err := d.Decode(&sc); err != nil {
		return err
	}
	o.Security = sc
	for _, v := range s.valitatorSet {
		if err := v(o); err != nil {
			o.Security = Security{}
			return err
		}
	}
	return nil
}

// SecurityFile wrapps SecurityJSON.
type SecurityFile struct {
	name         string
	securityJSON SecurityJSON
}

// NewSecurityFile returns a new SecurityFile with the given name.
func NewSecurityFile(name string) *SecurityFile {
	return &SecurityFile{
		name: name,
		securityJSON: SecurityJSON{
			valitatorSet: sValids,
		},
	}
}

// Load implements Loader.
func (s *SecurityFile) Load(o *Opts) error {
	f, err := os.Open(s.name)
	if err != nil {
		return err
	}
	defer f.Close()
	s.securityJSON.src = f
	if err := s.securityJSON.Load(o); err != nil {
		return err
	}
	return nil
}
