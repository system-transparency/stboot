package opts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
)

// BootMode controlls where to load the OS from
type BootMode int

const (
	BootModeUnset BootMode = iota
	LocalBoot
	NetworkBoot
)

// String implements fmt.Stringer
func (b BootMode) String() string {
	return [...]string{"", "local", "network"}[b]
}

// MarshalJSON implements json.Marshaler
func (b BootMode) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.String())
}

// UnmarshalJSON implements json.Unmarshaler
func (b *BootMode) UnmarshalJSON(data []byte) error {
	toId := map[string]BootMode{
		"":        BootModeUnset,
		"local":   LocalBoot,
		"network": NetworkBoot,
	}

	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
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

// SecurityCfg groups security specific configuration
type SecurityCfg struct {
	ValidSignatureThreshold uint     `json:"min_valid_sigs_required"`
	BootMode                BootMode `json:"boot_mode"`
	UsePkgCache             bool     `json:"use_ospkg_cache"`
}

func jsonTags(s interface{}) ([]string, error) {
	tags := make([]string, 0)

	var typ reflect.Type
	typ = reflect.TypeOf(s)
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}

	if typ.Kind() != reflect.Struct {
		return nil, fmt.Errorf("expect struct or pointer to struct")
	}

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if tag := field.Tag.Get("json"); tag != "" {
			tags = append(tags, tag)
		}
	}
	return tags, nil
}

// UnmarshalJSON implements json.Unmarshaler
func (s *SecurityCfg) UnmarshalJSON(data []byte) error {
	var maybeCfg map[string]interface{}
	if err := json.Unmarshal(data, &maybeCfg); err != nil {
		return err
	}

	// check for missing json tags
	tags, _ := jsonTags(s)
	for _, tag := range tags {
		if _, ok := maybeCfg[tag]; !ok {
			return fmt.Errorf("missing json key %q", tag)
		}
	}

	type SecurityCfgAlias SecurityCfg
	var sc struct {
		Version int
		SecurityCfgAlias
	}
	d := json.NewDecoder(bytes.NewBuffer(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&sc); err != nil {
		return err
	}

	*s = SecurityCfg(sc.SecurityCfgAlias)
	return nil
}

type SecurityCfgJSONParser struct {
	r io.Reader
}

func (s *SecurityCfgJSONParser) Parse() (*Opts, error) {
	var sc SecurityCfg
	d := json.NewDecoder(s.r)
	if err := d.Decode(&sc); err != nil {
		return nil, err
	}

	return &Opts{SecurityCfg: sc}, nil
}
