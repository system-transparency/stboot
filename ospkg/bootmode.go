package ospkg

import (
	"encoding/json"
	"fmt"
	"reflect"

	"system-transparency.org/stboot/internal/jsonutil"
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
