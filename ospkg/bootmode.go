package ospkg

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

// BootMode controls where to load the OS from.
type BootMode int

// Supported methods to fetch an OS package.
const (
	NetworkBoot BootMode = iota + 1
)

func fromStr(s string) (BootMode, bool) {
	var fromStr = map[string]BootMode{
		"network": NetworkBoot,
	}

	val, ok := fromStr[s]

	return val, ok
}

func (b BootMode) toStr() (string, bool) {
	var toStr = map[BootMode]string{
		NetworkBoot: "network",
	}

	str, found := toStr[b]

	return str, found
}

// String implements fmt.Stringer.
func (b BootMode) String() string {
	str, ok := b.toStr()
	if !ok {
		return "invalid boot mode"
	}

	return str
}

// MarshalJSON implements json.Marshaler.
func (b BootMode) MarshalJSON() ([]byte, error) {
	str, ok := b.toStr()
	if !ok {
		return nil, &json.MarshalerError{
			Type: reflect.TypeOf(b),
			Err:  errors.New("invalid boot mode"),
		}
	}

	return json.Marshal(str)
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *BootMode) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	bootMode, ok := fromStr(str)
	if !ok {
		return &json.UnmarshalTypeError{
			Value: fmt.Sprintf("string %q", str),
			Type:  reflect.TypeOf(b),
		}
	}

	*b = bootMode

	return nil
}
