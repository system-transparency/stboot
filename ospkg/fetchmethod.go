package ospkg

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

// FetchMethod controls where to load the OS package from.
type FetchMethod int

// Supported methods to fetch an OS package.
const (
	FetchFromNetwork FetchMethod = iota + 1
)

func fromStr(s string) (FetchMethod, bool) {
	var fromStr = map[string]FetchMethod{
		"network": FetchFromNetwork,
	}

	val, ok := fromStr[s]

	return val, ok
}

func (f FetchMethod) toStr() (string, bool) {
	var toStr = map[FetchMethod]string{
		FetchFromNetwork: "network",
	}

	str, found := toStr[f]

	return str, found
}

// String implements fmt.Stringer.
func (f FetchMethod) String() string {
	str, ok := f.toStr()
	if !ok {
		return "invalid fetch method"
	}

	return str
}

// IsValid returns true if b is a defined FetchMethod value.
func (f FetchMethod) IsValid() bool {
	_, ok := f.toStr()

	return ok
}

// MarshalJSON implements json.Marshaler.
func (f FetchMethod) MarshalJSON() ([]byte, error) {
	str, ok := f.toStr()
	if !ok {
		return nil, &json.MarshalerError{
			Type: reflect.TypeOf(f),
			Err:  errors.New("invalid fetch method"),
		}
	}

	return json.Marshal(str)
}

// UnmarshalJSON implements json.Unmarshaler.
func (f *FetchMethod) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return err
	}

	bootMode, ok := fromStr(str)
	if !ok {
		return &json.UnmarshalTypeError{
			Value: fmt.Sprintf("string %q", str),
			Type:  reflect.TypeOf(f),
		}
	}

	*f = bootMode

	return nil
}
