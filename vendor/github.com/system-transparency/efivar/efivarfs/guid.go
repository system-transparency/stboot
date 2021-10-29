// This code is a somewhat simplified and changed up version of
// github.com/canonical/go-efilib credits go their authors.
// It allows interaction with the efivarfs via u-root which means
// both read and write support.

package efivarfs

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
)

// GUID is the unique identifier of an efivar
type GUID [16]byte

// A first segment
func (guid GUID) A() uint32 {
	return binary.LittleEndian.Uint32(guid[0:4])
}

// B second segment
func (guid GUID) B() uint16 {
	return binary.LittleEndian.Uint16(guid[4:6])
}

// C third segment
func (guid GUID) C() uint16 {
	return binary.LittleEndian.Uint16(guid[6:8])
}

// D fourth segment
func (guid GUID) D() uint16 {
	return binary.BigEndian.Uint16(guid[8:10])
}

// E fifth segment
func (guid GUID) E() [6]uint8 {
	var out [6]uint8
	copy(out[:], guid[10:16])
	return out
}

// String returns the string representation of a GUID
func (guid GUID) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", guid.A(), guid.B(), guid.C(), guid.D(), guid.E())
}

// MakeGUID makes a new GUID from the supplied arguments.
func MakeGUID(a uint32, b, c, d uint16, e [6]uint8) (out GUID) {
	binary.LittleEndian.PutUint32(out[0:4], a)
	binary.LittleEndian.PutUint16(out[4:6], b)
	binary.LittleEndian.PutUint16(out[6:8], c)
	binary.BigEndian.PutUint16(out[8:10], d)
	copy(out[10:], e[:])
	return
}

// ReadGUID reads a EFI_GUID from the supplied io.Reader.
func ReadGUID(r io.Reader) (out GUID, err error) {
	_, err = io.ReadFull(r, out[:])
	return
}

var guidRe = regexp.MustCompile(`\{?([[:xdigit:]]{8})-([[:xdigit:]]{4})-([[:xdigit:]]{4})-([[:xdigit:]]{4})-([[:xdigit:]]{12})\}?`)

func decodeStringUint32(s string) (uint32, error) {
	h, err := hex.DecodeString(s)
	if err != nil {
		return 0, err
	}
	if len(h) > 4 {
		return 0, errors.New("invalid length")
	}
	return binary.BigEndian.Uint32(h), nil
}

func decodeStringUint16(s string) (uint16, error) {
	h, err := hex.DecodeString(s)
	if err != nil {
		return 0, err
	}
	if len(h) > 2 {
		return 0, errors.New("invalid length")
	}
	return binary.BigEndian.Uint16(h), nil
}

// DecodeGUIDString decodes the supplied GUID string. The string must have
// the format "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" and may be surrounded
// by curly braces.
func DecodeGUIDString(s string) (GUID, error) {
	m := guidRe.FindStringSubmatch(s)
	if m == nil {
		return GUID{}, errors.New("invalid format")
	}

	a, _ := decodeStringUint32(m[1])
	b, _ := decodeStringUint16(m[2])
	c, _ := decodeStringUint16(m[3])
	d, _ := decodeStringUint16(m[4])
	e, _ := hex.DecodeString(m[5])

	var e2 [6]uint8
	copy(e2[:], e)
	return MakeGUID(a, b, c, d, e2), nil
}
