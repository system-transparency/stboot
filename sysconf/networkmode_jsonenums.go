// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sysconf

import (
	"encoding/json"
	"fmt"
)

var (
	_networkmodeNameToValue = map[string]networkmode{
		"Static": Static,
		"DHCP":   DHCP,
	}

	_networkmodeValueToName = map[networkmode]string{
		Static: "Static",
		DHCP:   "DHCP",
	}
)

func init() {
	var v networkmode
	if _, ok := interface{}(v).(fmt.Stringer); ok {
		_networkmodeNameToValue = map[string]networkmode{
			interface{}(Static).(fmt.Stringer).String(): Static,
			interface{}(DHCP).(fmt.Stringer).String():   DHCP,
		}
	}
}

// MarshalJSON is generated so networkmode satisfies json.Marshaler.
func (r networkmode) MarshalJSON() ([]byte, error) {
	if s, ok := interface{}(r).(fmt.Stringer); ok {
		return json.Marshal(s.String())
	}
	s, ok := _networkmodeValueToName[r]
	if !ok {
		return nil, fmt.Errorf("invalid networkmode: %d", r)
	}
	return json.Marshal(s)
}

// UnmarshalJSON is generated so networkmode satisfies json.Unmarshaler.
func (r *networkmode) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("networkmode should be a string, got %s", data)
	}
	v, ok := _networkmodeNameToValue[s]
	if !ok {
		return fmt.Errorf("invalid networkmode %q", s)
	}
	*r = v
	return nil
}
