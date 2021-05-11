// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
)

var (
	_bootmodeNameToValue = map[string]bootmode{
		"Local":   Local,
		"Network": Network,
	}

	_bootmodeValueToName = map[bootmode]string{
		Local:   "Local",
		Network: "Network",
	}
)

func init() {
	var v bootmode
	if _, ok := interface{}(v).(fmt.Stringer); ok {
		_bootmodeNameToValue = map[string]bootmode{
			interface{}(Local).(fmt.Stringer).String():   Local,
			interface{}(Network).(fmt.Stringer).String(): Network,
		}
	}
}

// MarshalJSON is generated so bootmode satisfies json.Marshaler.
func (r bootmode) MarshalJSON() ([]byte, error) {
	if s, ok := interface{}(r).(fmt.Stringer); ok {
		return json.Marshal(s.String())
	}
	s, ok := _bootmodeValueToName[r]
	if !ok {
		return nil, fmt.Errorf("invalid bootmode: %d", r)
	}
	return json.Marshal(s)
}

// UnmarshalJSON is generated so bootmode satisfies json.Unmarshaler.
func (r *bootmode) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("bootmode should be a string, got %s", data)
	}
	v, ok := _bootmodeNameToValue[s]
	if !ok {
		return fmt.Errorf("invalid bootmode %q", s)
	}
	*r = v
	return nil
}
