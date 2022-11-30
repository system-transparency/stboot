// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package host exposes functionality to interact with the host mashine.
package jsonutil

import (
	"reflect"
)

const Null = "null"

// Tags returns the json tags of struct or struct pointer s.
func Tags(s interface{}) []string {
	tags := make([]string, 0)

	typ := reflect.TypeOf(s)
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}

	if typ.Kind() != reflect.Struct {
		return []string{}
	}

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if tag := field.Tag.Get("json"); tag != "" {
			tags = append(tags, tag)
		}
	}

	return tags
}
