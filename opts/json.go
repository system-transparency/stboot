package opts

import (
	"reflect"
)

const JSONNull = "null"

func jsonTags(s interface{}) []string {
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
