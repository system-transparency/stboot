package opts

import (
	"fmt"
	"reflect"
)

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
