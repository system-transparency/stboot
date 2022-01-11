package opts

import (
	"reflect"
	"testing"
)

func TestJSONTags(t *testing.T) {
	tests := []struct {
		name string
		in   interface{}
		want []string
	}{
		{
			name: "Only json tags",
			in: struct {
				Field1 string `json:"field1_tag"`
				Field2 int    `json:"field2_tag"`
			}{
				Field1: "foo",
				Field2: 1,
			},
			want: []string{"field1_tag", "field2_tag"},
		},
		{
			name: "Mixed tags",
			in: struct {
				Field1 string `json:"field1_tag"`
				Field2 int    `json:"field2_tag"`
				Field3 string `foo:"field1_tag"`
				Field4 int    `bar:"field2_tag"`
			}{
				Field1: "foo",
				Field2: 1,
				Field3: "bar",
				Field4: 2,
			},
			want: []string{"field1_tag", "field2_tag"},
		},
		{
			name: "Non-json tags",
			in: struct {
				Field1 string `foo:"field1_tag"`
				Field2 int    `bar:"field2_tag"`
			}{
				Field1: "foo",
				Field2: 1,
			},
			want: []string{},
		},
		{
			name: "No tags at all",
			in: struct {
				Field1 string
				Field2 int
			}{
				Field1: "foo",
				Field2: 1,
			},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := jsonTags(tt.in)

			if err != nil {
				t.Fatalf("unexpected error %+v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}

	t.Run("Invalid input", func(t *testing.T) {

		var x int
		_, err := jsonTags(x)
		if err == nil {
			t.Error("expect an error")
		}
	})
}
