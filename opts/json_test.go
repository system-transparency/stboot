package opts

import (
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
		{
			name: "Invalid input",
			in:   3,
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := jsonTags(tt.in)
			assert(t, nil, nil, got, tt.want)
		})
	}
}
