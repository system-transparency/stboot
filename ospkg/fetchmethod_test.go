package ospkg

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestFetchMethodString(t *testing.T) {
	tests := []struct {
		name   string
		method FetchMethod
		want   string
	}{
		{
			name:   "Zero value",
			method: FetchMethod(0),
			want:   "invalid fetch method",
		},
		{
			name:   "String for 'FetchFromNetwork'",
			method: FetchFromNetwork,
			want:   "network",
		},
		{
			name:   "String for 'FetchFromInitramfs'",
			method: FetchFromInitramfs,
			want:   "initramfs",
		},
		{
			name:   "Invalid value",
			method: FetchMethod(100),
			want:   "invalid fetch method",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.method.String()
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFetchMethodMarshalJSON(t *testing.T) {
	validtests := []struct {
		name   string
		method FetchMethod
		want   string
	}{
		{
			name:   "Network",
			method: FetchFromNetwork,
			want:   `"network"`,
		},
		{
			name:   "Initramfs",
			method: FetchFromInitramfs,
			want:   `"initramfs"`,
		},
	}

	invalidtests := []struct {
		name   string
		method FetchMethod
	}{
		{
			name:   "zero value",
			method: FetchMethod(0),
		},
		{
			name:   "unknown value",
			method: FetchMethod(100),
		},
	}

	for _, tt := range validtests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.method.MarshalJSON()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}

	for _, tt := range invalidtests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.method.MarshalJSON()
			if err == nil {
				t.Fatalf("expect an error")
			}
			var marshalerError *json.MarshalerError
			if !errors.As(err, &marshalerError) {
				t.Errorf("want error of type %T, got %T", marshalerError, err)
			}
		})
	}
}

func TestFetchMethodUnmarshalJSON(t *testing.T) {
	validtests := []struct {
		name string
		json string
		want FetchMethod
	}{
		{
			name: "network",
			json: `"network"`,
			want: FetchFromNetwork,
		},
		{
			name: "initramfs",
			json: `"initramfs"`,
			want: FetchFromInitramfs,
		},
	}

	invalidtests := []struct {
		name string
		json string
	}{
		{
			name: "wrong type",
			json: `1`,
		},
		{
			name: "unknown string",
			json: `"foo"`,
		},
		{
			name: "empty string",
			json: `""`,
		},
		{
			name: "JSON null",
			json: `null`,
		},
	}

	for _, tt := range validtests {
		t.Run(tt.name, func(t *testing.T) {
			var got FetchMethod
			err := got.UnmarshalJSON([]byte(tt.json))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}

	for _, tt := range invalidtests {
		t.Run(tt.name, func(t *testing.T) {
			var got FetchMethod
			err := got.UnmarshalJSON([]byte(tt.json))
			if err == nil {
				t.Fatalf("expect an error")
			}
			var unmarshalError *json.UnmarshalTypeError
			if !errors.As(err, &unmarshalError) {
				t.Errorf("want error of type %T, got %T", unmarshalError, err)
			}
		})
	}
}
