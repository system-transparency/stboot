package ospkg

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestBootModeString(t *testing.T) {
	tests := []struct {
		name string
		mode BootMode
		want string
	}{
		{
			name: "Zero value",
			mode: BootMode(0),
			want: "invalid boot mode",
		},
		{
			name: "String for 'NetworkBoot'",
			mode: NetworkBoot,
			want: "network",
		},
		{
			name: "Invalid value",
			mode: BootMode(100),
			want: "invalid boot mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.mode.String()
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBootModeMarshalJSON(t *testing.T) {
	validtests := []struct {
		name string
		mode BootMode
		want string
	}{
		{
			name: "NetworkBoot",
			mode: NetworkBoot,
			want: `"network"`,
		},
	}

	invalidtests := []struct {
		name string
		mode BootMode
	}{
		{
			name: "zero value",
			mode: BootMode(0),
		},
		{
			name: "unknown value",
			mode: BootMode(100),
		},
	}

	for _, tt := range validtests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.mode.MarshalJSON()
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
			_, err := tt.mode.MarshalJSON()
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

func TestBootModeUnmarshalJSON(t *testing.T) {
	validtests := []struct {
		name string
		json string
		want BootMode
	}{
		{
			name: "network",
			json: `"network"`,
			want: NetworkBoot,
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
			var got BootMode
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
			var got BootMode
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
