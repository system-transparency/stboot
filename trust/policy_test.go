package trust

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"system-transparency.org/stboot/internal/jsonutil"
)

func TestBootModeString(t *testing.T) {
	tests := []struct {
		name string
		mode BootMode
		want string
	}{
		{
			name: "String for default value",
			mode: BootModeUnset,
			want: "unset",
		},
		{
			name: "String for 'NetworkBoot'",
			mode: NetworkBoot,
			want: "network",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.mode.String()
			assert(t, nil, nil, got, tt.want)
		})
	}
}

func TestBootModeMarshal(t *testing.T) {
	tests := []struct {
		name string
		mode BootMode
		want string
	}{
		{
			name: "BootModeUnset",
			mode: BootModeUnset,
			want: `null`,
		},
		{
			name: "NetworkBoot",
			mode: NetworkBoot,
			want: `"network"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.mode.MarshalJSON()
			assert(t, err, nil, string(got), tt.want)
		})
	}
}

func TestBootModeUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    BootMode
		errType error
	}{
		{
			name:    jsonutil.Null,
			json:    `null`,
			want:    BootModeUnset,
			errType: nil,
		},
		{
			name:    "network",
			json:    `"network"`,
			want:    NetworkBoot,
			errType: nil,
		},
		{
			name:    "wrong type",
			json:    `1`,
			want:    BootModeUnset,
			errType: &json.UnmarshalTypeError{},
		},
		{
			name:    "invalid string",
			json:    `"foo"`,
			want:    BootModeUnset,
			errType: &json.UnmarshalTypeError{},
		},
		{
			name:    "invalid empty string",
			json:    `""`,
			want:    BootModeUnset,
			errType: &json.UnmarshalTypeError{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got BootMode
			err := got.UnmarshalJSON([]byte(tt.json))
			assert(t, err, tt.errType, got, tt.want)
		})
	}
}

func TestPolicyUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    Policy
		errType error
	}{
		{
			name: "All set",
			json: `{
				"min_valid_sigs_required": 1,
				"boot_mode": "network"
			}`,
			want: Policy{
				ValidSignatureThreshold: 1,
				BootMode:                NetworkBoot,
			},
			errType: nil,
		},
		{
			name:    "Bad JSON",
			json:    `bad json`,
			want:    Policy{},
			errType: &json.SyntaxError{},
		},
		{
			name: "Unset BootMode",
			json: `{
				"min_valid_sigs_required": 1,
				"boot_mode": null
			}`,
			want:    Policy{},
			errType: errors.New(""),
		},
		{
			name: "Unset ValidSignaturesThreshold",
			json: `{
				"min_valid_sigs_required": null,
				"boot_mode": "local"
			}`,
			want:    Policy{},
			errType: errors.New(""),
		},
		{
			name: "ValidSignaturesThreshold set to 0",
			json: `{
				"min_valid_sigs_required": 0,
				"boot_mode": "local"
			}`,
			want:    Policy{},
			errType: errors.New(""),
		},
		{
			name: "Missing field min_valid_sigs_required",
			json: `{
				"boot_mode": "local"
			}`,
			want:    Policy{},
			errType: errors.New(""),
		},
		{
			name: "Missing field boot_mode",
			json: `{
				"min_valid_sigs_required": 1
			}`,
			want:    Policy{},
			errType: errors.New(""),
		},
		{
			name: "Optional version field",
			json: `{
				"version": 0,
				"min_valid_sigs_required": 1,
				"boot_mode": "network"
			}`,
			want: Policy{
				ValidSignatureThreshold: 1,
				BootMode:                NetworkBoot,
			},
			errType: nil,
		},
		{
			name: "Unknown field",
			json: `{
				"min_valid_sigs_required": 1,
				"boot_mode": "local",
				"foo": null
			}`,
			want:    Policy{},
			errType: errors.New(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Policy
			err := got.UnmarshalJSON([]byte(tt.json))

			assert(t, err, tt.errType, got, tt.want)
		})
	}
}

func assert(t *testing.T, gotErr error, wantErrType, got, want interface{}) {
	t.Helper()

	if wantErrType != nil {
		if gotErr == nil {
			t.Fatal("expect an error")
		}

		ok := errors.As(gotErr, &wantErrType)
		if !ok {
			t.Fatalf("%+v does not wrap expected %+v", gotErr, wantErrType)
		}
	} else if gotErr != nil {
		t.Fatalf("unexpected error: %v", gotErr)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}
