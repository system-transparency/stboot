package trust

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"system-transparency.org/stboot/ospkg"
)

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
				BootMode:                ospkg.NetworkBoot,
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
				BootMode:                ospkg.NetworkBoot,
			},
			errType: nil,
		},
		{
			name: "Unknown field",
			json: `{
				"min_valid_sigs_required": 1,
				"boot_mode": "local","system-transparency.org/stboot/ospkg"
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
