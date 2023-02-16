package trust

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"system-transparency.org/stboot/ospkg"
)

func TestPolicyUnmarshalJSON(t *testing.T) {
	validtests := []struct {
		name string
		json string
		want Policy
	}{
		{
			name: "All set",
			json: `{
				"ospkg_signature_threshold": 1,
				"ospkg_fetch_method": "network"
			}`,
			want: Policy{
				SignatureThreshold: 1,
				FetchMethod:        ospkg.FetchFromNetwork,
			},
		},
		{
			name: "Unknown field",
			json: `{
				"ospkg_signature_threshold": 1,
				"ospkg_fetch_method": "network",
				"unknown": "foo"
			}`,
			want: Policy{
				SignatureThreshold: 1,
				FetchMethod:        ospkg.FetchFromNetwork,
			},
		},
	}

	invalidtests := []struct {
		name string
		json string
	}{
		{
			name: "SignaturesThreshold missing",
			json: `{
				"ospkg_fetch_method": "network"
			}`,
		},
		{
			name: "SignaturesThreshold null",
			json: `{
				"ospkg_signature_threshold": null,
				"ospkg_fetch_method": "network"
			}`,
		},
		{
			name: "SignaturesThreshold 0",
			json: `{
				"ospkg_signature_threshold": 0,
				"ospkg_fetch_method": "network"
			}`,
		},
		{
			name: "SignaturesThreshold negative",
			json: `{
				"ospkg_signature_threshold": -1,
				"ospkg_fetch_method": "network"
			}`,
		},
		{
			name: "FetchMethod missing",
			json: `{
				"ospkg_signature_threshold": 1
			}`,
		},
		{
			name: "FetchMethod null",
			json: `{
				"ospkg_signature_threshold": 1,
				"ospkg_fetch_method": null
			}`,
		},
		{
			name: "FetchMethod empty",
			json: `{
				"ospkg_signature_threshold": 1,
				"ospkg_fetch_method": ""
			}`,
		},
		{
			name: "FetchMethod unknown",
			json: `{
				"ospkg_signature_threshold": 1,
				"ospkg_fetch_method": "unknown"
			}`,
		},
	}

	for _, tt := range validtests {
		t.Run(tt.name, func(t *testing.T) {
			var got Policy
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
			var got Policy
			err := got.UnmarshalJSON([]byte(tt.json))
			if err == nil {
				t.Fatalf("expect an error")
			}
			var errType *json.UnmarshalTypeError
			switch {
			case errors.As(err, &errType):
			case errors.Is(err, ErrInvalidPolicy):
			default:
				t.Errorf("expect ErrInvalidPolicy or %T, got %T: %v", errType, err, err)
			}
		})
	}
}
