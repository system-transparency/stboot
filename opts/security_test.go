package opts

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"testing"
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
			name:    JSONNull,
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

func TestSecurityUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    Security
		errType error
	}{
		{
			name: "All set",
			json: `{
				"min_valid_sigs_required": 1,
				"boot_mode": "network"
			}`,
			want: Security{
				ValidSignatureThreshold: 1,
				BootMode:                NetworkBoot,
			},
			errType: nil,
		},
		{
			name:    "Bad JSON",
			json:    `bad json`,
			want:    Security{},
			errType: &json.SyntaxError{},
		},
		{
			name: "Unset BootMode",
			json: `{
				"min_valid_sigs_required": 1,
				"boot_mode": null
			}`,
			want:    Security{},
			errType: Error(""),
		},
		{
			name: "Unset ValidSignaturesThreshold",
			json: `{
				"min_valid_sigs_required": null,
				"boot_mode": "local"
			}`,
			want:    Security{},
			errType: Error(""),
		},
		{
			name: "ValidSignaturesThreshold set to 0",
			json: `{
				"min_valid_sigs_required": 0,
				"boot_mode": "local"
			}`,
			want:    Security{},
			errType: Error(""),
		},
		{
			name: "Missing field min_valid_sigs_required",
			json: `{
				"boot_mode": "local"
			}`,
			want:    Security{},
			errType: ErrNonNil,
		},
		{
			name: "Missing field boot_mode",
			json: `{
				"min_valid_sigs_required": 1
			}`,
			want:    Security{},
			errType: ErrNonNil,
		},
		{
			name: "Optional version field",
			json: `{
				"version": 0,
				"min_valid_sigs_required": 1,
				"boot_mode": "network"
			}`,
			want: Security{
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
			want:    Security{},
			errType: ErrNonNil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Security
			err := got.UnmarshalJSON([]byte(tt.json))

			assert(t, err, tt.errType, got, tt.want)
		})
	}
}

func TestSecurityJSONLoad(t *testing.T) {
	goodJSON, err := os.ReadFile("testdata/security_good_all_set.json")
	if err != nil {
		t.Fatal(err)
	}

	badJSON, err := os.ReadFile("testdata/security_bad_unset.json")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		loader  SecurityJSON
		errType error
	}{
		{
			name: "Successful loading",
			loader: SecurityJSON{
				Reader: bytes.NewBuffer(goodJSON),
			},
			errType: nil,
		},
		{
			name:    "No source",
			loader:  SecurityJSON{},
			errType: ErrNonNil,
		},
		{
			name: "Bad source",
			loader: SecurityJSON{
				Reader: bytes.NewBufferString("bad"),
			},
			errType: &json.SyntaxError{},
		},
		{
			name: "Bad content",
			loader: SecurityJSON{
				Reader: bytes.NewBuffer(badJSON),
			},
			errType: Error(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.loader.Load(&Opts{})
			assert(t, err, tt.errType, nil, nil)
		})
	}
}

func TestSecurityFileLoad(t *testing.T) {
	goodJSON := "testdata/security_good_all_set.json"
	badJSON := "testdata/security_bad_unset.json"

	tests := []struct {
		name    string
		loader  SecurityFile
		errType error
	}{
		{
			name: "Successful loading",
			loader: SecurityFile{
				Name: goodJSON,
			},
			errType: nil,
		},
		{
			name:    "No file provided",
			loader:  SecurityFile{},
			errType: &fs.PathError{},
		},
		{
			name: "Bad file",
			loader: SecurityFile{
				Name: "not/exist",
			},
			errType: &fs.PathError{},
		},
		{
			name: "Bad content",
			loader: SecurityFile{
				Name: badJSON,
			},
			errType: Error(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.loader.Load(&Opts{})
			assert(t, err, tt.errType, nil, nil)
		})
	}
}
