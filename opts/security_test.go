package opts

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
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
			name: "String for default value",
			mode: BootModeUnset,
			want: "",
		},
		{
			name: "String for 'LocalBoot'",
			mode: LocalBoot,
			want: "local",
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
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
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
			name: "Marshal empty value",
			mode: BootModeUnset,
			want: `""`,
		},
		{
			name: "Marshal 'LocalBoot'",
			mode: LocalBoot,
			want: `"local"`,
		},
		{
			name: "Marshal 'NetworkBoot'",
			mode: NetworkBoot,
			want: `"network"`,
		},
	}

	for _, tt := range tests {
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
}

func TestSecurityUnmarshalJSON(t *testing.T) {
	tests := []struct {
		json    string
		want    Security
		errType error
	}{
		// version field is not used but accepted ATM.
		{
			json:    "testdata/unmarshal/sec_version.json",
			want:    Security{},
			errType: nil,
		},
		{
			json:    "testdata/unmarshal/sec_min_valid_sign_good.json",
			want:    Security{ValidSignatureThreshold: 1},
			errType: nil,
		},
		{
			json:    "testdata/unmarshal/sec_min_valid_sign_bad_type.json",
			want:    Security{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/unmarshal/sec_min_valid_sign_bad_value.json",
			want:    Security{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/unmarshal/sec_boot_mode_good_1.json",
			want:    Security{BootMode: LocalBoot},
			errType: nil,
		},
		{
			json:    "testdata/unmarshal/sec_boot_mode_good_2.json",
			want:    Security{BootMode: NetworkBoot},
			errType: nil,
		},
		{
			json:    "testdata/unmarshal/sec_boot_mode_bad_type.json",
			want:    Security{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/unmarshal/sec_use_pkg_cache_good.json",
			want:    Security{UsePkgCache: true},
			errType: nil,
		},
		{
			json:    "testdata/unmarshal/sec_boot_mode_bad_value.json",
			want:    Security{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/unmarshal/sec_use_pkg_cache_bad_type_1.json",
			want:    Security{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/unmarshal/sec_use_pkg_cache_bad_type_2.json",
			want:    Security{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/unmarshal/sec_good_unset.json",
			want:    Security{},
			errType: nil,
		},
		{
			json:    "testdata/unmarshal/sec_good_empty.json",
			want:    Security{},
			errType: nil,
		},
		{
			json:    "testdata/unmarshal/sec_bad_key.json",
			want:    Security{},
			errType: errors.New(""),
		},
		{
			json:    "testdata/unmarshal/sec_missing_1_bad.json",
			want:    Security{},
			errType: errors.New(""),
		},
		{
			json:    "testdata/unmarshal/sec_missing_2_bad.json",
			want:    Security{},
			errType: errors.New(""),
		},
		{
			json:    "testdata/unmarshal/sec_missing_3_bad.json",
			want:    Security{},
			errType: errors.New(""),
		},
		{
			json:    "testdata/unmarshal/bad_json.json",
			want:    Security{},
			errType: &json.SyntaxError{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.json, func(t *testing.T) {
			b, err := os.ReadFile(tt.json)
			if err != nil {
				t.Fatal(err)
			}

			sc := &Security{}
			err = sc.UnmarshalJSON(b)

			//check error
			if tt.errType != nil {
				if err == nil {
					t.Fatal("expect an error")
				}

				goterr, wanterr := reflect.TypeOf(err), reflect.TypeOf(tt.errType)
				if goterr != wanterr {
					t.Errorf("got %+v, want %+v", goterr, wanterr)
				}
			}

			// check return value
			got := *sc
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestSecurityJSONLoadNew(t *testing.T) {
	got := NewSecurityJSON(&bytes.Buffer{})
	if got == nil {
		t.Fatal("expect non-nil return")
	}
	if got.src == nil {
		t.Error("expect src to be initialized")
	}
	if got.valitatorSet == nil {
		t.Error("expect valitatorSet to be initialized")
	}
}

func TestSecurityJSONLoad(t *testing.T) {
	goodJSON, err := os.ReadFile("testdata/unmarshal/sec_good_empty.json")
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
				src: bytes.NewBuffer(goodJSON),
				valitatorSet: []validator{func(*Opts) error {
					return nil
				}},
			},
			errType: nil,
		},
		{
			name:    "No source",
			loader:  SecurityJSON{},
			errType: errors.New(""),
		},
		{
			name: "Bad source",
			loader: SecurityJSON{
				src: bytes.NewBufferString("bad"),
			},
			errType: &json.SyntaxError{},
		},
		{
			name: "Bad content",
			loader: SecurityJSON{
				src: bytes.NewBuffer(goodJSON),
				valitatorSet: []validator{func(*Opts) error {
					return InvalidError("dummy validation error")
				}},
			},
			errType: InvalidError(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.loader.Load(&Opts{})

			if tt.errType != nil {
				if err == nil {
					t.Fatal("expect an error")
				}
				goterr, wanterr := reflect.TypeOf(err), reflect.TypeOf(tt.errType)
				if goterr != wanterr {
					t.Errorf("got %+v, want %+v", goterr, wanterr)
				}
			} else {
				if err != nil {
					t.Error("unexpected error")
				}
			}
		})
	}
}

func TestSecurityFileNew(t *testing.T) {
	got := NewSecurityFile("some/name")
	if got == nil {
		t.Fatal("expect non-nil return")
	}
	if reflect.DeepEqual(got.securityJSON, SecurityJSON{}) {
		t.Error("expect securityJSON to be initialized")
	}
}

func TestSecurityFileLoad(t *testing.T) {
	goodJSON := "testdata/unmarshal/sec_good_empty.json"
	badJSON := "testdata/unmarshal/sec_missing_1_bad.json"

	tests := []struct {
		name    string
		loader  SecurityFile
		errType error
	}{
		{
			name: "Successful loading",
			loader: SecurityFile{
				name: goodJSON,
				securityJSON: SecurityJSON{
					valitatorSet: []validator{func(*Opts) error {
						return nil
					}},
				},
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
				name: "not/exist",
			},
			errType: &fs.PathError{},
		},
		{
			name: "Bad content",
			loader: SecurityFile{
				name: badJSON,
			},
			errType: errors.New(""),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.loader.Load(&Opts{})

			if tt.errType != nil {
				if err == nil {
					t.Fatal("expect an error")
				}
				goterr, wanterr := reflect.TypeOf(err), reflect.TypeOf(tt.errType)
				if goterr != wanterr {
					t.Errorf("got %+v, want %+v", goterr, wanterr)
				}
			} else {
				if err != nil {
					t.Error("unexpected error")
				}
			}
		})
	}
}
