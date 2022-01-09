package opts

import (
	"bytes"
	"encoding/json"
	"errors"
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

func TestSecurityCfgUnmarshalJSON(t *testing.T) {

	tests := []struct {
		json    string
		want    SecurityCfg
		errType error
	}{
		// version field is not used but accepted ATM.
		{
			json:    "testdata/sec_version.json",
			want:    SecurityCfg{},
			errType: nil,
		},
		{
			json:    "testdata/sec_min_valid_sign_good.json",
			want:    SecurityCfg{ValidSignatureThreshold: 1},
			errType: nil,
		},
		{
			json:    "testdata/sec_min_valid_sign_bad_type.json",
			want:    SecurityCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/sec_min_valid_sign_bad_value.json",
			want:    SecurityCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/sec_boot_mode_good_1.json",
			want:    SecurityCfg{BootMode: LocalBoot},
			errType: nil,
		},
		{
			json:    "testdata/sec_boot_mode_good_2.json",
			want:    SecurityCfg{BootMode: NetworkBoot},
			errType: nil,
		},
		{
			json:    "testdata/sec_boot_mode_bad_type.json",
			want:    SecurityCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/sec_use_pkg_cache_good.json",
			want:    SecurityCfg{UsePkgCache: true},
			errType: nil,
		},
		{
			json:    "testdata/sec_boot_mode_bad_value.json",
			want:    SecurityCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/sec_use_pkg_cache_bad_type_1.json",
			want:    SecurityCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/sec_use_pkg_cache_bad_type_2.json",
			want:    SecurityCfg{},
			errType: &json.UnmarshalTypeError{},
		},
		{
			json:    "testdata/sec_good_unset.json",
			want:    SecurityCfg{},
			errType: nil,
		},
		{
			json:    "testdata/sec_good_empty.json",
			want:    SecurityCfg{},
			errType: nil,
		},
		{
			json:    "testdata/sec_bad_key.json",
			want:    SecurityCfg{},
			errType: errors.New(""),
		},
		{
			json:    "testdata/sec_missing_1_bad.json",
			want:    SecurityCfg{},
			errType: errors.New(""),
		},
		{
			json:    "testdata/sec_missing_2_bad.json",
			want:    SecurityCfg{},
			errType: errors.New(""),
		},
		{
			json:    "testdata/sec_missing_3_bad.json",
			want:    SecurityCfg{},
			errType: errors.New(""),
		},
		{
			json:    "testdata/bad_json.json",
			want:    SecurityCfg{},
			errType: &json.SyntaxError{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.json, func(t *testing.T) {
			b, err := os.ReadFile(tt.json)
			if err != nil {
				t.Fatal(err)
			}

			sc := &SecurityCfg{}
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

type badReader struct{}

func (r *badReader) Read(b []byte) (n int, err error) {
	return 0, errors.New("bad read")
}

func TestSecurityCfgJSONParserParse(t *testing.T) {
	t.Run("Good JSON", func(t *testing.T) {
		b, err := os.ReadFile("testdata/sec_good_empty.json")
		if err != nil {
			t.Fatal(err)
		}
		j := SecurityCfgJSONParser{bytes.NewBuffer(b)}

		opts, err := j.Parse()
		if err != nil {
			t.Fatalf("uexpected error")
		}

		want := Opts{}
		got := *opts
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %+v, want %+v", got, want)
		}

	})

	t.Run("Invalid JSON", func(t *testing.T) {
		j := SecurityCfgJSONParser{bytes.NewBufferString("bad json")}

		_, err := j.Parse()

		if err == nil {
			t.Error("expect an error")
		}
	})

	t.Run("Bad reader", func(t *testing.T) {
		j := SecurityCfgJSONParser{&badReader{}}

		_, err := j.Parse()

		if err == nil {
			t.Error("expect an error")
		}
	})
}
