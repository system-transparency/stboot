package config

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"
)

func TestSecurityCfgJSONParser(t *testing.T) {

	goodTests := []struct {
		name string
		json string
		want *SecurityCfg
	}{
		{
			name: "Version field",
			json: fmt.Sprintf(`{"%s": 1}`, SecurityCfgVersionJSONKey),
			want: &SecurityCfg{Version: 1},
		},
		{
			name: "Valid signatures threshold field",
			json: fmt.Sprintf(`{"%s": 1}`, ValidSignatureThresholdJSONKey),
			want: &SecurityCfg{ValidSignatureThreshold: 1},
		},
		{
			name: "Boot mode field 1",
			json: fmt.Sprintf(`{"%s": "%s"}`, BootModeJSONKey, LocalBoot.String()),
			want: &SecurityCfg{BootMode: LocalBoot},
		},
		{
			name: "Boot mode field 2",
			json: fmt.Sprintf(`{"%s": "%s"}`, BootModeJSONKey, NetworkBoot.String()),
			want: &SecurityCfg{BootMode: NetworkBoot},
		},
		{
			name: "Use pkg cache field",
			json: fmt.Sprintf(`{"%s": true}`, UsePkgCacheJSONKey),
			want: &SecurityCfg{UsePkgCache: true},
		},
		{
			name: "No fields",
			json: `{}`,
			want: &SecurityCfg{},
		},
		{
			name: "Empty fields",
			json: fmt.Sprintf(`{"%s": 0, "%s": 0, "%s": ""}`, SecurityCfgVersionJSONKey, ValidSignatureThresholdJSONKey, BootModeJSONKey),
			want: &SecurityCfg{},
		},
	}

	badValueTests := []struct {
		name string
		json string
		key  string
	}{
		{
			name: "Bad boot mode string",
			json: fmt.Sprintf(`{"%s": "some string"}`, BootModeJSONKey),
			key:  BootModeJSONKey,
		},
		{
			name: "Bad valid signature threshold integer",
			json: fmt.Sprintf(`{"%s": -1}`, ValidSignatureThresholdJSONKey),
			key:  ValidSignatureThresholdJSONKey,
		},
	}

	badTypeTests := []struct {
		name string
		json string
	}{
		{
			name: "Bad version type",
			json: fmt.Sprintf(`{"%s": "one"}`, SecurityCfgVersionJSONKey),
		},
		{
			name: "Bad valid signature threshold type",
			json: fmt.Sprintf(`{"%s": "one"}`, ValidSignatureThresholdJSONKey),
		},
		{
			name: "Bad boot mode type",
			json: fmt.Sprintf(`{"%s": 1}`, BootModeJSONKey),
		},
		{
			name: "Bad use pkg cache type 1",
			json: fmt.Sprintf(`{"%s": 1}`, UsePkgCacheJSONKey),
		},
		{
			name: "Bad use pkg cache type 2",
			json: fmt.Sprintf(`{"%s": "true"}`, UsePkgCacheJSONKey),
		},
	}

	for _, tt := range goodTests {
		t.Run(tt.name, func(t *testing.T) {
			j := SecurityCfgJSONParser{bytes.NewBufferString(tt.json)}

			got, err := j.Parse()

			assertNoError(t, err)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %+v, want %+v", got, tt.want)
			}
		})
	}

	for _, tt := range badTypeTests {
		t.Run(tt.name, func(t *testing.T) {
			j := SecurityCfgJSONParser{bytes.NewBufferString(tt.json)}

			_, err := j.Parse()

			assertTypeError(t, err)
		})
	}

	for _, tt := range badValueTests {
		t.Run(tt.name, func(t *testing.T) {
			j := SecurityCfgJSONParser{bytes.NewBufferString(tt.json)}

			_, err := j.Parse()

			assertParseError(t, err, tt.key)
		})
	}

}

func TestBadSecurityCfgJSONParser(t *testing.T) {

	t.Run("Invalid JSON", func(t *testing.T) {
		j := SecurityCfgJSONParser{bytes.NewBufferString("bad json")}

		_, err := j.Parse()

		if err == nil {
			t.Error("expect error but got none")
		}
	})

	t.Run("Bad reader", func(t *testing.T) {
		j := SecurityCfgJSONParser{&badReader{}}

		_, err := j.Parse()

		if err == nil {
			t.Error("expect error but got none")
		}
	})
}
