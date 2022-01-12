package opts

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSecurityCfgGoodJSON(t *testing.T) {
	jsons, err := filepath.Glob("testdata/sec_*_good.json")
	if err != nil {
		t.Error("Failed to find test config files:", err)
	}

	for _, json := range jsons {
		t.Run(json, func(t *testing.T) {
			b, err := os.ReadFile(json)
			if err != nil {
				t.Fatalf("Failed to read file %s: %v", json, err)
			}

			j := SecurityCfgJSONParser{bytes.NewReader(b)}
			_, err = j.Parse()

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestSecurityCfgBadJSON(t *testing.T) {

	typeErrorTests := []struct {
		json string
	}{
		{
			json: "testdata/sec_version_type_bad.json",
		},
		{
			json: "testdata/sec_min_valid_sign_type_bad.json",
		},
		{
			json: "testdata/sec_boot_mode_type_bad.json",
		},
		{
			json: "testdata/sec_use_pkg_cache_1_type_bad.json",
		},
		{
			json: "testdata/sec_use_pkg_cache_2_type_bad.json",
		},
	}

	parseErrorTests := []struct {
		key, json string
	}{
		{
			key:  BootModeJSONKey,
			json: "testdata/sec_boot_mode_bad.json",
		},
		{
			key:  ValidSignatureThresholdJSONKey,
			json: "testdata/sec_min_valid_sign_bad.json",
		},
		{
			key:  SecurityCfgVersionJSONKey,
			json: "testdata/sec_missing_0_bad.json",
		},
		{
			key:  ValidSignatureThresholdJSONKey,
			json: "testdata/sec_missing_1_bad.json",
		},
		{
			key:  BootModeJSONKey,
			json: "testdata/sec_missing_2_bad.json",
		},
		{
			key:  UsePkgCacheJSONKey,
			json: "testdata/sec_missing_3_bad.json",
		},
	}

	for _, tt := range typeErrorTests {
		t.Run(tt.json, func(t *testing.T) {
			b, err := os.ReadFile(tt.json)
			if err != nil {
				t.Fatalf("Failed to read file %s: %v", tt.json, err)
			}

			j := SecurityCfgJSONParser{bytes.NewReader(b)}
			_, err = j.Parse()

			if _, ok := err.(*ParseError); !ok {
				t.Errorf("want ParseError, got %T", err)
			}
		})
	}

	for _, tt := range parseErrorTests {
		t.Run(tt.json, func(t *testing.T) {
			b, err := os.ReadFile(tt.json)
			if err != nil {
				t.Fatalf("Failed to read file %s: %v", tt.json, err)
			}

			j := SecurityCfgJSONParser{bytes.NewReader(b)}
			_, err = j.Parse()

			e, ok := err.(*ParseError)
			if !ok {
				t.Fatalf("want ParseError, got %T", err)
			}
			if e.key != tt.key {
				t.Errorf("want ParseError for JSON key %q, but got: %v", tt.key, err)
			}
		})
	}
}

type badReader struct{}

func (r *badReader) Read(b []byte) (n int, err error) {
	return 0, errors.New("bad read")
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
