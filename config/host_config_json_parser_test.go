package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestHostCfgGoodJSON(t *testing.T) {
	jsons, err := filepath.Glob("testdata/host_*_good.json")
	if err != nil {
		t.Error("Failed to find test config files:", err)
	}

	for _, json := range jsons {
		t.Run(json, func(t *testing.T) {
			b, err := os.ReadFile(json)
			if err != nil {
				t.Fatalf("Failed to read file %s: %v", json, err)
			}

			j := HostCfgJSONParser{bytes.NewReader(b)}
			_, err = j.Parse()

			assertNoError(t, err)
		})
	}
}

func TestHostCfgBadJSON(t *testing.T) {

	typeErrorTests := []struct {
		json string
	}{
		{
			json: "testdata/host_version_bad.json",
		},
		{
			json: "testdata/host_identity_bad.json",
		},
		{
			json: "testdata/host_authentication_bad.json",
		},
	}

	parseErrorTests := []struct {
		key, json string
	}{
		{
			key:  NetworkModeJSONKey,
			json: "testdata/host_network_mode_bad.json",
		},
		{
			key:  HostIPJSONKey,
			json: "testdata/host_host_ip_bad.json",
		},
		{
			key:  DefaultGatewayJSONKey,
			json: "testdata/host_gateway_bad.json",
		},
		{
			key:  DNSServerJSONKey,
			json: "testdata/host_dns_bad.json",
		},
		{
			key:  ProvisioningURLsJSONKey,
			json: "testdata/host_provisioning_urls_bad.json",
		},
		{
			key:  NetworkInterfaceJSONKey,
			json: "testdata/host_network_interface_bad.json",
		},
		{
			key:  HostCfgVersionJSONKey,
			json: "testdata/host_missing_0_bad.json",
		},
		{
			key:  NetworkModeJSONKey,
			json: "testdata/host_missing_1_bad.json",
		},
		{
			key:  HostIPJSONKey,
			json: "testdata/host_missing_2_bad.json",
		},
		{
			key:  DefaultGatewayJSONKey,
			json: "testdata/host_missing_3_bad.json",
		},
		{
			key:  DNSServerJSONKey,
			json: "testdata/host_missing_4_bad.json",
		},
		{
			key:  NetworkInterfaceJSONKey,
			json: "testdata/host_missing_5_bad.json",
		},
		{
			key:  ProvisioningURLsJSONKey,
			json: "testdata/host_missing_6_bad.json",
		},
		{
			key:  IdJSONKey,
			json: "testdata/host_missing_7_bad.json",
		},
		{
			key:  AuthJSONKey,
			json: "testdata/host_missing_8_bad.json",
		},
	}

	for _, test := range typeErrorTests {
		t.Run(test.json, func(t *testing.T) {
			b, err := os.ReadFile(test.json)
			if err != nil {
				t.Fatalf("Failed to read file %s: %v", test.json, err)
			}

			j := HostCfgJSONParser{bytes.NewReader(b)}
			_, err = j.Parse()

			assertTypeError(t, err)
		})
	}

	for _, test := range parseErrorTests {
		t.Run(test.json, func(t *testing.T) {
			b, err := os.ReadFile(test.json)
			if err != nil {
				t.Fatalf("Failed to read file %s: %v", test.json, err)
			}

			j := HostCfgJSONParser{bytes.NewReader(b)}
			_, err = j.Parse()

			assertParseError(t, err, test.key)
		})
	}
}

type badReader struct{}

func (r *badReader) Read(b []byte) (n int, err error) {
	return 0, errors.New("bad read")
}

func TestBadHostCfgJSONParser(t *testing.T) {

	t.Run("Invalid JSON", func(t *testing.T) {
		j := HostCfgJSONParser{bytes.NewBufferString("bad json")}

		_, err := j.Parse()

		if err == nil {
			t.Error("expect error but got none")
		}
	})

	t.Run("Bad reader", func(t *testing.T) {
		j := HostCfgJSONParser{&badReader{}}

		_, err := j.Parse()

		if err == nil {
			t.Error("expect error but got none")
		}
	})
}

func assertTypeError(t *testing.T, err error) {
	t.Helper()
	if _, ok := err.(*TypeError); !ok {
		t.Errorf("want TypeError, got %T", err)
	}
}

func assertParseError(t *testing.T, err error, key string) {
	t.Helper()
	e, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("want ParseError, got %T", err)
	}
	if e.Key != key {
		t.Errorf("want ParseError for JSON key %q, but got: %v", key, err)
	}
}
