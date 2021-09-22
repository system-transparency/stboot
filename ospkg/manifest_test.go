package ospkg

import (
	"bytes"
	"io/ioutil"
	"testing"
)

func TestManifestParsing(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   string
		wantErr error
	}{
		{
			name:  "Parse Manifest",
			input: "../testdata/testOSManifest.json",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data, err := ioutil.ReadFile(tt.input)
			if err != nil {
				t.Errorf("%v", err)
			}

			_, err = OSManifestFromBytes(data)
			if err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}

var (
	wantManifestBytes = []byte{123, 10, 32, 32, 34, 118, 101, 114, 115, 105, 111, 110, 34, 58, 32, 49, 44, 10, 32, 32, 34, 108, 97, 98, 101,
		108, 34, 58, 32, 34, 83, 121, 115, 116, 101, 109, 32, 84, 97, 114, 110, 115, 112, 97, 114, 101, 110, 99, 121, 32, 79, 83, 32,
		80, 97, 99, 107, 97, 103, 101, 32, 100, 117, 109, 109, 121, 95, 107, 101, 114, 110, 101, 108, 46, 98, 105, 110, 34, 44, 10, 32,
		32, 34, 107, 101, 114, 110, 101, 108, 34, 58, 32, 34, 98, 111, 111, 116, 47, 100, 117, 109, 109, 121, 95, 107, 101, 114, 110, 101,
		108, 46, 98, 105, 110, 34, 44, 10, 32, 32, 34, 105, 110, 105, 116, 114, 97, 109, 102, 115, 34, 58, 32, 34, 98, 111, 111, 116, 47,
		100, 117, 109, 109, 121, 95, 105, 110, 105, 116, 114, 97, 109, 102, 115, 46, 98, 105, 110, 34, 44, 10, 32, 32, 34, 99, 109, 100, 108,
		105, 110, 101, 34, 58, 32, 34, 34, 44, 10, 32, 32, 34, 116, 98, 111, 111, 116, 34, 58, 32, 34, 34, 44, 10, 32, 32, 34, 116, 98, 111,
		111, 116, 95, 97, 114, 103, 115, 34, 58, 32, 34, 34, 44, 10, 32, 32, 34, 97, 99, 109, 115, 34, 58, 32, 91, 10, 32, 32, 32, 32, 34, 98,
		111, 111, 116, 47, 97, 99, 109, 115, 47, 100, 117, 109, 109, 121, 95, 97, 99, 109, 46, 98, 105, 110, 34, 10, 32, 32, 93, 10, 125}

	testOSManifest = &OSManifest{
		Version:       1,
		Label:         "System Tarnsparency OS Package dummy_kernel.bin",
		KernelPath:    "boot/dummy_kernel.bin",
		InitramfsPath: "boot/dummy_initramfs.bin",
		Cmdline:       "",
		TbootPath:     "",
		TbootArgs:     "",
		ACMPaths:      []string{"boot/acms/dummy_acm.bin"},
	}
)

func TestManifestToBytes(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   *OSManifest
		want    []byte
		wantErr error
	}{
		{
			name:  "Manifest to Bytes",
			input: testOSManifest,
			want:  wantManifestBytes,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			gotBytes, err := tt.input.Bytes()
			if err != nil {
				t.Errorf("error converting input to bytes")
			}
			if !bytes.Equal(gotBytes, tt.want) {
				t.Errorf("gotBytes and tt.want not equal: \ngotBytes:\t%+v\ntt.want:\t%+v\n", gotBytes, tt.want)
			}
		})
	}
}

func TestManifestValidate(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   *OSManifest
		wantErr error
	}{
		{
			name:  "Validate",
			input: testOSManifest,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.input.Validate(); err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}
