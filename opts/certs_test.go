package opts

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDecodePem(t *testing.T) {
	for _, tt := range []struct {
		name    string
		file    string
		wantErr error
	}{
		{
			name:    "SingleCert_not_exist",
			file:    "file-not-exist.pem",
			wantErr: unix.ENOENT,
		},
		{
			name: "SingleCert_success",
			file: "testdata/testcert.pem",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodePem(tt.file)
			if err != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("decodePem(%s)= cert, %q, Want cert, %v", tt.file, err, tt.wantErr)
			}
		})
	}
}

func TestCertFileLoader(t *testing.T) {
	for _, tt := range []struct {
		name    string
		file    string
		wantErr error
	}{
		{
			name: "SingleCert_success",
			file: "testdata/testcert.pem",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			certLoader := &HTTPSRootsFile{tt.file}
			if _, err := NewOpts(certLoader); err != nil {
				t.Error(err)
			}
		})
		t.Run(tt.name, func(t *testing.T) {
			certLoader := &SigningRootFile{tt.file}
			if _, err := NewOpts(certLoader); err != nil {
				t.Error(err)
			}
		})
	}
}
