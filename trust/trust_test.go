package trust

import (
	"crypto/x509"
	"errors"
	"io/ioutil"
	"testing"
)

func TestLoadCertificates(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   string
		wantErr error
	}{
		{
			name:  "Test Single cert",
			input: "../testdata/certs/example1_cert.pem",
		},
		{
			name:    "Test Emtpy pem file",
			input:   "../testdata/certs/example_cert empty.pem",
			wantErr: errors.New("parsing x509 failed"),
		},
		/*
			{
				name:  "Multi cert in single file",
				input: "../testdata/certs/example_multi_cert.pem",

				TODO: Generate multi cert pem file
			},
		*/
		{
			name:    "Single cert in multi expect",
			input:   "../testdata/certs/example1_cert.pem",
			wantErr: errors.New("Only one certificate when multiple are expected"),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			var rest []byte
			var cert *x509.Certificate
			var certs []*x509.Certificate
			certdata, err := ioutil.ReadFile(tt.input)
			if err != nil {
				if errors.Is(err, tt.wantErr) {
					return
				}
			}
			lenData := len(certdata)
			for lenData > 0 {
				cert, rest, err = ParseCertificate(certdata)
				if err != nil {
					if errors.Is(err, tt.wantErr) {
						t.Logf("Test passed with: %v", err)
						return
					}
				}
				lenData = len(rest)
				if tt.name == "TestSingleCert" && lenData > 0 {
					if errors.Is(err, tt.wantErr) {
						t.Logf("Test passed with: %v", err)
						return
					}
				}
				if tt.name == "TestMultiCerts" {
					certs = append(certs, cert)
				}
				certdata = rest
			}
			if tt.name == "TestMultiCerts" && len(certs) < 2 {
				err := errors.New("Only one certificate when multiple are expected")
				if errors.Is(err, tt.wantErr) {
					t.Logf("Test passed with: %v", err)
					return
				}
			}
		})
	}
}
