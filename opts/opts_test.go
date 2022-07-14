package opts

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
)

func TestInvalidError(t *testing.T) {
	msg := "some error message"
	err := Error(msg)

	got := err.Error()
	if got != msg {
		t.Errorf("got %q, want %q", got, msg)
	}
}

const ErrFakeLoader = Error("fake Loader error")

func TestNewOpts(t *testing.T) {
	tests := []struct {
		name    string
		loaders []Loader
		want    *Opts
		errType error
	}{
		{
			name:    "no Loaders",
			loaders: []Loader{},
			want:    &Opts{},
			errType: nil,
		},
		{
			name:    "failing Loader",
			loaders: []Loader{func(o *Opts) error { return ErrFakeLoader }},
			want:    nil,
			errType: ErrNonNil,
		},
	}

	for _, tt := range tests {
		got, err := NewOpts(tt.loaders...)
		assert(t, err, tt.errType, got, tt.want)
	}
}

func TestWithSecurity(t *testing.T) {
	goodSrc, err := os.ReadFile("testdata/security_good_all_set.json")
	if err != nil {
		t.Fatal(err)
	}

	badSrc, err := os.ReadFile("testdata/security_bad_unset.json")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		reader     io.Reader
		wantLoaded bool
		errType    error
	}{
		{
			name:       "Successful loading",
			reader:     bytes.NewBuffer(goodSrc),
			wantLoaded: true,
			errType:    nil,
		},
		{
			name:       "No source",
			reader:     nil,
			wantLoaded: false,
			errType:    ErrNonNil,
		},
		{
			name:       "Bad source",
			reader:     bytes.NewBufferString("bad"),
			wantLoaded: false,
			errType:    &json.SyntaxError{},
		},
		{
			name:       "Bad content",
			reader:     bytes.NewBuffer(badSrc),
			wantLoaded: false,
			errType:    Error(""),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &Opts{}

			loader := WithSecurity(tt.reader)
			err := loader(opts)

			isLoaded := opts.Security != Security{}
			if isLoaded != tt.wantLoaded {
				t.Errorf("Security loaded = %v, want Security to be loaded = %v", isLoaded, tt.wantLoaded)
			}
			assert(t, err, tt.errType, nil, nil)
		})
	}
}

func TestWithSecurityFromFile(t *testing.T) {
	goodSrc := "testdata/security_good_all_set.json"
	badSrc := "testdata/security_bad_unset.json"

	tests := []struct {
		name       string
		file       string
		wantLoaded bool
		errType    error
	}{
		{
			name:       "Successful loading",
			file:       goodSrc,
			wantLoaded: true,
			errType:    nil,
		},
		{
			name:       "No source",
			file:       "",
			wantLoaded: false,
			errType:    ErrNonNil,
		},
		{
			name:       "Bad source",
			file:       "bad",
			wantLoaded: false,
			errType:    &json.SyntaxError{},
		},
		{
			name:       "Bad content",
			file:       badSrc,
			wantLoaded: false,
			errType:    Error(""),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &Opts{}

			loader := WithSecurityFromFile(tt.file)
			err := loader(opts)

			isLoaded := opts.Security != Security{}
			if isLoaded != tt.wantLoaded {
				t.Errorf("Security loaded = %v, want Security to be loaded = %v", isLoaded, tt.wantLoaded)
			}
			assert(t, err, tt.errType, nil, nil)
		})
	}
}

func TestWithHostCfg(t *testing.T) {
	goodSrc, err := os.ReadFile("testdata/host_good_all_set.json")
	if err != nil {
		t.Fatal(err)
	}

	badSrc, err := os.ReadFile("testdata/host_bad_unset.json")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		reader     io.Reader
		wantLoaded bool
		errType    error
	}{
		{
			name:       "Successful loading",
			reader:     bytes.NewBuffer(goodSrc),
			wantLoaded: true,
			errType:    nil,
		},
		{
			name:       "No source",
			reader:     nil,
			wantLoaded: false,
			errType:    ErrNonNil,
		},
		{
			name:       "Bad source",
			reader:     bytes.NewBufferString("bad"),
			wantLoaded: false,
			errType:    &json.SyntaxError{},
		},
		{
			name:       "Bad content",
			reader:     bytes.NewBuffer(badSrc),
			wantLoaded: false,
			errType:    Error(""),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &Opts{}

			loader := WithHostCfg(tt.reader)
			err := loader(opts)

			isLoaded := opts.HostCfg != HostCfg{}
			if isLoaded != tt.wantLoaded {
				t.Errorf("HostCfg loaded = %v, want HostCfg to be loaded = %v", isLoaded, tt.wantLoaded)
			}
			assert(t, err, tt.errType, nil, nil)
		})
	}
}

func TestWithHostCfgFromFile(t *testing.T) {
	goodSrc := "testdata/host_good_all_set.json"
	badSrc := "testdata/host_bad_unset.json"

	tests := []struct {
		name       string
		file       string
		wantLoaded bool
		errType    error
	}{
		{
			name:       "Successful loading",
			file:       goodSrc,
			wantLoaded: true,
			errType:    nil,
		},
		{
			name:       "No source",
			file:       "",
			wantLoaded: false,
			errType:    ErrNonNil,
		},
		{
			name:       "Bad source",
			file:       "bad",
			wantLoaded: false,
			errType:    &json.SyntaxError{},
		},
		{
			name:       "Bad content",
			file:       badSrc,
			wantLoaded: false,
			errType:    Error(""),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &Opts{}

			loader := WithHostCfgFromFile(tt.file)
			err := loader(opts)

			isLoaded := opts.HostCfg != HostCfg{}
			if isLoaded != tt.wantLoaded {
				t.Errorf("HostCfg loaded = %v, want HostCfg to be loaded = %v", isLoaded, tt.wantLoaded)
			}
			assert(t, err, tt.errType, nil, nil)
		})
	}
}

type badReader struct{}

var errBadRead = errors.New("bad read")

func (r badReader) Read(p []byte) (int, error) {
	return 0, errBadRead
}

func TestWithSigningRootCert(t *testing.T) {
	goodCertPEM, err := os.ReadFile("testdata/cert.pem")
	if err != nil {
		t.Fatal(err)
	}

	multipleCertsPEM, err := os.ReadFile("testdata/certs.pem")
	if err != nil {
		t.Fatal(err)
	}

	badCertPEM, err := os.ReadFile("testdata/cert_bad_cert.pem")
	if err != nil {
		t.Fatal(err)
	}

	keyPEM, err := os.ReadFile("testdata/key.pem")
	if err != nil {
		t.Fatal(err)
	}

	badPEM, err := os.ReadFile("testdata/cert_bad_pem.pem")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		reader     io.Reader
		wantLoaded bool
		errType    error
	}{
		{
			name:       "Successful loading",
			reader:     bytes.NewBuffer(goodCertPEM),
			wantLoaded: true,
			errType:    nil,
		},
		{
			name:       "Multiple certificates",
			reader:     bytes.NewBuffer(multipleCertsPEM),
			wantLoaded: false,
			errType:    Error(""),
		},
		{
			name:       "empty PEM",
			reader:     bytes.NewBufferString(""),
			wantLoaded: false,
			errType:    Error(""),
		},
		{
			name:       "nil Reader",
			reader:     nil,
			wantLoaded: false,
			errType:    Error(""),
		},
		{
			name:       "bad Reader",
			reader:     badReader{},
			wantLoaded: false,
			errType:    Error(""),
		},
		{
			name:       "bad PEM type",
			reader:     bytes.NewBuffer(keyPEM),
			wantLoaded: false,
			errType:    Error(""),
		},
		{
			name:       "bad PEM bytes",
			reader:     bytes.NewBuffer(badPEM),
			wantLoaded: false,
			errType:    Error(""),
		},
		{
			name:       "bad certificate",
			reader:     bytes.NewBuffer(badCertPEM),
			wantLoaded: false,
			errType:    Error(""),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &Opts{}

			loader := WithSigningRootCert(tt.reader)
			err := loader(opts)

			isLoaded := opts.SigningRoot != nil
			if isLoaded != tt.wantLoaded {
				t.Errorf("SigningRoot loaded = %v, want SigningRoot to be loaded = %v", isLoaded, tt.wantLoaded)
			}
			assert(t, err, tt.errType, nil, nil)
		})
	}
}

func TestWithHTTPSRootCerts(t *testing.T) {
	goodCertPEM, err := os.ReadFile("testdata/cert.pem")
	if err != nil {
		t.Fatal(err)
	}

	multipleCertsPEM, err := os.ReadFile("testdata/certs.pem")
	if err != nil {
		t.Fatal(err)
	}

	badCertPEM, err := os.ReadFile("testdata/cert_bad_cert.pem")
	if err != nil {
		t.Fatal(err)
	}

	keyPEM, err := os.ReadFile("testdata/key.pem")
	if err != nil {
		t.Fatal(err)
	}

	badPEM, err := os.ReadFile("testdata/cert_bad_pem.pem")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		reader     io.Reader
		wantLoaded bool
		errType    error
	}{
		{
			name:       "Successful loading",
			reader:     bytes.NewBuffer(goodCertPEM),
			wantLoaded: true,
			errType:    nil,
		},
		{
			name:       "Multiple certificates",
			reader:     bytes.NewBuffer(multipleCertsPEM),
			wantLoaded: true,
			errType:    nil,
		},
		{
			name:       "empty PEM",
			reader:     bytes.NewBufferString(""),
			wantLoaded: false,
			errType:    Error(""),
		},
		{
			name:       "nil Reader",
			reader:     nil,
			wantLoaded: false,
			errType:    Error(""),
		},
		{
			name:       "bad Reader",
			reader:     badReader{},
			wantLoaded: false,
			errType:    Error(""),
		},
		{
			name:       "bad PEM type",
			reader:     bytes.NewBuffer(keyPEM),
			wantLoaded: false,
			errType:    Error(""),
		},
		{
			name:       "bad PEM bytes",
			reader:     bytes.NewBuffer(badPEM),
			wantLoaded: false,
			errType:    Error(""),
		},
		{
			name:       "bad certificate",
			reader:     bytes.NewBuffer(badCertPEM),
			wantLoaded: false,
			errType:    Error(""),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &Opts{}

			loader := WithHTTPSRootCerts(tt.reader)
			err := loader(opts)

			isLoaded := opts.HTTPSRoots != nil
			if isLoaded != tt.wantLoaded {
				t.Errorf("SigningRoot loaded = %v, want SigningRoot to be loaded = %v", isLoaded, tt.wantLoaded)
			}
			assert(t, err, tt.errType, nil, nil)
		})
	}
}
