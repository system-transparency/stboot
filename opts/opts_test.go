package opts

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"testing"

	"system-transparency.org/stboot/host"
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
			name:    "failing Loaders",
			loaders: []Loader{func(o *Opts) error { return ErrFakeLoader }},
			want:    nil,
			errType: ErrNonNil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewOpts(tt.loaders...)
			assert(t, err, tt.errType, got, tt.want)
		})
	}
}

func open(t *testing.T, src string) *bytes.Buffer {
	t.Helper()

	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}

	return bytes.NewBuffer(b)
}

func TestWithSecurity(t *testing.T) {
	tests := []struct {
		name       string
		reader     io.Reader
		wantLoaded bool
		errType    error
	}{
		{
			name:       "Successful loading",
			reader:     open(t, "testdata/security_good_all_set.json"),
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
			reader:     open(t, "testdata/security_bad_unset.json"),
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

func TestWithHostCfg(t *testing.T) {
	tests := []struct {
		name       string
		reader     io.Reader
		wantLoaded bool
		errType    error
	}{
		{
			name:       "Successful loading",
			reader:     open(t, "testdata/host_good_all_set.json"),
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
			reader:     open(t, "testdata/host_bad_unset.json"),
			wantLoaded: false,
			errType:    Error(""),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &Opts{}

			loader := WithHostCfg(tt.reader)
			err := loader(opts)

			isLoaded := opts.HostCfg != host.Config{}
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
	tests := []struct {
		name       string
		reader     io.Reader
		wantLoaded bool
		errType    error
	}{
		{
			name:       "Successful loading",
			reader:     open(t, "testdata/cert.pem"),
			wantLoaded: true,
			errType:    nil,
		},
		{
			name:       "Multiple certificates",
			reader:     open(t, "testdata/certs.pem"),
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
			reader:     open(t, "testdata/key.pem"),
			wantLoaded: false,
			errType:    Error(""),
		},
		{
			name:       "bad PEM bytes",
			reader:     open(t, "testdata/cert_bad_pem.pem"),
			wantLoaded: false,
			errType:    Error(""),
		},
		{
			name:       "bad certificate",
			reader:     open(t, "testdata/cert_bad_cert.pem"),
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
	tests := []struct {
		name       string
		reader     io.Reader
		wantLoaded bool
		errType    error
	}{
		{
			name:       "Successful loading",
			reader:     open(t, "testdata/cert.pem"),
			wantLoaded: true,
			errType:    nil,
		},
		{
			name:       "Multiple certificates",
			reader:     open(t, "testdata/certs.pem"),
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
			reader:     open(t, "testdata/key.pem"),
			wantLoaded: false,
			errType:    Error(""),
		},
		{
			name:       "bad PEM bytes",
			reader:     open(t, "testdata/cert_bad_pem.pem"),
			wantLoaded: false,
			errType:    Error(""),
		},
		{
			name:       "bad certificate",
			reader:     open(t, "testdata/cert_bad_cert.pem"),
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

func assert(t *testing.T, gotErr error, wantErrType, got, want interface{}) {
	t.Helper()

	if wantErrType != nil {
		if gotErr == nil {
			t.Fatal("expect an error")
		}

		ok := errors.As(gotErr, &wantErrType)
		if !ok {
			t.Fatalf("%+v does not wrap expected %+v", gotErr, wantErrType)
		}
	} else if gotErr != nil {
		t.Fatalf("unexpected error: %v", gotErr)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}
