package opts

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

var (
	ErrNoSrcProvided         = errors.New("no/empty source provided")
	ErrMultipleSigningCerts  = errors.New("exactly one root certificate is expected")
	ErrMissingHTTPSRootCerts = errors.New("missing HTTPS root certificate(s)")
	ErrNoCertificateFound    = errors.New("no certifiates found")
)

// OptsVersion is the Version of Opts. It can be used for validation.
const OptsVersion int = 0

// Loader modifys the provided *Opts instance.
type Loader func(*Opts) error

// Opts controls the operation of stboot.
type Opts struct {
	Version int
	Security
	HostCfg
	SigningRoot *x509.Certificate
	HTTPSRoots  []*x509.Certificate
}

// NewOpts return a new Opts initialized by the provided Loaders.
func NewOpts(loaders ...Loader) (*Opts, error) {
	opts := &Opts{Version: OptsVersion}
	for _, l := range loaders {
		if err := l(opts); err != nil {
			return nil, fmt.Errorf("new opts: %w", err)
		}
	}

	return opts, nil
}

func WithSecurity(reader io.Reader) Loader {
	return func(opts *Opts) error {
		var security Security

		if reader == nil {
			return ErrNoSrcProvided
		}

		if err := decodeJSON(reader, &security); err != nil {
			return err
		}

		opts.Security = security

		return nil
	}
}

func WithHostCfg(reader io.Reader) Loader {
	return func(opts *Opts) error {
		var hostCfg HostCfg

		if reader == nil {
			return ErrNoSrcProvided
		}

		if err := decodeJSON(reader, &hostCfg); err != nil {
			return err
		}

		opts.HostCfg = hostCfg

		return nil
	}
}

func WithSigningRootCert(reader io.Reader) Loader {
	return func(opts *Opts) error {
		if reader == nil {
			return ErrNoSrcProvided
		}

		pemBytes, err := io.ReadAll(reader)
		if err != nil {
			return err
		}

		certs, err := decodePEM(pemBytes)
		if err != nil {
			return err
		}

		if len(certs) > 1 {
			return ErrMultipleSigningCerts
		}

		opts.SigningRoot = certs[0]

		return nil
	}
}

func WithHTTPSRootCerts(reader io.Reader) Loader {
	return func(opts *Opts) error {
		if reader == nil {
			return ErrNoSrcProvided
		}

		pemBytes, err := io.ReadAll(reader)
		if err != nil {
			return err
		}

		certs, err := decodePEM(pemBytes)
		if err != nil {
			return err
		}

		opts.HTTPSRoots = certs

		return nil
	}
}

func decodeJSON(r io.Reader, i interface{}) error {
	d := json.NewDecoder(r)
	if err := d.Decode(i); err != nil {
		return err
	}

	return nil
}

func decodePEM(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for len(pemBytes) > 0 {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			pemBytes = rest

			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}

		certs = append(certs, cert)
		pemBytes = rest
	}

	if len(certs) == 0 {
		return nil, ErrNoCertificateFound
	}

	return certs, nil
}
