package opts

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/system-transparency/stboot/stlog"
)

const (
	ErrMultipleSigningCertificates  = Error("exactly one certificate is expected for signature verification")
	ErrMissingHTTPSRootCertificates = Error("missing HTTPS root certificate(s)")
	ErrNoCertificateFound           = Error("no certifiates found")
)

type SigningRootFile struct {
	File string
}

// Load implements Loader.
func (s *SigningRootFile) Load(opts *Opts) error {
	certs, err := decodePem(s.File)
	if err != nil {
		return err
	}

	if len(certs) > 1 {
		stlog.Debug("%s contains %d certificates")

		return ErrMultipleSigningCertificates
	}

	printLogCerts(certs...)
	opts.SigningRoot = certs[0]

	return nil
}

type HTTPSRootsFile struct {
	File string
}

// Load implements Loader.
func (h *HTTPSRootsFile) Load(opts *Opts) error {
	certs, err := decodePem(h.File)
	if err != nil {
		return err
	}

	if len(certs) < 1 {
		stlog.Debug("%s does not contain a certificate")

		return ErrMissingHTTPSRootCertificates
	}

	printLogCerts(certs...)
	opts.HTTPSRoots = certs

	return nil
}

func decodePem(file string) ([]*x509.Certificate, error) {
	pemBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var (
		roots []*x509.Certificate
		iter  = 1
	)

	for len(pemBytes) > 0 {
		var block *pem.Block

		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		certBytes := block.Bytes

		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			continue
		}

		roots = append(roots, cert)
		iter++
	}

	if len(roots) == 0 {
		return nil, ErrNoCertificateFound
	}

	return roots, nil
}

func printLogCerts(certs ...*x509.Certificate) {
	for _, cert := range certs {
		stlog.Debug("  Version: %d", cert.Version)
		stlog.Debug("  SerialNumber: %s", cert.Issuer.SerialNumber)
		stlog.Debug("  Issuer:")
		stlog.Debug("    Organization: %s, %s", cert.Issuer.Organization, cert.Issuer.Country)
		stlog.Debug("    Common Name: %s", cert.Issuer.CommonName)
		stlog.Debug("  Subject:")
		stlog.Debug("    Organization: %s, %s", cert.Subject.Organization, cert.Subject.Country)
		stlog.Debug("    Common Name: %s", cert.Subject.CommonName)
		stlog.Debug("  Valid from: %s", cert.NotBefore.String())
		stlog.Debug("  Valid until: %s", cert.NotAfter.String())
	}
}
