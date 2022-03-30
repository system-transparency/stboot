package opts

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"github.com/system-transparency/stboot/stlog"
)

type SigningRootFile struct {
	File string
}

// Load implements Loader
func (s *SigningRootFile) Load(o *Opts) error {
	certs, err := decodePem(s.File)
	if err != nil {
		return err
	}
	if len(certs) > 1 {
		return fmt.Errorf("too many certificates in pem file: %s. Got: %d, Want: 1", s.File, len(certs))
	}
	printLogCerts(certs...)
	o.SigningRoot = certs[0]
	return nil
}

type HttpsRootsFile struct {
	File string
}

// Load implements Loader
func (h *HttpsRootsFile) Load(o *Opts) error {
	certs, err := decodePem(h.File)
	if err != nil {
		return err
	}
	if len(certs) < 1 {
		return fmt.Errorf("not enough certificates in pem file: %s. Got: %d, Want: >=1", h.File, len(certs))
	}
	printLogCerts(certs...)
	o.HttpsRoots = certs
	return nil
}

func decodePem(file string) ([]*x509.Certificate, error) {
	pemBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	var roots []*x509.Certificate
	var n = 1
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
		n++
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("no certifiates found")
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
