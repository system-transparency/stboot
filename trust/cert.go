package trust

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/system-transparency/stboot/stlog"
)

func LoadSigningRoot(path string) (*x509.Certificate, error) {
	pemBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %v", err)
	}
	stlog.Debug("Signing root certificate:\n%s", string(pemBytes))
	pemBlock, rest := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("decoding PEM failed")
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("unexpeceted trailing data")
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing x509 failed: %v", err)
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, fmt.Errorf("certificate has expired or is not yet valid")
	}
	return cert, nil
}

func LoadHTTPSRoots(path string) ([]*x509.Certificate, error) {
	pemBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %v", err)
	}
	var roots []*x509.Certificate
	for len(pemBytes) > 0 {
		var block *pem.Block
		var n = 1
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
		stlog.Debug("HTTPS root certificate %d: ", n)
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
		roots = append(roots, cert)
		n++
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("no certifiates found")
	}
	return roots, nil
}
