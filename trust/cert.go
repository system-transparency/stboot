package trust

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/system-transparency/stboot/stlog"
)

func ParseCertificate(pemBytes []byte) (*x509.Certificate, []byte, error) {
	stlog.Debug("Signing root certificate:\n%s", string(pemBytes))
	pemBlock, rest := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, nil, fmt.Errorf("decoding PEM failed")
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing x509 failed: %v", err)
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, nil, fmt.Errorf("certificate has expired or is not yet valid")
	}
	return cert, rest, nil
}
