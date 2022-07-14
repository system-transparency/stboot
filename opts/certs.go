package opts

import (
	"crypto/x509"

	"github.com/system-transparency/stboot/stlog"
)

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
