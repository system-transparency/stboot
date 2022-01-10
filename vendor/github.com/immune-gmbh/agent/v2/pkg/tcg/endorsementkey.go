package tcg

import (
	"crypto/x509"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	log "github.com/sirupsen/logrus"
)

var (
	// Default EK template defined in:
	// https://trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
	defaultEKTemplate = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagAdminWithPolicy | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: []byte{
			0x83, 0x71, 0x97, 0x67, 0x44, 0x84,
			0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
			0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52,
			0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
			0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
			0x69, 0xAA,
		},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:     2048,
			ExponentRaw: 0,
			ModulusRaw:  make([]byte, 256),
		},
	}
	// For swtpm
	defaultEKTemplateIndex    = tpmutil.Handle(0x01c00004)
	defaultEKCertificateIndex = tpmutil.Handle(0x01c00002)
	defaultEKHandle           = tpmutil.Handle(0x81010001)
)

func (a *TCGAnchor) ReadEKCertificate() (*x509.Certificate, error) {
	return doReadEKCertificate(a.Conn, defaultEKCertificateIndex)
}

func doReadEKCertificate(conn io.ReadWriteCloser, handle tpmutil.Handle) (*x509.Certificate, error) {
	blob, err := tpm2.NVRead(conn, handle)
	if err != nil {
		log.Debugf("Cannot read EK certificate: %s", err)
		return nil, err
	}

	certRef, err := x509.ParseCertificate(blob)
	if err != nil {
		log.Debugf("Cannot parse EK certificate: %s", err)
		return nil, err
	}

	return certRef, nil
}

func (a *TCGAnchor) GetEndorsementKey() (Handle, tpm2.Public, error) {
	ekPublic, err := loadEK(a.Conn, defaultEKHandle)
	if err != nil {
		log.Debugf("No EK found at 0x%x, trying to generate it.", defaultEKHandle)

		defaultEKHandle, ekPublic, err = generateAndLoadEK(a.Conn, &defaultEKTemplateIndex)
		if err != nil {
			log.Debugf("No EK template found at 0x%x, using default template", defaultEKTemplateIndex)

			// Retry with default EK template
			defaultEKHandle, ekPublic, err = generateAndLoadEK(a.Conn, nil)
			if err != nil {
				log.Debugf("Failed to load EK: %s. Tried to read EK template from 0x%x and to use the default EK template. Maybe the template it at a non-standard NV index?", err, defaultEKTemplateIndex)
				return nil, tpm2.Public{}, err
			}
		}
	}

	return &TCGHandle{Handle: defaultEKHandle}, ekPublic, nil
}

func loadEK(conn io.ReadWriteCloser, handle tpmutil.Handle) (tpm2.Public, error) {
	pub, _, _, err := tpm2.ReadPublic(conn, handle)
	return pub, err
}

func generateAndLoadEK(conn io.ReadWriteCloser, template *tpmutil.Handle) (tpmutil.Handle, tpm2.Public, error) {
	var handle tpmutil.Handle
	var pub tpm2.Public
	var err error

	if template != nil {
		tmpl, err := tpm2.NVRead(conn, *template)
		if err != nil {
			log.Debugf("Failed to fetch EK template: %v", err)
			return handle, pub, err
		}

		pub, err = tpm2.DecodePublic(tmpl)
		if err != nil {
			log.Debugf("EK template is not a TPM2_PUBLIC: %v", err)
			return handle, pub, err
		}
	}

	handle, _, err = tpm2.CreatePrimary(conn, tpm2.HandleEndorsement, tpm2.PCRSelection{}, "", "", defaultEKTemplate)
	if err != nil {
		log.Debugf("Failed to create EK: %v", err)
		return handle, pub, err
	}

	pub, _, _, err = tpm2.ReadPublic(conn, handle)
	if err != nil {
		log.Debugf("Failed to read EKs public part: %v", err)
		return handle, pub, err
	}

	return handle, pub, nil
}
