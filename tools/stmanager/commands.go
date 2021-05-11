package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"time"

	"github.com/system-transparency/stboot/pkg/stboot"
)

func createCmd(out, label, pkgURL, kernel, initramfs, cmdline, tboot, tbootArgs string, acms []string) error {
	ospkg, err := stboot.CreateOSPackage(label, pkgURL, kernel, initramfs, cmdline, tboot, tbootArgs, acms)
	if err != nil {
		return err
	}

	archive, err := ospkg.ArchiveBytes()
	if err != nil {
		return err
	}
	descriptor, err := ospkg.DescriptorBytes()
	if err != nil {
		return err
	}

	if err := ioutil.WriteFile(out+stboot.OSPackageExt, archive, 0666); err != nil {
		return err
	}
	if err := ioutil.WriteFile(out+stboot.DescriptorExt, descriptor, 0666); err != nil {
		return err
	}
	return nil
}

func signCmd(pkgPath, privKeyPath, certPath string) error {
	archive, err := ioutil.ReadFile(pkgPath + stboot.OSPackageExt)
	if err != nil {
		return err
	}
	descriptor, err := ioutil.ReadFile(pkgPath + stboot.DescriptorExt)
	if err != nil {
		return err
	}
	ospkg, err := stboot.NewOSPackage(archive, descriptor)
	if err != nil {
		return err
	}

	privKey, err := loadPEM(privKeyPath)
	if err != nil {
		return err
	}

	cert, err := loadPEM(certPath)
	if err != nil {
		return err
	}

	err = ospkg.Sign(privKey, cert)
	if err != nil {
		return err
	}

	descriptor, err = ospkg.DescriptorBytes()
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(pkgPath+stboot.DescriptorExt, descriptor, 0666); err != nil {
		return err
	}
	return nil
}

func showCmd(ospkgPath string) error {
	log.Print("Not yet implemented")
	return nil
}

func keygenCmd(rootCertPath, rootKeyPath string, validFrom, validUntil time.Time, certOut, keyOut string) error {
	var newCert *x509.Certificate
	var newPriv ed25519.PrivateKey
	var err error

	if rootCertPath == "" || rootKeyPath == "" {
		// self signed certificate
		newCert, newPriv, err = newCertWithED25519Keys(nil, nil, validFrom, validUntil)
		if err != nil {
			return fmt.Errorf("keygen: %v", err)
		}

	} else {
		rootCertBlock, err := loadPEM(rootCertPath)
		if err != nil {
			return fmt.Errorf("keygen: %v", err)
		}
		rootCert, err := x509.ParseCertificate(rootCertBlock.Bytes)
		if err != nil {
			return fmt.Errorf("keygen: parsing root cert failed: %v", err)
		}

		rootKeyBlock, err := loadPEM(rootKeyPath)
		if err != nil {
			return fmt.Errorf("keygen: %v", err)
		}
		rootKey, err := x509.ParsePKCS8PrivateKey(rootKeyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("keygen: parsing root key failed: %v", err)
		}

		newCert, newPriv, err = newCertWithED25519Keys(rootCert, &rootKey, validFrom, validUntil)
		if err != nil {
			return fmt.Errorf("keygen: %v", err)
		}
	}

	key, err := x509.MarshalPKCS8PrivateKey(newPriv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %v", err)
	}

	certBlock := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: newCert.Raw,
	}

	keyBlock := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: key,
	}

	if err := writePEM(&certBlock, certOut); err != nil {
		return fmt.Errorf("keygen: failed to write cert: %v", err)
	}

	if err := writePEM(&keyBlock, keyOut); err != nil {
		return fmt.Errorf("keygen: failed to write key: %v", err)
	}

	return nil
}

func newCertWithED25519Keys(rootCert *x509.Certificate, rootKey *interface{}, validFrom, validUntil time.Time) (*x509.Certificate, ed25519.PrivateKey, error) {

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("new cert: failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		NotBefore:    validFrom,
		NotAfter:     validUntil,
	}

	newPub, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("new cert: failed to generate key: %v", err)
	}

	var certBytes []byte

	if rootCert == nil || rootKey == nil {
		// creating self signed certificate
		template.KeyUsage |= x509.KeyUsageCertSign
		template.BasicConstraintsValid = true
		template.IsCA = true
		certBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, newPub, newPriv)
	} else {
		// creating certificate signed by root
		certBytes, err = x509.CreateCertificate(rand.Reader, &template, rootCert, newPub, *rootKey)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("new cert: creation failed: %v", err)
	}

	newCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("new cert: parsing failed: %v", err)
	}

	return newCert, newPriv, nil
}

func loadPEM(path string) (*pem.Block, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, rest := pem.Decode(bytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if len(rest) != 0 {
		return nil, errors.New("unexpected trailing data after PEM block")
	}
	return block, nil
}

func writePEM(b *pem.Block, path string) error {
	pemBytes := pem.EncodeToMemory(b)
	return ioutil.WriteFile(path, pemBytes, 0666)
}
