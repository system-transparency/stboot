// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ospkg

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"path/filepath"

	"github.com/system-transparency/stboot/stlog"
	"github.com/system-transparency/stboot/trust"
	"github.com/u-root/u-root/pkg/boot"
)

const (
	// DefaultOSPackageName is the file name of the archive, which is expected to contain
	// the stboot configuration file along with the corresponding files
	DefaultOSPackageName string = "ospkg.zip"
	// OSPackageExt is the file extension of OS packages
	OSPackageExt string = ".zip"

	bootfilesDir string = "boot"
)

// OSPackage represents an OS package ZIP archive and and related data.
type OSPackage struct {
	raw        []byte
	descriptor *Descriptor
	hash       [32]byte
	manifest   *OSManifest
	kernel     []byte
	initramfs  []byte
	signer     trust.Signer
	isVerified bool
}

// CreateOSPackage constructs a OSPackage from the passed files.
func CreateOSPackage(label, pkgURL, kernel, initramfs, cmdline string) (*OSPackage, error) {
	var m = &OSManifest{
		Version:   ManifestVersion,
		Label:     label,
		Cmdline:   cmdline,
	}

	var d = &Descriptor{
		Version: DescriptorVersion,
	}

	var osp = &OSPackage{
		descriptor: d,
		manifest:   m,
		signer:     trust.ED25519Signer{},
		isVerified: false,
	}

	var err error
	if pkgURL != "" {
		u, err := url.Parse(pkgURL)
		if err != nil {
			return nil, fmt.Errorf("os package: OS package URL: %v", err)
		}
		if u.Scheme == "" || u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("os package: OS package URL: missing or unsupported scheme in %s", u.String())
		}
		osp.descriptor.PkgURL = pkgURL
	}

	if kernel != "" {
		osp.kernel, err = ioutil.ReadFile(kernel)
		if err != nil {
			return nil, fmt.Errorf("os package: kernel path: %v", err)
		}
		osp.manifest.KernelPath = filepath.Join(bootfilesDir, filepath.Base(kernel))
	}

	if initramfs != "" {
		osp.initramfs, err = ioutil.ReadFile(initramfs)
		if err != nil {
			return nil, fmt.Errorf("os package: initramfs path: %v", err)
		}
		osp.manifest.InitramfsPath = filepath.Join(bootfilesDir, filepath.Base(initramfs))
	}

	if err := osp.validate(); err != nil {
		return nil, err
	}

	return osp, nil
}

// NewOSPackage constructs a new OSPackage initialized with raw bytes
// and valid internal state.
func NewOSPackage(archiveZIP, descriptorJSON []byte) (*OSPackage, error) {

	// check archive
	_, err := zip.NewReader(bytes.NewReader(archiveZIP), int64(len(archiveZIP)))
	if err != nil {
		return nil, fmt.Errorf("os package: %v", err)
	}
	// check descriptor
	descriptor, err := DescriptorFromBytes(descriptorJSON)
	if err != nil {
		if err != nil {
			return nil, fmt.Errorf("os package: %v", err)
		}
	}

	if err = descriptor.Validate(); err != nil {
		return nil, fmt.Errorf("os package: invalid descriptor: %v", err)
	}

	osp := OSPackage{
		raw:        archiveZIP,
		descriptor: descriptor,
		signer:     trust.ED25519Signer{},
		isVerified: false,
	}

	osp.hash, err = calculateHash(osp.raw)
	if err != nil {
		return nil, fmt.Errorf("os package: calculate hash failed: %v", err)
	}

	return &osp, nil
}

func (osp *OSPackage) validate() error {
	// manifest
	if osp.manifest == nil {
		return fmt.Errorf("missing manifest data")
	} else if err := osp.manifest.Validate(); err != nil {
		return err
	}
	// descriptor
	if osp.descriptor == nil {
		return fmt.Errorf("missing descriptor data")
	} else if err := osp.descriptor.Validate(); err != nil {
		return err
	}
	// kernel is mandatory
	if len(osp.kernel) == 0 {
		return fmt.Errorf("missing kernel")
	}
	// initrmafs is mandatory
	if len(osp.initramfs) == 0 {
		return fmt.Errorf("missing initramfs")
	}
	return nil
}

// ArchiveBytes return the zip compressed archive part of osp.
func (osp *OSPackage) ArchiveBytes() ([]byte, error) {
	if len(osp.raw) == 0 {
		if err := osp.zip(); err != nil {
			return nil, fmt.Errorf("os package: %v", err)
		}
	}
	return osp.raw, nil
}

// DescriptorBytes return the zip compressed archive part of osp.
func (osp *OSPackage) DescriptorBytes() ([]byte, error) {
	b, err := osp.descriptor.Bytes()
	if err != nil {
		return nil, fmt.Errorf("os package: serializing descriptor failed: %v", err)
	}
	return b, nil
}

// zip packs the content stored in osp and (over)writes osp.Raw
func (osp *OSPackage) zip() error {
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	// directories
	if err := zipDir(zipWriter, bootfilesDir); err != nil {
		return fmt.Errorf("zip dir failed: %v", err)
	}
	// kernel
	name := osp.manifest.KernelPath
	if err := zipFile(zipWriter, name, osp.kernel); err != nil {
		return fmt.Errorf("zip kernel failed: %v", err)
	}
	// initramfs
	if len(osp.initramfs) > 0 {
		name = osp.manifest.InitramfsPath
		if err := zipFile(zipWriter, name, osp.initramfs); err != nil {
			return fmt.Errorf("zip initramfs failed: %v", err)
		}
	}
	// manifest
	mbytes, err := osp.manifest.Bytes()
	if err != nil {
		return fmt.Errorf("serializing manifest failed: %v", err)
	}
	if err := zipFile(zipWriter, ManifestName, mbytes); err != nil {
		return fmt.Errorf("zip manifest failed: %v", err)
	}
	if err := zipWriter.Close(); err != nil {
		return fmt.Errorf("zip writer: %v", err)
	}

	osp.raw = buf.Bytes()
	return nil
}

func (osp *OSPackage) unzip() error {
	reader := bytes.NewReader(osp.raw)
	size := int64(len(osp.raw))
	archive, err := zip.NewReader(reader, size)
	if err != nil {
		return fmt.Errorf("zip reader failed: %v", err)
	}
	// manifest
	m, err := unzipFile(archive, ManifestName)
	if err != nil {
		return fmt.Errorf("unzip manifest failed: %v", err)
	}
	osp.manifest, err = OSManifestFromBytes(m)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	// kernel
	osp.kernel, err = unzipFile(archive, osp.manifest.KernelPath)
	if err != nil {
		return fmt.Errorf("unzip kernel failed: %v", err)
	}
	// initramfs
	osp.initramfs, err = unzipFile(archive, osp.manifest.InitramfsPath)
	if err != nil {
		return fmt.Errorf("unzip initramfs failed: %v", err)
	}
	return nil
}

// Sign signes osp.HashValue using osp.Signer.
// Both, the signature and the certificate are stored into the OSPackage.
func (osp *OSPackage) Sign(keyBlock, certBlock *pem.Block) error {

	hash, err := calculateHash(osp.raw)
	if err != nil {
		return err
	}
	osp.hash = hash

	priv, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("os package sign: parse PKCS8: %v", err)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("os package sign: parse certificate: %v", err)
	}

	// check for dublicate certificates
	for _, pemBytes := range osp.descriptor.Certificates {
		block, _ := pem.Decode(pemBytes)
		storedCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		if storedCert.Equal(cert) {
			return errors.New("certificate has already been used")
		}
	}

	// sign with private key

	sig, err := osp.signer.Sign(priv, osp.hash[:])
	if err != nil {
		return fmt.Errorf("signing failed: %v", err)
	}

	certPEM := pem.EncodeToMemory(certBlock)
	osp.descriptor.Certificates = append(osp.descriptor.Certificates, certPEM)
	osp.descriptor.Signatures = append(osp.descriptor.Signatures, sig)
	return nil
}

// Verify first verifies the certificates stored together with the signatures
// in the os package descriptor against the provided root certificates and then
// verifies the signatures.
// The number of found signatures and the number of valid signatures are returned.
// A signature is valid if:
// * Its certificate was signed by the root certificate
// * It passed verification
// * Its certificate is not a duplicate of a previous one
// The validity bounds of all in volved certificates are ignored.
func (osp *OSPackage) Verify(rootCert *x509.Certificate) (found, valid uint, err error) {
	found = 0
	valid = 0

	var certsUsed []*x509.Certificate
	for i, sig := range osp.descriptor.Signatures {
		found++
		block, _ := pem.Decode(osp.descriptor.Certificates[i])
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return 0, 0, fmt.Errorf("verify: certificate %d: parsing failed: %v", i+1, err)
		}

		// verify certificate: only make sure that cert was signed by roots.
		// no further verification opions, not even validity dates.
		roots := x509.NewCertPool()
		roots.AddCert(rootCert)
		opts := x509.VerifyOptions{
			Roots: roots,
		}
		_, err = cert.Verify(opts)
		if err != nil {
			stlog.Debug("skip signature %d: invalid certificate: %v", i+1, err)
			continue
		}

		// check for dublicates
		var dublicate bool
		for _, c := range certsUsed {
			if c.Equal(cert) {
				dublicate = true
				break
			}
		}
		if dublicate {
			stlog.Debug("skip signature %d: dublicate", i+1)
			continue
		}
		certsUsed = append(certsUsed, cert)

		// verify signature
		err = osp.signer.Verify(sig, osp.hash[:], cert.PublicKey)
		if err != nil {
			stlog.Debug("skip signature %d: verification failed: %v", i+1, err)
			continue
		}
		valid++
	}
	osp.isVerified = true
	return found, valid, nil
}

// OSImage parses a boot.OSImage from osp.
func (osp *OSPackage) OSImage() (boot.OSImage, error) {
	if !osp.isVerified {
		return nil, fmt.Errorf("os package: content not verified")
	}
	if err := osp.unzip(); err != nil {
		return nil, fmt.Errorf("os package: %v", err)
	}
	if err := osp.validate(); err != nil {
		return nil, fmt.Errorf("os package: %v", err)
	}

	// linuxboot image
	return &boot.LinuxImage{
		Name:    osp.manifest.Label,
		Kernel:  bytes.NewReader(osp.kernel),
		Initrd:  bytes.NewReader(osp.initramfs),
		Cmdline: osp.manifest.Cmdline,
	}, nil
}

func calculateHash(data []byte) ([32]byte, error) {
	if len(data) == 0 {
		return [32]byte{}, fmt.Errorf("empty input")
	}
	return sha256.Sum256(data), nil
}
