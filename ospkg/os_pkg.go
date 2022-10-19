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
	"net/url"
	"os"
	"path/filepath"

	"github.com/system-transparency/stboot/sterror"
	"github.com/system-transparency/stboot/stlog"
	"github.com/system-transparency/stboot/trust"
	"github.com/u-root/u-root/pkg/boot"
)

// Scope and operations used for raising Errors of this package.
const (
	ErrScope                  sterror.Scope = "OS package"
	ErrOpCreateOSPkg          sterror.Op    = "CreateOSPackage"
	ErrOpNewOSPkg             sterror.Op    = "NewOSPackage"
	ErrOpOSPkgArchiveBytes    sterror.Op    = "OSPackage.ArchiveBytes"
	ErrOpOSPkgDescriptorBytes sterror.Op    = "OSPackage.DescriptorBytes"
	ErrOpOSPkgSign            sterror.Op    = "OSPackage.Sign"
	ErrOpOSPkgVerify          sterror.Op    = "OSPackage.Verify"
	ErrOpOSPkgvalidate        sterror.Op    = "OSPackage.validate"
	ErrOpOSPkgzip             sterror.Op    = "OSPackage.zip"
	ErrOpOSPkgunzip           sterror.Op    = "OSPackage.unzip"
	ErrOpOSPkgparseCert       sterror.Op    = "OSPackage.parseCert"
	ErrOpcalculateHash        sterror.Op    = "calculateHash"
	ErrOpOSImage              sterror.Op    = "OSImage"
)

// Errors which may be raised and wrapped in this package.
var (
	ErrVrfy          = errors.New("signature verification failed")
	ErrParse         = errors.New("failed to parse")
	ErrSerialize     = errors.New("failed to serialize")
	ErrValidate      = errors.New("failed to validate")
	ErrSign          = errors.New("failed to sign")
	ErrWriteToFile   = errors.New("failed to write to file")
	ErrFailedToUnzip = errors.New("failed to unzip archive")
	ErrFailedToZip   = errors.New("failed to zip")
	ErrNotHashable   = errors.New("data not hashable")
	ErrGenerateData  = errors.New("failed to generate data")
	ErrMissingData   = errors.New("missing data")
	ErrOverwriteData = errors.New("failed to overwrite data")
)

// Additional information which might get included into Errors.
const (
	ErrInfoFailedToReadFrom = "failed to read from %v"
	ErrInfoInvalidPath      = "missing %v path"
	ErrInfoInvalidVer       = "invalid version: %d, expected %d"
	ErrInfoMissingScheme    = "missing scheme"
	ErrInfoLengthOfZero     = "data %v has length of zero"
)

const (
	// DefaultOSPackageName is the file name of the archive, which is expected to contain
	// the stboot configuration file along with the corresponding files.
	DefaultOSPackageName string = "ospkg.zip"
	// OSPackageExt is the file extension of OS packages.
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
// nolint:cyclop
func CreateOSPackage(label, pkgURL, kernel, initramfs, cmdline string) (*OSPackage, error) {
	var manifest = &OSManifest{
		Version: ManifestVersion,
		Label:   label,
		Cmdline: cmdline,
	}

	var descriptor = &Descriptor{
		Version: DescriptorVersion,
	}

	var osp = &OSPackage{
		descriptor: descriptor,
		manifest:   manifest,
		signer:     trust.ED25519Signer{},
		isVerified: false,
	}

	var err error
	if pkgURL != "" {
		uri, err := url.Parse(pkgURL)
		if err != nil {
			return nil, sterror.E(ErrScope, ErrOpCreateOSPkg, ErrGenerateData, err.Error())
		}

		if uri.Scheme == "" || uri.Scheme != "http" && uri.Scheme != "https" {
			stlog.Debug("os package: OS package URL: missing or unsupported scheme in %s", uri.String())

			return nil, sterror.E(ErrScope, ErrOpCreateOSPkg, ErrGenerateData, ErrInfoMissingScheme)
		}

		osp.descriptor.PkgURL = pkgURL
	}

	if kernel != "" {
		osp.kernel, err = os.ReadFile(kernel)
		if err != nil {
			return nil, sterror.E(ErrScope, ErrOpCreateOSPkg, ErrGenerateData, fmt.Sprintf(ErrInfoFailedToReadFrom, "kernel"))
		}

		osp.manifest.KernelPath = filepath.Join(bootfilesDir, filepath.Base(kernel))
	}

	if initramfs != "" {
		osp.initramfs, err = os.ReadFile(initramfs)
		if err != nil {
			return nil, sterror.E(ErrScope, ErrOpCreateOSPkg, ErrGenerateData, fmt.Sprintf(ErrInfoFailedToReadFrom, "initramfs"))
		}

		osp.manifest.InitramfsPath = filepath.Join(bootfilesDir, filepath.Base(initramfs))
	}

	if err := osp.validate(); err != nil {
		return nil, sterror.E(ErrScope, ErrOpCreateOSPkg, ErrGenerateData, err.Error())
	}

	return osp, nil
}

// NewOSPackage constructs a new OSPackage initialized with raw bytes
// and valid internal state.
func NewOSPackage(archiveZIP, descriptorJSON []byte) (*OSPackage, error) {
	// check archive
	_, err := zip.NewReader(bytes.NewReader(archiveZIP), int64(len(archiveZIP)))
	if err != nil {
		return nil, sterror.E(ErrScope, ErrOpNewOSPkg, ErrGenerateData, err.Error())
	}
	// check descriptor
	descriptor, err := DescriptorFromBytes(descriptorJSON)
	if err != nil {
		if err != nil {
			return nil, sterror.E(ErrScope, ErrOpNewOSPkg, ErrGenerateData, err.Error())
		}
	}

	if err = descriptor.Validate(); err != nil {
		return nil, sterror.E(ErrScope, ErrOpNewOSPkg, ErrGenerateData, err.Error())
	}

	osp := OSPackage{
		raw:        archiveZIP,
		descriptor: descriptor,
		signer:     trust.ED25519Signer{},
		isVerified: false,
	}

	osp.hash, err = calculateHash(osp.raw)
	if err != nil {
		return nil, sterror.E(ErrScope, ErrOpNewOSPkg, ErrGenerateData, err.Error())
	}

	return &osp, nil
}

func (osp *OSPackage) validate() error {
	// manifest
	if osp.manifest == nil {
		stlog.Debug("missing manifest data")

		return sterror.E(ErrScope, ErrOpOSPkgvalidate, ErrMissingData, fmt.Sprintf(ErrInfoLengthOfZero, "manifest"))
	} else if err := osp.manifest.Validate(); err != nil {
		return err
	}
	// descriptor
	if osp.descriptor == nil {
		stlog.Debug("missing descriptor data")

		return sterror.E(ErrScope, ErrOpOSPkgvalidate, ErrMissingData, fmt.Sprintf(ErrInfoLengthOfZero, "descriptor"))
	} else if err := osp.descriptor.Validate(); err != nil {
		return err
	}
	// kernel is mandatory
	if len(osp.kernel) == 0 {
		stlog.Debug("missing kernel")

		return sterror.E(ErrScope, ErrOpOSPkgvalidate, ErrMissingData, fmt.Sprintf(ErrInfoLengthOfZero, "kernel"))
	}
	// initrmafs is mandatory
	if len(osp.initramfs) == 0 {
		stlog.Debug("missing initramfs")

		return sterror.E(ErrScope, ErrOpOSPkgvalidate, ErrMissingData, fmt.Sprintf(ErrInfoLengthOfZero, "initramfs"))
	}

	return nil
}

// ArchiveBytes return the zip compressed archive part of osp.
func (osp *OSPackage) ArchiveBytes() ([]byte, error) {
	if len(osp.raw) == 0 {
		if err := osp.zip(); err != nil {
			return nil, sterror.E(ErrScope, ErrOpOSPkgArchiveBytes, ErrFailedToZip, err.Error())
		}
	}

	return osp.raw, nil
}

// DescriptorBytes return the zip compressed archive part of osp.
func (osp *OSPackage) DescriptorBytes() ([]byte, error) {
	b, err := osp.descriptor.Bytes()
	if err != nil {
		return nil, sterror.E(ErrScope, ErrOpOSPkgDescriptorBytes, ErrFailedToZip, err.Error())
	}

	return b, nil
}

// zip packs the content stored in osp and (over)writes osp.Raw.
func (osp *OSPackage) zip() error {
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	// directories
	if err := zipDir(zipWriter, bootfilesDir); err != nil {
		return sterror.E(ErrScope, ErrOpOSPkgzip, ErrOverwriteData, err.Error())
	}
	// kernel
	name := osp.manifest.KernelPath
	if err := zipFile(zipWriter, name, osp.kernel); err != nil {
		return sterror.E(ErrScope, ErrOpOSPkgzip, ErrOverwriteData, err.Error())
	}
	// initramfs
	if len(osp.initramfs) > 0 {
		name = osp.manifest.InitramfsPath
		if err := zipFile(zipWriter, name, osp.initramfs); err != nil {
			return sterror.E(ErrScope, ErrOpOSPkgzip, ErrOverwriteData, err.Error())
		}
	}
	// manifest
	mbytes, err := osp.manifest.Bytes()
	if err != nil {
		return sterror.E(ErrScope, ErrOpOSPkgzip, ErrOverwriteData, err.Error())
	}

	if err := zipFile(zipWriter, ManifestName, mbytes); err != nil {
		return sterror.E(ErrScope, ErrOpOSPkgzip, ErrOverwriteData, err.Error())
	}

	if err := zipWriter.Close(); err != nil {
		return sterror.E(ErrScope, ErrOpOSPkgzip, ErrOverwriteData, err.Error())
	}

	osp.raw = buf.Bytes()

	return nil
}

func (osp *OSPackage) unzip() error {
	reader := bytes.NewReader(osp.raw)
	size := int64(len(osp.raw))

	archive, err := zip.NewReader(reader, size)
	if err != nil {
		return sterror.E(ErrScope, ErrOpOSPkgunzip, ErrFailedToUnzip, err.Error())
	}
	// manifest
	m, err := unzipFile(archive, ManifestName)
	if err != nil {
		return sterror.E(ErrScope, ErrOpOSPkgunzip, ErrFailedToUnzip, err.Error())
	}

	osp.manifest, err = OSManifestFromBytes(m)
	if err != nil {
		return sterror.E(ErrScope, ErrOpOSPkgunzip, ErrFailedToUnzip, err.Error())
	}
	// kernel
	osp.kernel, err = unzipFile(archive, osp.manifest.KernelPath)
	if err != nil {
		return sterror.E(ErrScope, ErrOpOSPkgunzip, ErrFailedToUnzip, err.Error())
	}
	// initramfs
	osp.initramfs, err = unzipFile(archive, osp.manifest.InitramfsPath)
	if err != nil {
		return sterror.E(ErrScope, ErrOpOSPkgunzip, ErrFailedToUnzip, err.Error())
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
		return sterror.E(ErrScope, ErrOpOSPkgSign, ErrSign, err.Error())
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return sterror.E(ErrScope, ErrOpOSPkgSign, ErrSign, err.Error())
	}

	// check for duplicate certificates
	for _, pemBytes := range osp.descriptor.Certificates {
		storedCert, err := osp.parseCert(pemBytes)

		if err != nil {
			return sterror.E(ErrScope, ErrOpOSPkgSign, ErrSign, err.Error())
		}

		if storedCert.Equal(cert) {
			stlog.Debug("certificate has already been used")

			return sterror.E(ErrScope, ErrOpOSPkgSign, ErrSign, "certificate has already been used")
		}
	}

	// sign with private key

	sig, err := osp.signer.Sign(priv, osp.hash[:])
	if err != nil {
		return sterror.E(ErrScope, ErrOpOSPkgSign, ErrSign, err.Error())
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
//
// nolint:nonamedreturns
func (osp *OSPackage) Verify(rootCert *x509.Certificate) (found, valid uint, err error) {
	found = 0
	valid = 0

	certsUsed := make([]*x509.Certificate, 0, len(osp.descriptor.Signatures))

	for iter, sig := range osp.descriptor.Signatures {
		found++

		cert, err := osp.parseCert(osp.descriptor.Certificates[iter])

		if err != nil {
			return 0, 0, sterror.E(ErrScope, ErrOpOSPkgVerify, ErrVrfy, fmt.Sprintf("could not parse cert %d: %v", iter+1, err))
		}

		// verify certificate: only make sure that cert was signed by roots.
		// no further verification opions, not even validity dates.
		roots := x509.NewCertPool()
		roots.AddCert(rootCert)

		opts := x509.VerifyOptions{
			Roots: roots,
		}

		if _, err = cert.Verify(opts); err != nil {
			stlog.Debug("skip signature %d: invalid certificate: %v", iter+1, err)

			continue
		}

		var duplicate bool

		for _, c := range certsUsed {
			if c.Equal(cert) {
				duplicate = true

				break
			}
		}

		if duplicate {
			stlog.Debug("skip signature %d: dublicate", iter+1)

			continue
		}

		certsUsed = append(certsUsed, cert)

		err = osp.signer.Verify(sig, osp.hash[:], cert.PublicKey)
		if err != nil {
			stlog.Debug("skip signature %d: verification failed: %v", iter+1, err)

			continue
		}
		valid++
	}

	osp.isVerified = true

	return found, valid, nil
}

// OSImage parses a boot.OSImage from osp.
func (osp *OSPackage) OSImage() (*boot.LinuxImage, error) {
	if !osp.isVerified {
		stlog.Debug("os package: content not verified")

		return nil, sterror.E(ErrScope, ErrOpOSImage, ErrParse, "content is not verified")
	}

	if err := osp.unzip(); err != nil {
		return nil, sterror.E(ErrScope, ErrOpOSImage, ErrParse, err.Error())
	}

	if err := osp.validate(); err != nil {
		return nil, sterror.E(ErrScope, ErrOpOSImage, ErrParse, err.Error())
	}

	// linuxboot image
	return &boot.LinuxImage{
		Name:    osp.manifest.Label,
		Kernel:  bytes.NewReader(osp.kernel),
		Initrd:  bytes.NewReader(osp.initramfs),
		Cmdline: osp.manifest.Cmdline,
	}, nil
}

func (osp *OSPackage) parseCert(certData []byte) (*x509.Certificate, error) {
	var block *pem.Block

	block, _ = pem.Decode(certData)

	if block == nil {
		return nil, sterror.E(ErrScope, ErrOpOSPkgparseCert, ErrParse, "certificate is not encoded as pem")
	}

	if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		return nil, sterror.E(ErrScope, ErrOpOSPkgparseCert, ErrParse, "encoded data is not a certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, sterror.E(ErrScope, ErrOpOSPkgparseCert, ErrParse, err)
	}

	return cert, nil
}

func calculateHash(data []byte) ([32]byte, error) {
	if len(data) == 0 {
		return [32]byte{}, sterror.E(ErrScope, ErrOpcalculateHash, ErrNotHashable, fmt.Sprintf(ErrInfoLengthOfZero, "data"))
	}

	return sha256.Sum256(data), nil
}
