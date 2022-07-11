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

var (
	ErrCreateOSPackage           = errors.New("failed to create OS package")
	ErrCreateOSPackageURL        = errors.New("failed to parse URL")
	ErrCreateOSMissingScheme     = errors.New("missing scheme")
	ErrCreateOSKernelPath        = errors.New("failed to read from kernel path")
	ErrCreateOSInitramfs         = errors.New("failed to read from initramfs path")
	ErrNewOSPkg                  = errors.New("failed to construct new OS package")
	ErrValidateMissingManifest   = errors.New("missing manifest data")
	ErrValidateMissingDescriptor = errors.New("missing descriptor data")
	ErrValidateMissingKernel     = errors.New("missing kernel")
	ErrValidateMissingInitramfs  = errors.New("missing initramfs")
	ErrArchiveBytes              = errors.New("failed to archive os package")
	ErrDescriptorBytes           = errors.New("failed to serialize os package")
	ErrZipOSPkg                  = errors.New("failed to zip osp and (over)write osp.Raw")
	ErrZipOSPkgDir               = errors.New("zip dir failed")
	ErrZipOSPkgZipKernel         = errors.New("zip kernel failed")
	ErrZipOSPkgZipInitramfs      = errors.New("zip initramfs failed")
	ErrZipOSPkgSerManifest       = errors.New("serializing manifest failed")
	ErrZipOSPkgZipManifest       = errors.New("zip manifest failed")
	ErrZipOSPkgZipWriter         = errors.New("zip writer failed")
	ErrUnzipOSPkg                = errors.New("failed to unzip osp")
	ErrUnzipOSPkgDir             = errors.New("unzip dir failed")
	ErrUnzipOSPkgUnzipKernel     = errors.New("unzip kernel failed")
	ErrUnzipOSPkgUnzipInitramfs  = errors.New("unzip initramfs failed")
	ErrUnzipOSPkgDeSerManifest   = errors.New("deserializing manifest failed")
	ErrUnzipOSPkgUnzipManifest   = errors.New("unzip manifest failed")
	ErrUnzipOSPkgUnzipReader     = errors.New("unzip reader failed")
	ErrSignOSPkg                 = errors.New("failed to sign os package")
	ErrSignOSPkgParsePKCS8       = errors.New("failed parse PKCS8")
	ErrSignOSPkgParseCert        = errors.New("failed parse certificate")
	ErrSignOSPkgReusedCert       = errors.New("certificate has already been used")
	ErrVerifyOSPkg               = errors.New("failed to verify certificate")
	ErrVerifyOSPkgParse          = errors.New("parsing failed at certificate")
	ErrOSImage                   = errors.New("failed to parse OSImage")
	ErrNoHashInput               = errors.New("data to be hashed has zero length")
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
			return nil, fmt.Errorf("%w: %v %v", ErrCreateOSPackage, ErrCreateOSPackageURL, err)
		}

		if uri.Scheme == "" || uri.Scheme != "http" && uri.Scheme != "https" {
			stlog.Debug("os package: OS package URL: missing or unsupported scheme in %s", uri.String())

			return nil, fmt.Errorf("%w: %v", ErrCreateOSPackage, ErrCreateOSMissingScheme)
		}

		osp.descriptor.PkgURL = pkgURL
	}

	if kernel != "" {
		osp.kernel, err = ioutil.ReadFile(kernel)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCreateOSPackage, ErrCreateOSKernelPath)
		}

		osp.manifest.KernelPath = filepath.Join(bootfilesDir, filepath.Base(kernel))
	}

	if initramfs != "" {
		osp.initramfs, err = ioutil.ReadFile(initramfs)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCreateOSPackage, ErrCreateOSInitramfs)
		}

		osp.manifest.InitramfsPath = filepath.Join(bootfilesDir, filepath.Base(initramfs))
	}

	if err := osp.validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCreateOSPackage, err)
	}

	return osp, nil
}

// NewOSPackage constructs a new OSPackage initialized with raw bytes
// and valid internal state.
func NewOSPackage(archiveZIP, descriptorJSON []byte) (*OSPackage, error) {
	// check archive
	_, err := zip.NewReader(bytes.NewReader(archiveZIP), int64(len(archiveZIP)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNewOSPkg, err)
	}
	// check descriptor
	descriptor, err := DescriptorFromBytes(descriptorJSON)
	if err != nil {
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNewOSPkg, err)
		}
	}

	if err = descriptor.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNewOSPkg, err)
	}

	osp := OSPackage{
		raw:        archiveZIP,
		descriptor: descriptor,
		signer:     trust.ED25519Signer{},
		isVerified: false,
	}

	osp.hash, err = calculateHash(osp.raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNewOSPkg, err)
	}

	return &osp, nil
}

func (osp *OSPackage) validate() error {
	// manifest
	if osp.manifest == nil {
		stlog.Debug("missing manifest data")

		return ErrValidateMissingManifest
	} else if err := osp.manifest.Validate(); err != nil {
		return err
	}
	// descriptor
	if osp.descriptor == nil {
		stlog.Debug("missing descriptor data")

		return ErrValidateMissingDescriptor
	} else if err := osp.descriptor.Validate(); err != nil {
		return err
	}
	// kernel is mandatory
	if len(osp.kernel) == 0 {
		stlog.Debug("missing kernel")

		return ErrValidateMissingKernel
	}
	// initrmafs is mandatory
	if len(osp.initramfs) == 0 {
		stlog.Debug("missing initramfs")

		return ErrValidateMissingInitramfs
	}

	return nil
}

// ArchiveBytes return the zip compressed archive part of osp.
func (osp *OSPackage) ArchiveBytes() ([]byte, error) {
	if len(osp.raw) == 0 {
		if err := osp.zip(); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrArchiveBytes, err)
		}
	}

	return osp.raw, nil
}

// DescriptorBytes return the zip compressed archive part of osp.
func (osp *OSPackage) DescriptorBytes() ([]byte, error) {
	b, err := osp.descriptor.Bytes()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDescriptorBytes, err)
	}

	return b, nil
}

// zip packs the content stored in osp and (over)writes osp.Raw.
func (osp *OSPackage) zip() error {
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	// directories
	if err := zipDir(zipWriter, bootfilesDir); err != nil {
		return fmt.Errorf("%w: %v: %v", ErrZipOSPkg, ErrZipOSPkgDir, err)
	}
	// kernel
	name := osp.manifest.KernelPath
	if err := zipFile(zipWriter, name, osp.kernel); err != nil {
		return fmt.Errorf("%w: %v: %v", ErrZipOSPkg, ErrZipOSPkgZipKernel, err)
	}
	// initramfs
	if len(osp.initramfs) > 0 {
		name = osp.manifest.InitramfsPath
		if err := zipFile(zipWriter, name, osp.initramfs); err != nil {
			return fmt.Errorf("%w: %v: %v", ErrZipOSPkg, ErrZipOSPkgZipInitramfs, err)
		}
	}
	// manifest
	mbytes, err := osp.manifest.Bytes()
	if err != nil {
		return fmt.Errorf("%w: %v: %v", ErrZipOSPkg, ErrZipOSPkgSerManifest, err)
	}

	if err := zipFile(zipWriter, ManifestName, mbytes); err != nil {
		return fmt.Errorf("%w: %v: %v", ErrZipOSPkg, ErrZipOSPkgZipManifest, err)
	}

	if err := zipWriter.Close(); err != nil {
		return fmt.Errorf("%w: %v: %v", ErrZipOSPkg, ErrZipOSPkgZipWriter, err)
	}

	osp.raw = buf.Bytes()

	return nil
}

func (osp *OSPackage) unzip() error {
	reader := bytes.NewReader(osp.raw)
	size := int64(len(osp.raw))

	archive, err := zip.NewReader(reader, size)
	if err != nil {
		return fmt.Errorf("%w: %v %v", ErrUnzipOSPkg, ErrUnzipOSPkgUnzipReader, err)
	}
	// manifest
	m, err := unzipFile(archive, ManifestName)
	if err != nil {
		return fmt.Errorf("%w: %v %v", ErrUnzipOSPkg, ErrUnzipOSPkgUnzipManifest, err)
	}

	osp.manifest, err = OSManifestFromBytes(m)
	if err != nil {
		return fmt.Errorf("%w: %v %v", ErrUnzipOSPkg, ErrUnzipOSPkgDeSerManifest, err)
	}
	// kernel
	osp.kernel, err = unzipFile(archive, osp.manifest.KernelPath)
	if err != nil {
		return fmt.Errorf("%w: %v %v", ErrUnzipOSPkg, ErrUnzipOSPkgUnzipKernel, err)
	}
	// initramfs
	osp.initramfs, err = unzipFile(archive, osp.manifest.InitramfsPath)
	if err != nil {
		return fmt.Errorf("%w: %v %v", ErrUnzipOSPkg, ErrUnzipOSPkgUnzipInitramfs, err)
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
		return fmt.Errorf("%w: %v: %v", ErrSignOSPkg, ErrSignOSPkgParsePKCS8, err)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("%w: %v: %v", ErrSignOSPkg, ErrSignOSPkgParseCert, err)
	}

	// check for duplicate certificates
	for _, pemBytes := range osp.descriptor.Certificates {
		block, _ := pem.Decode(pemBytes)

		storedCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("%w: %v: %v", ErrSignOSPkg, ErrSignOSPkgParseCert, err)
		}

		if storedCert.Equal(cert) {
			stlog.Debug("certificate has already been used")

			return fmt.Errorf("%w: %v: %v", ErrSignOSPkg, ErrSignOSPkgReusedCert, err)
		}
	}

	// sign with private key

	sig, err := osp.signer.Sign(priv, osp.hash[:])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSignOSPkg, err)
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

		block, _ := pem.Decode(osp.descriptor.Certificates[iter])

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return 0, 0, fmt.Errorf("%w: %v %d: %v", ErrVerifyOSPkg, ErrVerifyOSPkgParse, iter+1, err)
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

		return nil, ErrOSImage
	}

	if err := osp.unzip(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOSImage, err)
	}

	if err := osp.validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOSImage, err)
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
		return [32]byte{}, ErrNoHashInput
	}

	return sha256.Sum256(data), nil
}
