// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package stboot

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"path/filepath"

	"github.com/u-root/u-root/pkg/boot"
	"github.com/u-root/u-root/pkg/boot/multiboot"
)

const (
	bootfilesDir  string = "boot"
	acmDir        string = "boot/acms"
	signaturesDir string = "signatures"
)

// OSPackage represents an OS package ZIP archive and and related data.
type OSPackage struct {
	raw        []byte
	descriptor *Descriptor
	hash       [32]byte
	manifest   *OSManifest
	kernel     []byte
	initramfs  []byte
	tboot      []byte
	acms       [][]byte
	signer     Signer
	isVerified bool
}

// CreateOSPackage constructs a OSPackage from the passed files.
func CreateOSPackage(label, pkgURL, kernel, initramfs, cmdline, tboot, tbootArgs string, acms []string) (*OSPackage, error) {
	var m = &OSManifest{
		Version:   ManifestVersion,
		Label:     label,
		Cmdline:   cmdline,
		TbootArgs: tbootArgs,
	}

	var d = &Descriptor{
		Version: DescriptorVersion,
	}

	var ospkg = &OSPackage{
		descriptor: d,
		manifest:   m,
		signer:     ED25519Signer{},
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
		ospkg.descriptor.PkgURL = pkgURL
	}

	if kernel != "" {
		ospkg.kernel, err = ioutil.ReadFile(kernel)
		if err != nil {
			return nil, fmt.Errorf("os package: kernel path: %v", err)
		}
		ospkg.manifest.KernelPath = filepath.Join(bootfilesDir, filepath.Base(kernel))
	}

	if initramfs != "" {
		ospkg.initramfs, err = ioutil.ReadFile(initramfs)
		if err != nil {
			return nil, fmt.Errorf("os package: initramfs path: %v", err)
		}
		ospkg.manifest.InitramfsPath = filepath.Join(bootfilesDir, filepath.Base(initramfs))
	}

	if tboot != "" {
		ospkg.tboot, err = ioutil.ReadFile(tboot)
		if err != nil {
			return nil, fmt.Errorf("os package: tboot path: %v", err)
		}
		ospkg.manifest.TbootPath = filepath.Join(bootfilesDir, filepath.Base(tboot))
	}

	for _, acm := range acms {
		a, err := ioutil.ReadFile(acm)
		if err != nil {
			return nil, fmt.Errorf("os package: acm path: %v", err)
		}
		ospkg.acms = append(ospkg.acms, a)
		name := filepath.Join(acmDir, filepath.Base(acm))
		ospkg.manifest.ACMPaths = append(ospkg.manifest.ACMPaths, name)
	}

	if err := ospkg.validate(); err != nil {
		return nil, err
	}

	return ospkg, nil
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

	ospkg := OSPackage{
		raw:        archiveZIP,
		descriptor: descriptor,
		signer:     ED25519Signer{},
		isVerified: false,
	}

	ospkg.hash, err = calculateHash(ospkg.raw)
	if err != nil {
		return nil, fmt.Errorf("os package: calculate hash failed: %v", err)
	}

	return &ospkg, nil
}

func (ospkg *OSPackage) validate() error {
	// manifest
	if ospkg.manifest == nil {
		return fmt.Errorf("missing manifest data")
	} else if err := ospkg.manifest.Validate(); err != nil {
		return err
	}
	// descriptor
	if ospkg.descriptor == nil {
		return fmt.Errorf("missing descriptor data")
	} else if err := ospkg.descriptor.Validate(); err != nil {
		return err
	}
	// kernel is mandatory
	if len(ospkg.kernel) == 0 {
		return fmt.Errorf("missing kernel")
	}
	// initrmafs is mandatory
	if len(ospkg.initramfs) == 0 {
		return fmt.Errorf("missing initramfs")
	}
	// tboot
	if len(ospkg.tboot) != 0 && len(ospkg.acms) == 0 {
		return fmt.Errorf("tboot requires at least one ACM")
	}
	return nil
}

// ArchiveBytes return the zip compressed archive part of ospkg.
func (ospkg *OSPackage) ArchiveBytes() ([]byte, error) {
	if len(ospkg.raw) == 0 {
		if err := ospkg.zip(); err != nil {
			return nil, fmt.Errorf("os package: %v", err)
		}
	}
	return ospkg.raw, nil
}

// DescriptorBytes return the zip compressed archive part of ospkg.
func (ospkg *OSPackage) DescriptorBytes() ([]byte, error) {
	b, err := ospkg.descriptor.Bytes()
	if err != nil {
		return nil, fmt.Errorf("os package: serializing descriptor failed: %v", err)
	}
	return b, nil
}

// zip packs the content stored in ospkg and (over)writes ospkg.Raw
func (ospkg *OSPackage) zip() error {
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	// directories
	if err := zipDir(zipWriter, bootfilesDir); err != nil {
		return fmt.Errorf("zip dir failed: %v", err)
	}
	if len(ospkg.acms) > 0 {
		if err := zipDir(zipWriter, acmDir); err != nil {
			return fmt.Errorf("zip dir failed: %v", err)
		}
	}
	// kernel
	name := ospkg.manifest.KernelPath
	if err := zipFile(zipWriter, name, ospkg.kernel); err != nil {
		return fmt.Errorf("zip kernel failed: %v", err)
	}
	// initramfs
	if len(ospkg.initramfs) > 0 {
		name = ospkg.manifest.InitramfsPath
		if err := zipFile(zipWriter, name, ospkg.initramfs); err != nil {
			return fmt.Errorf("zip initramfs failed: %v", err)
		}
	}
	// tboot
	if len(ospkg.tboot) > 0 {
		name = ospkg.manifest.TbootPath
		if err := zipFile(zipWriter, name, ospkg.tboot); err != nil {
			return fmt.Errorf("zip tboot failed: %v", err)
		}
	}
	// ACMs
	if len(ospkg.acms) > 0 {
		for i, acm := range ospkg.acms {
			name = ospkg.manifest.ACMPaths[i]
			if err := zipFile(zipWriter, name, acm); err != nil {
				return fmt.Errorf("zip ACMs failed: %v", err)
			}
		}
	}
	// manifest
	mbytes, err := ospkg.manifest.Bytes()
	if err != nil {
		return fmt.Errorf("serializing manifest failed: %v", err)
	}
	if err := zipFile(zipWriter, ManifestName, mbytes); err != nil {
		return fmt.Errorf("zip manifest failed: %v", err)
	}
	if err := zipWriter.Close(); err != nil {
		return fmt.Errorf("zip writer: %v", err)
	}

	ospkg.raw = buf.Bytes()
	return nil
}

func (ospkg *OSPackage) unzip() error {
	reader := bytes.NewReader(ospkg.raw)
	size := int64(len(ospkg.raw))
	archive, err := zip.NewReader(reader, size)
	if err != nil {
		return fmt.Errorf("zip reader failed: %v", err)
	}
	// manifest
	m, err := unzipFile(archive, ManifestName)
	if err != nil {
		return fmt.Errorf("unzip manifest failed: %v", err)
	}
	ospkg.manifest, err = OSManifestFromBytes(m)
	if err != nil {
		return fmt.Errorf("%v", err)
	}
	// kernel
	ospkg.kernel, err = unzipFile(archive, ospkg.manifest.KernelPath)
	if err != nil {
		return fmt.Errorf("unzip kernel failed: %v", err)
	}
	// initramfs
	ospkg.initramfs, err = unzipFile(archive, ospkg.manifest.InitramfsPath)
	if err != nil {
		return fmt.Errorf("unzip initramfs failed: %v", err)
	}
	// tboot
	if ospkg.manifest.TbootPath != "" {
		ospkg.tboot, err = unzipFile(archive, ospkg.manifest.TbootPath)
		if err != nil {
			return fmt.Errorf("unzip tboot failed: %v", err)
		}
	}
	// ACMs
	if len(ospkg.manifest.ACMPaths) > 0 {
		for _, acm := range ospkg.manifest.ACMPaths {
			a, err := unzipFile(archive, acm)
			if err != nil {
				return fmt.Errorf("unzip ACMs failed: %v", err)
			}
			ospkg.acms = append(ospkg.acms, a)
		}
	}
	return nil
}

// Sign signes ospkg.HashValue using ospkg.Signer.
// Both, the signature and the certificate are stored into the OSPackage.
func (ospkg *OSPackage) Sign(keyBlock, certBlock *pem.Block) error {

	hash, err := calculateHash(ospkg.raw)
	if err != nil {
		return err
	}
	ospkg.hash = hash

	priv, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("os package sign: parse PKCS8: %v", err)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("os package sign: parse certificate: %v", err)
	}

	// check for dublicate certificates
	for _, pemBytes := range ospkg.descriptor.Certificates {
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

	sig, err := ospkg.signer.Sign(priv, ospkg.hash[:])
	if err != nil {
		return fmt.Errorf("signing failed: %v", err)
	}

	certPEM := pem.EncodeToMemory(certBlock)
	ospkg.descriptor.Certificates = append(ospkg.descriptor.Certificates, certPEM)
	ospkg.descriptor.Signatures = append(ospkg.descriptor.Signatures, sig)
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
func (ospkg *OSPackage) Verify(rootCert *x509.Certificate) (found, valid int, err error) {
	found = 0
	valid = 0

	var certsUsed []*x509.Certificate
	for i, sig := range ospkg.descriptor.Signatures {
		found++
		block, _ := pem.Decode(ospkg.descriptor.Certificates[i])
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
			log.Printf("skip signature %d: invalid certificate: %v", i+1, err)
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
			log.Printf("skip signature %d: dublicate", i+1)
			continue
		}
		certsUsed = append(certsUsed, cert)

		// verify signature
		err = ospkg.signer.Verify(sig, ospkg.hash[:], cert.PublicKey)
		if err != nil {
			log.Printf("skip signature %d: verification failed: %v", i+1, err)
			continue
		}
		valid++
	}
	ospkg.isVerified = true
	return found, valid, nil
}

// OSImage parses a boot.OSImage from ospkg. If tryTboot is set to false
// a boot.LinuxImage is returned. If tryTboot is true and ospk contains a
// tboot setup, a boot.MultibootImage is returned, else a boot.LinuxImage
//
func (ospkg *OSPackage) OSImage(tryTboot bool) (boot.OSImage, error) {
	if !ospkg.isVerified {
		return nil, fmt.Errorf("os package: content not verified")
	}
	if err := ospkg.unzip(); err != nil {
		return nil, fmt.Errorf("os package: %v", err)
	}
	if err := ospkg.validate(); err != nil {
		return nil, fmt.Errorf("os package: %v", err)
	}

	var osi boot.OSImage
	if tryTboot && len(ospkg.tboot) >= 0 {
		// multiboot image
		var modules []multiboot.Module
		kernel := multiboot.Module{
			Module:  bytes.NewReader(ospkg.kernel),
			Cmdline: "os-kernel " + ospkg.manifest.Cmdline,
		}
		modules = append(modules, kernel)

		initramfs := multiboot.Module{
			Module:  bytes.NewReader(ospkg.initramfs),
			Cmdline: "os-initramfs",
		}
		modules = append(modules, initramfs)

		for n, a := range ospkg.acms {
			acm := multiboot.Module{
				Module:  bytes.NewReader(a),
				Cmdline: fmt.Sprintf("ACM%d", n+1),
			}
			modules = append(modules, acm)
		}

		osi = &boot.MultibootImage{
			Name:    ospkg.manifest.Label,
			Kernel:  bytes.NewReader(ospkg.tboot),
			Cmdline: ospkg.manifest.TbootArgs,
			Modules: modules,
		}
	}

	// linuxboot image
	osi = &boot.LinuxImage{
		Name:    ospkg.manifest.Label,
		Kernel:  bytes.NewReader(ospkg.kernel),
		Initrd:  bytes.NewReader(ospkg.initramfs),
		Cmdline: ospkg.manifest.Cmdline,
	}
	return osi, nil
}

func calculateHash(data []byte) ([32]byte, error) {
	if len(data) == 0 {
		return [32]byte{}, fmt.Errorf("empty input")
	}
	return sha256.Sum256(data), nil
}
