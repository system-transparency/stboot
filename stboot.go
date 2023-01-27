// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"git.glasklar.is/system-transparency/core/stboot/host"
	"git.glasklar.is/system-transparency/core/stboot/host/network"
	"git.glasklar.is/system-transparency/core/stboot/opts"
	"git.glasklar.is/system-transparency/core/stboot/ospkg"
	"git.glasklar.is/system-transparency/core/stboot/stlog"
	"github.com/u-root/u-root/pkg/boot"
	"github.com/u-root/u-root/pkg/uio"
)

const (
	logLevelHelp = "Log level: e 'errors' w 'warn', i 'info', d 'debug'."
	dryRunHelp   = "Stop before kexec-ing into the loaded OS kernel"
)

// Files at initramfs.
const (
	hostCfgFile        = "/etc/host_configuration.json"
	securityConfigFile = "/etc/security_configuration.json"
	signingRootFile    = "/etc/ospkg_signing_root.pem"

	// For HTTPS roots only Let's Encrypt ISRG Root X1 is used.
	httpsRootsFile = "/etc/ssl/certs/isrgrootx1.pem"
)

const banner = `
  _____ _______   _____   ____   ____________
 / ____|__   __|  |  _ \ / __ \ / __ \__   __|
| (___    | |     | |_) | |  | | |  | | | |
 \___ \   | |     |  _ <| |  | | |  | | | |
 ____) |  | |     | |_) | |__| | |__| | | |
|_____/   |_|     |____/ \____/ \____/  |_|

`

const check = `
           //\\
verified  //  \\
OS       //   //
        //   //
 //\\  //   //
//  \\//   //
\\        //
 \\      //
  \\    //
   \\__//
`

// Error reports stboot errors.
type Error string

// Error implements error interface.
func (e Error) Error() string {
	return string(e)
}

type ospkgSampl struct {
	name       string
	descriptor io.ReadCloser
	archive    io.ReadCloser
}

//nolint:funlen,maintidx,cyclop
func main() {
	logLevel := flag.String("loglevel", "info", logLevelHelp)
	dryRun := flag.Bool("dryrun", false, dryRunHelp)

	flag.Parse()

	switch *logLevel {
	case "e", "error":
		stlog.SetLevel(stlog.ErrorLevel)
	case "w", "warm":
		stlog.SetLevel(stlog.WarnLevel)
	case "i", "info":
		stlog.SetLevel(stlog.InfoLevel)
	case "d", "debug":
		stlog.SetLevel(stlog.DebugLevel)
	default:
		stlog.SetLevel(stlog.InfoLevel)
	}

	stlog.Info(banner)

	flag.Visit(func(f *flag.Flag) {
		stlog.Debug("-%s %s", f.Name, f.Value)
	})

	/////////////////////
	// Validation & Setup
	/////////////////////
	signingRootSrc, err := os.Open(signingRootFile)
	if err != nil {
		stlog.Error("signing root certificate: %v", err)
		host.Recover()
	}

	httpsRootsSrc, err := os.Open(httpsRootsFile)
	if err != nil {
		stlog.Error("HTTPS root certificates: %v", err)
		host.Recover()
	}

	securityCfgSrc, err := os.Open(securityConfigFile)
	if err != nil {
		stlog.Error("security configuration: %v", err)
		host.Recover()
	}

	hostCfgSrc, err := host.ConfigAutodetect()
	if err != nil {
		stlog.Error("host configuration: %v", err)
		host.Recover()
	}

	stOptions, err := opts.NewOpts(
		opts.WithSecurity(securityCfgSrc),
		opts.WithHostCfg(hostCfgSrc),
		opts.WithSigningRootCert(signingRootSrc),
		opts.WithHTTPSRootCerts(httpsRootsSrc))
	if err != nil {
		stlog.Error("load opts: %v", err)
		host.Recover()
	}

	optsStr, err := json.MarshalIndent(stOptions, "", "  ")
	if err != nil {
		stlog.Debug("Opts: %v", stOptions)
	} else {
		stlog.Debug("Opts: %s", optsStr)
	}

	switch stOptions.BootMode {
	case opts.NetworkBoot:
		if err := network.SetupNetworkInterface(&stOptions.HostCfg); err != nil {
			stlog.Error("failed to setup network interfaces: %v", err)
			host.Recover()
		}
	case opts.BootModeUnset:
	default:
		stlog.Error("invalid state: boot mode is not set")
		host.Recover()
	}

	//////////////////
	// Load OS package
	//////////////////

	if stOptions.BootMode != opts.NetworkBoot {
		stlog.Error("boot mode %q not implemented", stOptions.BootMode)
		host.Recover()
	}

	stlog.Info("Loading OS package via network")

	sample, err := networkLoad(&stOptions.HostCfg, stOptions.HTTPSRoots)
	if err != nil {
		stlog.Error("load OS package via network: %v", err)
		host.Recover()
	}

	stlog.Debug("OS package to be processed:", sample.name)

	//////////////////////
	// Process OS packages
	//////////////////////

	stlog.Info("Processing OS package %s", sample.name)

	aBytes, err := io.ReadAll(sample.archive)
	if err != nil {
		stlog.Error("Read archive: %v", err)
		host.Recover()
	}

	dBytes, err := io.ReadAll(sample.descriptor)
	if err != nil {
		stlog.Error("Read archive: %v", err)
		host.Recover()
	}

	osp, err := ospkg.NewOSPackage(aBytes, dBytes)
	if err != nil {
		stlog.Error("Create OS package: %v", err)
		host.Recover()
	}

	////////////////////
	// Verify OS package
	////////////////////

	//nolint:godox
	// TODO: write ospkg.info method for debug output

	numSig, valid, err := osp.Verify(stOptions.SigningRoot)
	if err != nil {
		stlog.Error("Verifying OS package: %v", err)
		host.Recover()
	}

	threshold := stOptions.ValidSignatureThreshold
	if valid < threshold {
		stlog.Error("Not enough valid signatures: %d found, %d valid, %d required", numSig, valid, threshold)
		host.Recover()
	}

	stlog.Debug("Signatures: %d found, %d valid, %d required", numSig, valid, threshold)
	stlog.Info("OS package passed verification")
	stlog.Info(check)

	/////////////
	// Extract OS
	/////////////
	linuxImg, err := osp.LinuxImage()
	if err != nil {
		stlog.Error("Get boot image: %v", err)
		host.Recover()
	}

	if linuxImg.Kernel == nil {
		stlog.Error("No kernel, image not usable")
		host.Recover()
	}

	stlog.Debug("Boot image:\n %s", linuxImg.String())

	///////////////////////
	// TPM Measurement
	///////////////////////
	stlog.Info("Try TPM measurements")

	var toBeMeasured = [][]byte{}

	ospkgBytes, _ := osp.ArchiveBytes()
	descriptorBytes, _ := osp.DescriptorBytes()

	securityConfigBytes, err := json.Marshal(stOptions.Security)
	if err != nil {
		stlog.Warn("cannot serialize security config for measurement: %w", err)
	}

	toBeMeasured = append(toBeMeasured, ospkgBytes)
	stlog.Debug(" - OS package zip: %d bytes", len(ospkgBytes))

	toBeMeasured = append(toBeMeasured, descriptorBytes)
	stlog.Debug(" - OS package descriptor: %d bytes", len(descriptorBytes))

	toBeMeasured = append(toBeMeasured, securityConfigBytes)
	stlog.Debug(" - Security configuration json: %d bytes", len(securityConfigBytes))

	toBeMeasured = append(toBeMeasured, stOptions.SigningRoot.Raw)
	stlog.Debug(" - Signing root cert ASN1 DER content: %d bytes", len(stOptions.SigningRoot.Raw))

	for n, c := range stOptions.HTTPSRoots {
		toBeMeasured = append(toBeMeasured, c.Raw)
		stlog.Debug(" - HTTPS root %d: %d bytes", n, len(c.Raw))
	}

	// try to measure
	if err = host.MeasureTPM(toBeMeasured...); err != nil {
		stlog.Warn("TPM measurements failed: %v", err)
	}

	//////////
	// Boot OS
	//////////
	if *dryRun {
		stlog.Info("Dryrun mode: will not boot")

		return
	}

	stlog.Info("Loading boot image into memory")

	if err = linuxImg.Load(false); err != nil {
		stlog.Error("%s", err)
		host.Recover()
	}

	stlog.Info("Handing over control - kexec")

	if err = boot.Execute(); err != nil {
		stlog.Error("%v", err)
	}

	stlog.Error("unexpected return from kexec")
	host.Recover()
}

const errDownload = Error("download failed")

//nolint:funlen,gocognit,cyclop
func doDownload(hostCfg *host.Config, roots *x509.CertPool) (*ospkgSampl, error) {
	var sample ospkgSampl

	for _, url := range *hostCfg.ProvisioningURLs {
		stlog.Debug("Downloading %s", url.String())

		if strings.Contains(url.String(), "$ID") {
			stlog.Debug("replacing $ID with identity provided by the Host configuration")

			url, _ = url.Parse(strings.ReplaceAll(url.String(), "$ID", *hostCfg.ID))
		}

		if strings.Contains(url.String(), "$AUTH") {
			stlog.Debug("replacing $AUTH with authentication provided by the Host configuration")

			url, _ = url.Parse(strings.ReplaceAll(url.String(), "$AUTH", *hostCfg.Auth))
		}

		dBytes, err := network.Download(url, roots)
		if err != nil {
			stlog.Debug("Skip %s: %v", url.String(), err)

			continue
		}

		stlog.Debug("Content type: %s", http.DetectContentType(dBytes))
		stlog.Debug("Parsing descriptor")

		descriptor, err := ospkg.DescriptorFromBytes(dBytes)
		if err != nil {
			stlog.Debug("Skip %s: %v", url.String(), err)

			continue
		}

		stlog.Debug("Package descriptor:")
		stlog.Debug("  Version: %d", descriptor.Version)
		stlog.Debug("  Package URL: %s", descriptor.PkgURL)
		stlog.Debug("  %d signature(s)", len(descriptor.Signatures))
		stlog.Debug("  %d certificate(s)", len(descriptor.Certificates))
		stlog.Info("Validating descriptor")

		if err = descriptor.Validate(); err != nil {
			stlog.Debug("Skip %s: %v", url.String(), err)

			continue
		}

		stlog.Debug("Parsing OS package URL form descriptor")

		if descriptor.PkgURL == "" {
			stlog.Debug("Skip %s: no OS package URL provided in descriptor")

			continue
		}

		pkgURL, err := url.Parse(descriptor.PkgURL)
		if err != nil {
			stlog.Debug("Skip %s: %v", url.String(), err)

			continue
		}

		s := pkgURL.Scheme
		if s == "" || s != "http" && s != "https" {
			stlog.Debug("Skip %s: missing or unsupported scheme in OS package URL %s", pkgURL.String())

			continue
		}

		filename := filepath.Base(pkgURL.Path)
		if ext := filepath.Ext(filename); ext != ospkg.OSPackageExt {
			stlog.Debug("Skip %s: package URL must contain a path to a %s file: %s", ospkg.OSPackageExt, pkgURL.String())

			continue
		}

		var aBytes []byte

		if aBytes == nil {
			stlog.Debug("Downloading %s", pkgURL.String())

			aBytes, err = network.Download(pkgURL, roots)
			if err != nil {
				stlog.Debug("Skip %s: %v", url.String(), err)

				continue
			}

			s := pkgURL.Scheme
			if s == "" || s != "http" && s != "https" {
				stlog.Debug("Skip %s: missing or unsupported scheme in OS package URL %s", pkgURL.String())

				continue
			}

			filename := filepath.Base(pkgURL.Path)
			if ext := filepath.Ext(filename); ext != ospkg.OSPackageExt {
				stlog.Debug("Skip %s: package URL must contain a path to a %s file: %s", ospkg.OSPackageExt, pkgURL.String())

				continue
			}

			stlog.Debug("Downloading %s", pkgURL.String())

			aBytes, err = network.Download(pkgURL, roots)
			if err != nil {
				stlog.Debug("Skip %s: %v", url.String(), err)

				continue
			}

			stlog.Debug("Content type: %s", http.DetectContentType(aBytes))

			// create sample
			archiveReader := uio.NewLazyOpener(func() (io.Reader, error) {
				return bytes.NewReader(aBytes), nil
			})
			descriptorReader := uio.NewLazyOpener(func() (io.Reader, error) {
				return bytes.NewReader(dBytes), nil
			})
			sample.name = filename
			sample.archive = archiveReader
			sample.descriptor = descriptorReader

			return &sample, nil
		}

		stlog.Debug("all provisioning URLs failed")

		return nil, errDownload
	}

	stlog.Debug("no provisioning URLs")

	return nil, errDownload
}

const errNetworkLoad = Error("network load failed")

func networkLoad(hostCfg *host.Config, httpsRoots []*x509.Certificate) (*ospkgSampl, error) {
	stlog.Debug("Provisioning URLs:")

	if hostCfg.ProvisioningURLs != nil {
		for _, u := range *hostCfg.ProvisioningURLs {
			stlog.Debug(" - %s", u.String())
		}
	}

	if len(httpsRoots) == 0 {
		stlog.Debug("httpsRoots must not be empty")

		return nil, errNetworkLoad
	}

	roots := x509.NewCertPool()
	for _, cert := range httpsRoots {
		roots.AddCert(cert)
	}

	var (
		err    error
		sample *ospkgSampl
	)

	const (
		retries   = 8
		retryWait = 1
	)

	for iter := 0; iter < retries; iter++ {
		sample, err = doDownload(hostCfg, roots)
		if err == nil {
			break
		}

		time.Sleep(time.Second * time.Duration(retryWait))
		stlog.Debug("All provisioning URLs failed, retry %v", iter+1)
	}

	return sample, err
}
