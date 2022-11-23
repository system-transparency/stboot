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
	"path/filepath"
	"strings"
	"time"

	"git.glasklar.is/system-transparency/core/stboot/host"
	"git.glasklar.is/system-transparency/core/stboot/host/network"
	"git.glasklar.is/system-transparency/core/stboot/opts"
	"git.glasklar.is/system-transparency/core/stboot/ospkg"
	"git.glasklar.is/system-transparency/core/stboot/stlog"
	"github.com/u-root/u-root/pkg/boot"
	"github.com/u-root/u-root/pkg/efivarfs"
	"github.com/u-root/u-root/pkg/uio"
)

const (
	logLevelHelp = "Level of logging: w 'warn', e 'error', i 'info', d 'debug'."
	klogHelp     = "Write log output to kernel syslog"
	dryRunHelp   = "Stop before kexec-ing into the loaded OS kernel"
	hostCfgHelp  = `Location of Host Configuration file.
inside initramfs:       "/path/to/host_configuration.json"
as efivar:              "efivar:YOURID-d736a263-c838-4702-9df4-50134ad8a636"
as cdrom:               "cdrom:/path/to/host_configuration.json"
`
)

// Files at initramfs.
const (
	hostCfgFile        = "/etc/host_configuration.json"
	securityConfigFile = "/etc/security_configuration.json"
	signingRootFile    = "/etc/ospkg_signing_root.pem"
	httpsRootsFile     = "/etc/https_roots.pem"
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

// nolint:funlen,gocognit,gocyclo,maintidx,cyclop
func main() {
	logLevel := flag.String("loglevel", "warn", logLevelHelp)
	klog := flag.Bool("klog", false, klogHelp)
	dryRun := flag.Bool("dryrun", false, dryRunHelp)
	flagHostCfg := flag.String("host-config", hostCfgFile, hostCfgHelp)

	flag.Parse()

	if *klog {
		stlog.SetOutput(stlog.KernelSyslog)
	} else {
		stlog.SetOutput(stlog.StdError)
	}

	switch *logLevel {
	case "e", "error":
		stlog.SetLevel(stlog.ErrorLevel)
	case "i", "info":
		stlog.SetLevel(stlog.InfoLevel)
	case "d", "debug":
		stlog.SetLevel(stlog.DebugLevel)
	case "w", "warm":
		stlog.SetLevel(stlog.WarnLevel)
	default:
		stlog.SetLevel(stlog.WarnLevel)
	}

	// parse host configuration flag
	type hostCfgLocation int

	const (
		hostCfgInitramfs hostCfgLocation = iota
		hostCfgEfivar
		hostCfgCdrom
	)

	hostCfg := struct {
		name     string
		location hostCfgLocation
	}{}

	{
		hcflag := strings.Split(*flagHostCfg, ":")
		switch {
		case len(hcflag) == 1 && len(hcflag[0]) > 0:
			hostCfg.name = hcflag[0]
			hostCfg.location = hostCfgInitramfs
		case len(hcflag) == 2 && hcflag[0] == "efivar" && len(hcflag[1]) > 0:
			hostCfg.name = hcflag[1]
			hostCfg.location = hostCfgEfivar
		case len(hcflag) == 2 && hcflag[0] == "cdrom" && len(hcflag[1]) > 0:
			hostCfg.name = hcflag[1]
			hostCfg.location = hostCfgCdrom
		default:
			stlog.Error("invalid host-config value: \"%s\"", *flagHostCfg)
			host.Recover()
		}
	}

	stlog.Info(banner)

	flag.Visit(func(f *flag.Flag) {
		stlog.Debug("-%s %s", f.Name, f.Value)
	})

	/////////////////////
	// Validation & Setup
	/////////////////////

	// load options
	var signingRootLoader, httpsRootLoader, securityLoader, hostCfgLoader opts.Loader

	// Define loader for signing root certificate
	signingRootLoader = &opts.SigningRootFile{File: signingRootFile}

	// Define loader for https root certificate
	httpsRootLoader = &opts.HTTPSRootsFile{File: httpsRootsFile}

	securityLoader = &opts.SecurityFile{Name: securityConfigFile}

	switch hostCfg.location {
	case hostCfgEfivar:
		// To be able to build stboot initramfs with newer u-root versions where
		// the efivarfs is already mounted by u-root's init. Will fail on older u-root versions.
		// Implement proper error handling.
		// _, err := mount.Mount("efivarfs", "/sys/firmware/efi/efivars", "efivarfs", "", 0)
		// if err != nil {
		// 	stlog.Error("mounting efivarfs: %v", err)
		// 	host.Recover()
		// }
		// stlog.Info("mounted efivarfs at /sys/firmware/efi/efivars")
		_, efiReader, err := efivarfs.SimpleReadVariable(hostCfg.name)
		if err != nil {
			stlog.Error("reading efivar %q: %v", hostCfg.name, err)
			host.Recover()
		}

		hostCfgLoader = &opts.HostCfgJSON{Reader: efiReader}
	case hostCfgInitramfs:
		hostCfgLoader = &opts.HostCfgFile{Name: hostCfg.name}
	case hostCfgCdrom:
		if err := host.MountCdrom(); err != nil {
			stlog.Error("mount CDROM: %v", err)
			host.Recover()
		}

		p := filepath.Join(host.MountPoint, hostCfg.name)
		hostCfgLoader = &opts.HostCfgFile{Name: p}
	}

	stOptions, err := opts.NewOpts(securityLoader, hostCfgLoader, signingRootLoader, httpsRootLoader)
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
		// Network interface
		switch stOptions.IPAddrMode {
		case opts.IPStatic:
			if err := network.ConfigureStatic(&stOptions.HostCfg); err != nil {
				stlog.Error("cannot set up IO: %v", err)
				host.Recover()
			}
		case opts.IPDynamic:
			if err := network.ConfigureDHCP(&stOptions.HostCfg); err != nil {
				stlog.Error("cannot set up IO: %v", err)
				host.Recover()
			}
		case opts.IPUnset:
		default:
			stlog.Error("invalid state: IP addr mode is not set")
			host.Recover()
		}

		if stOptions.DNSServer != nil {
			stlog.Info("Set DNS Server %s", stOptions.DNSServer.String())

			if err := network.SetDNSServer(*stOptions.DNSServer); err != nil {
				stlog.Error("set DNS Server: %v", err)
				host.Recover()
			}
		}
	case opts.BootModeUnset:
	default:
		stlog.Error("invalid state: boot mode is not set")
		host.Recover()
	}

	//////////////////
	// Load OS package
	//////////////////
	var ospkgSampls []*ospkgSampl

	switch stOptions.BootMode {
	case opts.NetworkBoot:
		stlog.Info("Loading OS package via network")

		sample, err := networkLoad(&stOptions.HostCfg, stOptions.HTTPSRoots)
		if err != nil {
			stlog.Error("load OS package via network: %v", err)
			host.Recover()
		}

		ospkgSampls = append(ospkgSampls, sample)
	case opts.BootModeUnset:
	default:
		stlog.Error("invalid state: boot mode is not set")
		host.Recover()
	}

	if len(ospkgSampls) == 0 {
		stlog.Error("No OS packages found")
		host.Recover()
	}

	stlog.Debug("OS packages to be processed:")

	for _, s := range ospkgSampls {
		stlog.Debug(" - %s", s.name)
	}

	//////////////////////
	// Process OS packages
	//////////////////////
	var (
		bootImg boot.LinuxImage
		osp     *ospkg.OSPackage
	)

	for _, sample := range ospkgSampls {
		stlog.Info("Processing OS package %s", sample.name)

		aBytes, err := io.ReadAll(sample.archive)
		if err != nil {
			stlog.Debug("Read archive: %v", err)

			continue
		}

		dBytes, err := io.ReadAll(sample.descriptor)
		if err != nil {
			stlog.Debug("Read archive: %v", err)

			continue
		}

		osp, err = ospkg.NewOSPackage(aBytes, dBytes)
		if err != nil {
			stlog.Debug("Create OS package: %v", err)

			continue
		}

		////////////////////
		// Verify OS package
		////////////////////

		// nolint:godox
		// TODO: write ospkg.info method for debug output

		numSig, valid, err := osp.Verify(stOptions.SigningRoot)
		if err != nil {
			stlog.Debug("Skip, error verifying OS package: %v", err)

			continue
		}

		threshold := stOptions.ValidSignatureThreshold
		if valid < threshold {
			stlog.Debug("Skip, not enough valid signatures: %d found, %d valid, %d required", numSig, valid, threshold)

			continue
		}

		stlog.Debug("Signatures: %d found, %d valid, %d required", numSig, valid, threshold)
		stlog.Info("OS package passed verification")
		stlog.Info(check)

		/////////////
		// Extract OS
		/////////////
		bootImg, err = osp.LinuxImage()
		if err != nil {
			stlog.Debug("Get boot image: %v", err)

			continue
		}

		break
	} // end process-os-pkgs-loop

	for _, s := range ospkgSampls {
		s.archive.Close()
		s.descriptor.Close()
	}

	if bootImg.Kernel == nil {
		stlog.Error("No usable OS package")
		host.Recover()
	}

	stlog.Debug("Boot image:\n %s", bootImg.String())

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

	if err = bootImg.Load(false); err != nil {
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

// nolint:funlen,gocognit,cyclop
func doDownload(hostCfg *opts.HostCfg, roots *x509.CertPool) (*ospkgSampl, error) {
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

func networkLoad(hostCfg *opts.HostCfg, httpsRoots []*x509.Certificate) (*ospkgSampl, error) {
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
