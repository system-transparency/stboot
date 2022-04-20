// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/system-transparency/efivar/efivarfs"
	"github.com/system-transparency/stboot/host"
	"github.com/system-transparency/stboot/host/network"
	"github.com/system-transparency/stboot/opts"
	"github.com/system-transparency/stboot/ospkg"
	"github.com/system-transparency/stboot/stlog"
	"github.com/u-root/u-root/pkg/boot"
	"github.com/u-root/u-root/pkg/mount"
	"github.com/u-root/u-root/pkg/uio"
)

const (
	logLevelHelp      = "Level of logging: w 'warn', e 'error', i 'info', d 'debug'."
	klogHelp          = "Write log output to kernel syslog"
	dryRunHelp        = "Stop before kexec-ing into the loaded OS kernel"
	tlsSkipVerifyHelp = "No verification of the provisioning server's HTTPS certificate chain and host name"
	hostCfgHelp       = `Location of Host Configuration file.
inside initramfs:       "/path/to/host_configuration.json"
as efivar:              "efivar:YOURID-d736a263-c838-4702-9df4-50134ad8a636"
as cdrom:               "cdrom:/path/to/host_configuration.json"
STBOOT (fix location):  "legacy"
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

type ospkgSampl struct {
	name       string
	descriptor io.ReadCloser
	archive    io.ReadCloser
}

// nolint:funlen,gocognit,gocyclo,maintidx
func main() {
	logLevel := flag.String("loglevel", "warn", logLevelHelp)
	klog := flag.Bool("klog", false, klogHelp)
	dryRun := flag.Bool("dryrun", false, dryRunHelp)
	tlsSkipVerify := flag.Bool("tlsskipverify", false, tlsSkipVerifyHelp)
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
		hostCfgLegacy
		hostCfgCdrom
	)

	hostCfg := struct {
		name     string
		location hostCfgLocation
	}{}

	{
		h := strings.Split(*flagHostCfg, ":")
		switch {
		case len(h) == 1 && h[0] == "legacy":
			hostCfg.name = host.HostConfigFile
			hostCfg.location = hostCfgLegacy
		case len(h) == 1 && len(h[0]) > 0:
			hostCfg.name = h[0]
			hostCfg.location = hostCfgInitramfs
		case len(h) == 2 && h[0] == "efivar" && len(h[1]) > 0:
			hostCfg.name = h[1]
			hostCfg.location = hostCfgEfivar
		case len(h) == 2 && h[0] == "cdrom" && len(h[1]) > 0:
			hostCfg.name = h[1]
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
	httpsRootLoader = &opts.HttpsRootsFile{File: httpsRootsFile}

	securityLoader = &opts.SecurityFile{Name: securityConfigFile}

	switch hostCfg.location {
	case hostCfgEfivar:
		_, err := mount.Mount("efivarfs", "/sys/firmware/efi/efivars", "efivarfs", "", 0)
		if err != nil {
			stlog.Error("mounting efivarfs: %v", err)
			host.Recover()
		}

		stlog.Info("mounted efivarfs at /sys/firmware/efi/efivars")

		_, r, err := efivarfs.SimpleReadVariable(hostCfg.name)
		if err != nil {
			stlog.Error("reading efivar %q: %v", hostCfg.name, err)
			host.Recover()
		}

		hostCfgLoader = &opts.HostCfgJSON{Reader: &r}
	case hostCfgInitramfs:
		hostCfgLoader = &opts.HostCfgFile{Name: hostCfg.name}
	case hostCfgLegacy:
		// Mount STBOOT partition
		if err := host.MountBootPartition(); err != nil {
			stlog.Error("mount STBOOT partition: %v", err)
			host.Recover()
		}

		p := filepath.Join(host.BootPartitionMountPoint, hostCfg.name)
		hostCfgLoader = &opts.HostCfgFile{Name: p}
	case hostCfgCdrom:
		if err := host.MountCdrom(); err != nil {
			stlog.Error("mount CDROM: %v", err)
			host.Recover()
		}

		p := filepath.Join(host.BootPartitionMountPoint, hostCfg.name)
		hostCfgLoader = &opts.HostCfgFile{Name: p}
	}

	stOptions, err := opts.NewOpts(securityLoader, hostCfgLoader, signingRootLoader, httpsRootLoader)
	if err != nil {
		stlog.Error("load opts: %v", err)
		host.Recover()
	}

	optsStr, _ := json.MarshalIndent(stOptions, "", "  ")
	stlog.Debug("Opts: %s", optsStr)

	var bootorder []string

	switch stOptions.BootMode {
	case opts.LocalBoot:
		// Mount STDATA partition
		if err = host.MountDataPartition(); err != nil {
			stlog.Error("mount STDATA partition: %v", err)
			host.Recover()
		}
		// Boot order
		if stOptions.BootMode == opts.LocalBoot {
			p := filepath.Join(host.DataPartitionMountPoint, host.LocalBootOrderFile)

			bootorder, err = LoadBootOrder(p, host.LocalOSPkgDir)
			if err != nil {
				stlog.Error("load boot order: %v", err)
				host.Recover()
			}
		}
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
	default:
		stlog.Error("invalid state: boot mode is not set")
		host.Recover()
	}

	// Update System time
	if stOptions.Timestamp != nil {
		if err = host.CheckSystemTime(*stOptions.Timestamp); err != nil {
			stlog.Error("%v", err)
			host.Recover()
		}
	}

	//////////////////
	// Load OS package
	//////////////////
	var ospkgSampls []*ospkgSampl

	switch stOptions.BootMode {
	case opts.NetworkBoot:
		stlog.Info("Loading OS package via network")

		if *tlsSkipVerify {
			stlog.Info("Insecure tlsSkipVerify flag is set. HTTPS certificate verification is not performed!")
		}

		s, err := networkLoad(&stOptions.HostCfg, stOptions.HttpsRoots, *tlsSkipVerify)
		if err != nil {
			stlog.Error("load OS package via network: %v", err)
			host.Recover()
		}

		ospkgSampls = append(ospkgSampls, s)
	case opts.LocalBoot:
		stlog.Info("Loading OS package from disk")

		ss, err := diskLoad(bootorder)
		if err != nil {
			stlog.Error("load OS package from disk: %v", err)
			host.Recover()
		}

		ospkgSampls = append(ospkgSampls, ss...)
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
		bootImg boot.OSImage
		osp     *ospkg.OSPackage
	)

	for _, sample := range ospkgSampls {
		stlog.Info("Processing OS package %s", sample.name)

		aBytes, err := ioutil.ReadAll(sample.archive)
		if err != nil {
			stlog.Debug("Read archive: %v", err)

			continue
		}

		dBytes, err := ioutil.ReadAll(sample.descriptor)
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

		n, valid, err := osp.Verify(stOptions.SigningRoot)
		if err != nil {
			stlog.Debug("Skip, error verifying OS package: %v", err)

			continue
		}

		threshold := stOptions.ValidSignatureThreshold
		if valid < threshold {
			stlog.Debug("Skip, not enough valid signatures: %d found, %d valid, %d required", n, valid, threshold)

			continue
		}

		stlog.Debug("Signatures: %d found, %d valid, %d required", n, valid, threshold)
		stlog.Info("OS package passed verification")
		stlog.Info(check)

		/////////////
		// Extract OS
		/////////////
		bootImg, err = osp.OSImage()
		if err != nil {
			stlog.Debug("Get boot image: %v", err)

			continue
		}

		switch t := bootImg.(type) {
		case *boot.LinuxImage:
			stlog.Debug("Got linux boot image from os package")
		case *boot.MultibootImage:
			stlog.Debug("Got tboot multiboot image from os package")
		default:
			stlog.Debug("Skip, unknown boot image type %T", t)

			continue
		}

		if stOptions.BootMode == opts.LocalBoot {
			currentPkgPath := filepath.Join(host.DataPartitionMountPoint, host.LocalOSPkgDir, sample.name)
			markCurrentOSpkg(currentPkgPath)
		}

		break
	} // end process-os-pkgs-loop

	for _, s := range ospkgSampls {
		s.archive.Close()
		s.descriptor.Close()
	}

	if bootImg == nil {
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
	securityConfigBytes, _ := json.Marshal(stOptions.Security)

	toBeMeasured = append(toBeMeasured, ospkgBytes)
	stlog.Debug(" - OS package zip: %d bytes", len(ospkgBytes))

	toBeMeasured = append(toBeMeasured, descriptorBytes)
	stlog.Debug(" - OS package descriptor: %d bytes", len(descriptorBytes))

	toBeMeasured = append(toBeMeasured, securityConfigBytes)
	stlog.Debug(" - Security configuration json: %d bytes", len(securityConfigBytes))

	toBeMeasured = append(toBeMeasured, stOptions.SigningRoot.Raw)
	stlog.Debug(" - Signing root cert ASN1 DER content: %d bytes", len(stOptions.SigningRoot.Raw))

	for n, c := range stOptions.HttpsRoots {
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

func markCurrentOSpkg(pkgPath string) {
	f := filepath.Join(host.DataPartitionMountPoint, host.CurrentOSPkgFile)
	current := pkgPath + string('\n')

	if err := ioutil.WriteFile(f, []byte(current), os.ModePerm); err != nil {
		stlog.Error("write current OS package: %v", err)
		host.Recover()
	}
}

// nolint:funlen,gocognit
func doDownload(hc *opts.HostCfg, insecure bool, roots *x509.CertPool) (*ospkgSampl, error) {
	var sample ospkgSampl

	for _, url := range *hc.ProvisioningURLs {
		stlog.Debug("Downloading %s", url.String())

		if strings.Contains(url.String(), "$ID") {
			stlog.Debug("replacing $ID with identity provided by the Host configuration")

			url, _ = url.Parse(strings.ReplaceAll(url.String(), "$ID", *hc.ID))
		}

		if strings.Contains(url.String(), "$AUTH") {
			stlog.Debug("replacing $AUTH with authentication provided by the Host configuration")

			url, _ = url.Parse(strings.ReplaceAll(url.String(), "$AUTH", *hc.Auth))
		}

		dBytes, err := network.Download(url, roots, insecure)
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

			aBytes, err = network.Download(pkgURL, roots, insecure)
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

			aBytes, err = network.Download(pkgURL, roots, insecure)
			if err != nil {
				stlog.Debug("Skip %s: %v", url.String(), err)

				continue
			}

			stlog.Debug("Content type: %s", http.DetectContentType(aBytes))

			// create sample
			ar := uio.NewLazyOpener(func() (io.Reader, error) {
				return bytes.NewReader(aBytes), nil
			})
			dr := uio.NewLazyOpener(func() (io.Reader, error) {
				return bytes.NewReader(dBytes), nil
			})
			sample.name = filename
			sample.archive = ar
			sample.descriptor = dr

			return &sample, nil
		}

		return nil, fmt.Errorf("all provisioning URLs failed")
	}

	return nil, fmt.Errorf("no provisioning URLs")
}

func networkLoad(hc *opts.HostCfg, httpsRoots []*x509.Certificate, insecure bool) (*ospkgSampl, error) {
	stlog.Debug("Provisioning URLs:")

	if hc.ProvisioningURLs != nil {
		for _, u := range *hc.ProvisioningURLs {
			stlog.Debug(" - %s", u.String())
		}
	}

	if len(httpsRoots) == 0 {
		return nil, fmt.Errorf("httpsRoots must not be empty")
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

	for i := 0; i < retries; i++ {
		sample, err = doDownload(hc, insecure, roots)
		if err == nil {
			break
		}

		time.Sleep(time.Second * time.Duration(retryWait))
		stlog.Debug("All provisioning URLs failed, retry %v", i+1)
	}

	return sample, err
}

func diskLoad(names []string) ([]*ospkgSampl, error) {
	dir := filepath.Join(host.DataPartitionMountPoint, host.LocalOSPkgDir)

	if len(names) == 0 {
		return nil, fmt.Errorf("names must not be empty")
	}

	samples := make([]*ospkgSampl, len(names))

	for _, name := range names {
		ap := filepath.Join(dir, name+ospkg.OSPackageExt)
		dp := filepath.Join(dir, name+ospkg.DescriptorExt)

		if _, err := os.Stat(ap); err != nil {
			return nil, err
		}

		if _, err := os.Stat(dp); err != nil {
			return nil, err
		}

		ar := uio.NewLazyOpener(func() (io.Reader, error) {
			return os.Open(ap)
		})
		dr := uio.NewLazyOpener(func() (io.Reader, error) {
			return os.Open(dp)
		})
		s := &ospkgSampl{
			name:       name,
			archive:    ar,
			descriptor: dr,
		}
		samples = append(samples, s)
	}

	return samples, nil
}

func LoadBootOrder(path, localOSPkgDir string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %v", err)
	}

	var names []string

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		names = append(names, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scann file: %v", err)
	}

	f.Close()

	if len(names) == 0 {
		return nil, fmt.Errorf("no entries found")
	}

	bootorder := make([]string, len(names))

	for _, name := range names {
		ext := filepath.Ext(name)
		if ext == ospkg.OSPackageExt || ext == ospkg.DescriptorExt {
			name = strings.TrimSuffix(name, ext)
		}

		p := filepath.Join(host.DataPartitionMountPoint, localOSPkgDir, name+ospkg.OSPackageExt)

		if _, err := os.Stat(p); err != nil {
			stlog.Debug("Skip %s: %v", name, err)

			continue
		}

		p = filepath.Join(host.DataPartitionMountPoint, localOSPkgDir, name+ospkg.DescriptorExt)

		if _, err = os.Stat(p); err != nil {
			stlog.Debug("Skip %s: %v", name, err)

			continue
		}

		bootorder = append(bootorder, name)
	}

	if len(bootorder) == 0 {
		return nil, fmt.Errorf("no valid entries found")
	}

	return bootorder, nil
}
