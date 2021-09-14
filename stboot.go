// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/system-transparency/stboot/host"
	"github.com/system-transparency/stboot/host/network"
	"github.com/system-transparency/stboot/ospkg"
	"github.com/system-transparency/stboot/stlog"
	"github.com/system-transparency/stboot/sysconf"
	"github.com/u-root/u-root/pkg/boot"
	"github.com/u-root/u-root/pkg/uio"
)

// Flags
var (
	doDebug       = flag.Bool("debug", false, "Print additional debug output")
	klog          = flag.Bool("klog", false, "Print output to all attached consoles via the kernel log")
	dryRun        = flag.Bool("dryrun", false, "Do everything except booting the loaded kernel")
	tlsSkipVerify = flag.Bool("tlsskipverify", false, "Controls whether a client verifies the provisioning server's HTTPS certificate chain and host name")
)

// Files at initramfs
const (
	securityConfigFile = "/etc/security_configuration.json"
	signingRootFile    = "/etc/ospkg_signing_root.pem"
	httpsRootsFile     = "/etc/https_roots.pem"
)

// Files at STBOOT partition
const (
	hostConfigurationFile = "/host_configuration.json"
)

// Files at STDATA partition
const (
	timeFixFile        = "stboot/etc/system_time_fix"
	currentOSPkgFile   = "stboot/etc/current_ospkg_pathname"
	localOSPkgDir      = "stboot/os_pkgs/local/"
	localBootOrderFile = "stboot/os_pkgs/local/boot_order"
	networkOSpkgCache  = "stboot/os_pkgs/cache"
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

func main() {

	flag.Parse()
	if *klog {
		stlog.SetOutout(stlog.KernelSyslog)
	} else {
		stlog.SetOutout(stlog.StdError)
	}
	if *doDebug {
		stlog.SetLevel(stlog.DebugLevel)
	} else {
		stlog.SetLevel(stlog.InfoLevel)
	}

	stlog.Info(banner)

	/////////////////////
	// Validation & Setup
	/////////////////////

	// Security Configuration
	securityConfig, err := loadSecurityConfig(securityConfigFile)
	if err != nil {
		stlog.Error("load security config: %v", err)
		host.Recover()
	}

	// Signing root certificate
	signingRoot, err := loadSigningRoot(signingRootFile)
	if err != nil {
		stlog.Error("load signing root: %v", err)
		host.Recover()
	}

	// HTTPS root certificates
	var httpsRoots []*x509.Certificate
	if securityConfig.BootMode == sysconf.Network {
		httpsRoots, err = loadHTTPSRoots(httpsRootsFile)
		if err != nil {
			stlog.Error("load HTTPS roots: %v", err)
			host.Recover()
		}
	}

	// STBOOT and STDATA partitions
	part := &host.AbstractPartition{
		Partition: &host.RealPartition{},
	}
	if err = part.MountBootPartition(); err != nil {
		stlog.Error("mount STBOOT partition: %v", err)
		host.Recover()
	}
	if err = part.MountDataPartition(); err != nil {
		stlog.Error("mount STDATA partition: %v", err)
		host.Recover()
	}
	if err = validatePartitions(securityConfig.BootMode); err != nil {
		stlog.Error("invalid partition: %v", err)
		host.Recover()
	}

	// Host configuration
	p := filepath.Join(host.BootPartitionMountPoint, hostConfigurationFile)
	hostConfig, err := loadHostConfig(p, securityConfig.BootMode == sysconf.Network)
	if err != nil {
		stlog.Error("load host config: %v", err)
		host.Recover()
	}

	// Boot order
	var bootorder []string
	if securityConfig.BootMode == sysconf.Local {
		p = filepath.Join(host.DataPartitionMountPoint, localBootOrderFile)
		bootorder, err = loadBootOrder(p)
		if err != nil {
			stlog.Error("load boot order: %v", err)
			host.Recover()
		}
	}

	// System time
	p = filepath.Join(host.DataPartitionMountPoint, timeFixFile)
	buildTime, err := loadSystemTimeFix(p)
	if err != nil {
		stlog.Error("load system time fix: %v", err)
		host.Recover()
	}
	if err = host.CheckSystemTime(buildTime); err != nil {
		stlog.Error("%v", err)
		host.Recover()
	}

	// Network interface
	if securityConfig.BootMode == sysconf.Network {
		switch hostConfig.NetworkMode {
		case sysconf.Static:
			if err := network.ConfigureStatic(hostConfig); err != nil {
				stlog.Error("cannot set up IO: %v", err)
				host.Recover()
			}
		case sysconf.DHCP:
			if err := network.ConfigureDHCP(hostConfig, *doDebug); err != nil {
				stlog.Error("cannot set up IO: %v", err)
				host.Recover()
			}
		default:
			stlog.Error("unknown network mode: %s", hostConfig.NetworkMode.String())
			host.Recover()
		}
		if hostConfig.DNSServer != nil {
			stlog.Info("Set DNS Server %s", hostConfig.DNSServer.String())
			if err := network.SetDNSServer(hostConfig.DNSServer); err != nil {
				stlog.Error("set DNS Server: %v", err)
				host.Recover()
			}
		}
	}

	// TXT
	stlog.Info("TXT self tests are not implementet yet.")
	txtHostSuport := false

	//////////////////
	// Load OS package
	//////////////////
	var ospkgSampls []*ospkgSampl

	switch securityConfig.BootMode {
	case sysconf.Network:
		stlog.Info("Loading OS package via network")
		provUrls, err := hostConfig.ParseProvisioningURLs()
		if err != nil {
			stlog.Error("parse provisioning URLs: %v", err)
			host.Recover()
		}
		if *tlsSkipVerify {
			stlog.Info("Insecure tlsSkipVerify flag is set. HTTPS certificate verification is not performed!")
		}
		s, err := networkLoad(provUrls, securityConfig.UsePkgCache, httpsRoots, *tlsSkipVerify)
		if err != nil {
			stlog.Error("load OS package via network: %v", err)
			host.Recover()
		}
		ospkgSampls = append(ospkgSampls, s)
	case sysconf.Local:
		stlog.Info("Loading OS package from disk")
		ss, err := diskLoad(bootorder)
		if err != nil {
			stlog.Error("load OS package from disk: %v", err)
			host.Recover()
		}
		ospkgSampls = append(ospkgSampls, ss...)
	default:
		stlog.Error("unsupported boot mode: %s", securityConfig.BootMode.String())
		host.Recover()
	}
	if len(ospkgSampls) == 0 {
		stlog.Error("No OS packages found")
	}

	stlog.Debug("OS packages to be processed:")
	for _, s := range ospkgSampls {
		stlog.Debug(" - %s", s.name)
	}

	//////////////////////
	// Process OS packages
	//////////////////////
	var bootImg boot.OSImage
	var osp *ospkg.OSPackage
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

		//TODO: write ospkg.info method for debug output

		n, valid, err := osp.Verify(signingRoot)
		if err != nil {
			stlog.Debug("Skip, error verifying OS package: %v", err)
			continue
		}
		threshold := securityConfig.MinimalSignaturesMatch
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
		bootImg, err = osp.OSImage(txtHostSuport)
		if err != nil {
			stlog.Debug("Get boot image: %v", err)
			continue
		}
		switch t := bootImg.(type) {
		case *boot.LinuxImage:
			if txtHostSuport {
				stlog.Debug("TXT is supported on the host, but the os package doesn't provide tboot")
			}
			stlog.Debug("Got linux boot image from os package")
		case *boot.MultibootImage:
			stlog.Debug("Got tboot multiboot image from os package")
		default:
			stlog.Debug("Skip, unknown boot image type %T", t)
			continue
		}

		// write cache
		if securityConfig.BootMode == sysconf.Network && securityConfig.UsePkgCache {
			dir := filepath.Join(host.DataPartitionMountPoint, networkOSpkgCache)
			stlog.Debug("Caching OS package in %s", dir)
			// clear
			d, err := os.Open(dir)
			if err != nil {
				stlog.Error("clear cache: %v", err)
				host.Recover()
			}
			defer d.Close()
			names, err := d.Readdirnames(-1)
			if err != nil {
				stlog.Error("clear cache: %v", err)
				host.Recover()
			}
			for _, name := range names {
				err = os.RemoveAll(filepath.Join(dir, name))
				if err != nil {
					stlog.Error("clear cache: %v", err)
					host.Recover()
				}
			}
			// write
			p := filepath.Join(dir, sample.name)
			if err := ioutil.WriteFile(p, aBytes, 0666); err != nil {
				stlog.Error("write pkg cache: %v", err)
				host.Recover()
			}
		}

		var currentPkgPath string
		if securityConfig.BootMode == sysconf.Local {
			currentPkgPath = filepath.Join(host.DataPartitionMountPoint, localOSPkgDir, sample.name)
		} else if securityConfig.BootMode == sysconf.Network && securityConfig.UsePkgCache {
			currentPkgPath = filepath.Join(host.DataPartitionMountPoint, networkOSpkgCache, sample.name)
		} else {
			currentPkgPath = "UNCACHED_NETWORK_OS_PACKAGE"
		}
		markCurrentOSpkg(currentPkgPath)

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
	securityConfigBytes, _ := json.Marshal(securityConfig)

	toBeMeasured = append(toBeMeasured, ospkgBytes)
	stlog.Debug(" - OS package zip: %d bytes", len(ospkgBytes))
	toBeMeasured = append(toBeMeasured, descriptorBytes)
	stlog.Debug(" - OS package descriptor: %d bytes", len(descriptorBytes))
	toBeMeasured = append(toBeMeasured, securityConfigBytes)
	stlog.Debug(" - Security configuration json: %d bytes", len(securityConfigBytes))
	toBeMeasured = append(toBeMeasured, signingRoot.Raw)
	stlog.Debug(" - Signing root cert ASN1 DER content: %d bytes", len(signingRoot.Raw))
	for n, c := range httpsRoots {
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
	err = bootImg.Load(false)
	if err != nil {
		stlog.Error("%s", err)
		host.Recover()
	}
	stlog.Info("Handing over controll - kexec")
	err = boot.Execute()
	if err != nil {
		stlog.Error("%v", err)
	}

	stlog.Error("unexpected return from kexec")
	host.Recover()
}

func markCurrentOSpkg(pkgPath string) {
	f := filepath.Join(host.DataPartitionMountPoint, currentOSPkgFile)
	current := pkgPath + string('\n')
	if err := ioutil.WriteFile(f, []byte(current), os.ModePerm); err != nil {
		stlog.Error("write current OS package: %v", err)
		host.Recover()
	}
}

func networkLoad(urls []*url.URL, useCache bool, httpsRoots []*x509.Certificate, insecure bool) (*ospkgSampl, error) {
	var sample ospkgSampl

	stlog.Debug("Provisioning URLs:")
	for _, u := range urls {
		stlog.Debug(" - %s", u.String())
	}

	if len(httpsRoots) == 0 {
		return nil, fmt.Errorf("httpsRoots must not be empty")
	}
	roots := x509.NewCertPool()
	for _, cert := range httpsRoots {
		roots.AddCert(cert)
	}

	for _, url := range urls {
		stlog.Debug("Downloading %s", url.String())
		dBytes, err := network.Download(url, roots, insecure, *doDebug)
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
		if useCache {
			stlog.Debug("Look up OS package cache")
			dir := filepath.Join(host.DataPartitionMountPoint, networkOSpkgCache)
			fis, err := ioutil.ReadDir(dir)
			if err != nil {
				stlog.Error("read cache: %v", err)
				host.Recover()
			}
			for _, fi := range fis {
				if fi.Name() == filename {
					p := filepath.Join(dir, filename)
					stlog.Info("Using cached OS package %s", p)
					aBytes, err = ioutil.ReadFile(p)
					if err != nil {
						stlog.Error("read cache: %v", err)
						host.Recover()
					}
					break
				}
			}
			if aBytes == nil {
				stlog.Debug("%s is not cached", filename)
			}
		}
		if aBytes == nil {
			stlog.Debug("Downloading %s", pkgURL.String())
			aBytes, err = network.Download(pkgURL, roots, insecure, *doDebug)
			if err != nil {
				stlog.Debug("Skip %s: %v", url.String(), err)
				continue
			}
			stlog.Debug("Content type: %s", http.DetectContentType(aBytes))
		}

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

func diskLoad(names []string) ([]*ospkgSampl, error) {
	var samples []*ospkgSampl
	dir := filepath.Join(host.DataPartitionMountPoint, localOSPkgDir)
	if len(names) == 0 {
		return nil, fmt.Errorf("names must not be empty")
	}
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

func validatePartitions(mode sysconf.Bootmode) error {
	//STBOOT host config file
	p := filepath.Join(host.BootPartitionMountPoint, hostConfigurationFile)
	_, err := os.Stat(p)
	if err != nil {
		return fmt.Errorf("STBOOT: missing file %s", hostConfigurationFile)
	}
	// STDATA /etc dir
	etcDir := filepath.Dir(currentOSPkgFile)
	p = filepath.Join(host.DataPartitionMountPoint, etcDir)
	stat, err := os.Stat(p)
	if err != nil || !stat.IsDir() {
		return fmt.Errorf("STDATA: missing directory %s", etcDir)
	}
	//STDATA timefix file
	p = filepath.Join(host.DataPartitionMountPoint, timeFixFile)
	_, err = os.Stat(p)
	if err != nil {
		return fmt.Errorf("STDATA: missing file %s", timeFixFile)
	}
	if mode == sysconf.Local {
		// STDATA local packages dir
		p = filepath.Join(host.DataPartitionMountPoint, localOSPkgDir)
		stat, err := os.Stat(p)
		if err != nil || !stat.IsDir() {
			return fmt.Errorf("STDATA: missing directory %s", localOSPkgDir)
		}
		//STDATA local boot order file
		p = filepath.Join(host.DataPartitionMountPoint, localBootOrderFile)
		_, err = os.Stat(p)
		if err != nil {
			return fmt.Errorf("STDATA: missing file %s", localBootOrderFile)
		}
	}
	if mode == sysconf.Network {
		// STDATA network cache dir
		p = filepath.Join(host.DataPartitionMountPoint, networkOSpkgCache)
		stat, err := os.Stat(p)
		if err != nil || !stat.IsDir() {
			return fmt.Errorf("STDATA: missing directory %s", networkOSpkgCache)
		}
	}
	return nil
}

func loadSecurityConfig(path string) (*sysconf.SecurityConfig, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %v", err)
	}
	var sc sysconf.SecurityConfig
	if err = json.Unmarshal(b, &sc); err != nil {
		return nil, fmt.Errorf("parsing JSON failed: %v", err)
	}

	str, _ := json.MarshalIndent(sc, "", "  ")
	stlog.Debug("Security configuration: %s", str)

	if err = sc.Validate(); err != nil {
		return nil, fmt.Errorf("invalid: %v", err)
	}
	return &sc, nil
}

func loadSigningRoot(path string) (*x509.Certificate, error) {
	pemBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %v", err)
	}
	stlog.Debug("Signing root certificate:\n%s", string(pemBytes))
	pemBlock, rest := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("decoding PEM failed")
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("unexpeceted trailing data")
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing x509 failed: %v", err)
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, fmt.Errorf("certificate has expired or is not yet valid")
	}
	return cert, nil
}

func loadHTTPSRoots(path string) ([]*x509.Certificate, error) {
	pemBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %v", err)
	}
	var roots []*x509.Certificate
	for len(pemBytes) > 0 {
		var block *pem.Block
		var n = 1
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		certBytes := block.Bytes
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			continue
		}
		stlog.Debug("HTTPS root certificate %d: ", n)
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
		roots = append(roots, cert)
		n++
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("no certifiates found")
	}
	return roots, nil
}

func loadHostConfig(path string, validateNetwork bool) (*sysconf.HostConfig, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %v", err)
	}
	var hc *sysconf.HostConfig
	err = json.Unmarshal(bytes, &hc)
	if err != nil {
		return nil, fmt.Errorf("parsing JSON failed: %v", err)
	}

	hcCpy := *hc
	hcCpy.Auth = strings.Repeat("*", len(hc.Auth))
	str, _ := json.MarshalIndent(hcCpy, "", "  ")
	stlog.Info("Host configuration: %s", str)

	if err = hc.Validate(validateNetwork); err != nil {
		return nil, fmt.Errorf("invalid: %v", err)
	}
	return hc, nil
}

func loadBootOrder(path string) ([]string, error) {
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

	var bootorder []string
	for _, name := range names {
		ext := filepath.Ext(name)
		if ext == ospkg.OSPackageExt || ext == ospkg.DescriptorExt {
			name = strings.TrimSuffix(name, ext)
		}
		p := filepath.Join(host.DataPartitionMountPoint, localOSPkgDir, name+ospkg.OSPackageExt)
		_, err := os.Stat(p)
		if err != nil {
			stlog.Debug("Skip %s: %v", name, err)
			continue
		}
		p = filepath.Join(host.DataPartitionMountPoint, localOSPkgDir, name+ospkg.DescriptorExt)
		_, err = os.Stat(p)
		if err != nil {
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

func loadSystemTimeFix(path string) (time.Time, error) {
	var t time.Time
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		return t, fmt.Errorf("read file: %v", err)
	}
	t, err = host.ParseUNIXTimestamp(string(raw))
	if err != nil {
		return t, fmt.Errorf("parse UNIX timestamp: %v", err)
	}
	return t, nil
}
