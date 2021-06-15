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
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/system-transparency/stboot/pkg/stboot"
	"github.com/u-root/u-root/pkg/boot"
	"github.com/u-root/u-root/pkg/recovery"
	"github.com/u-root/u-root/pkg/uio"
	"github.com/u-root/u-root/pkg/ulog"
)

// Flags
var (
	doDebug       = flag.Bool("debug", false, "Print additional debug output")
	klog          = flag.Bool("klog", false, "Print output to all attached consoles via the kernel log")
	dryRun        = flag.Bool("dryrun", false, "Do everything except booting the loaded kernel")
	tlsSkipVerify = flag.Bool("tlsskipverify", false, "Controls whether a client verifies the provisioning server's HTTPS certificate chain and host name")
)
var debug = func(string, ...interface{}) {}

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

var banner = `
  _____ _______   _____   ____   ____________
 / ____|__   __|  |  _ \ / __ \ / __ \__   __|
| (___    | |     | |_) | |  | | |  | | | |   
 \___ \   | |     |  _ <| |  | | |  | | | |   
 ____) |  | |     | |_) | |__| | |__| | | |   
|_____/   |_|     |____/ \____/ \____/  |_|   

`

var check = `           
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
	log.SetFlags(0) // no time or date
	log.SetPrefix("stboot: ")
	ulog.KernelLog.SetLogLevel(ulog.KLogNotice)
	ulog.KernelLog.SetConsoleLogLevel(ulog.KLogInfo)

	flag.Parse()
	if *doDebug {
		debug = info
	}

	info(banner)

	/////////////////////
	// Validation & Setup
	/////////////////////

	// Security Configuration
	securityConfig, err := loadSecurityConfig(securityConfigFile)
	if err != nil {
		reboot("load security config: %v", err)
	}

	// Signing root certificate
	signingRoot, err := loadSigningRoot(signingRootFile)
	if err != nil {
		reboot("load signing root: %v", err)
	}

	// HTTPS root certificates
	var httpsRoots []*x509.Certificate
	if securityConfig.BootMode == Network {
		httpsRoots, err = loadHTTPSRoots(httpsRootsFile)
		if err != nil {
			reboot("load HTTPS roots: %v", err)
		}
	}

	// STBOOT and STDATA partitions
	if err = mountBootPartition(); err != nil {
		reboot("mount STBOOT partition: %v", err)
	}
	if err = mountDataPartition(); err != nil {
		reboot("mount STDATA partition: %v", err)
	}
	if err = validatePartitions(securityConfig.BootMode); err != nil {
		reboot("invalid partition: %v", err)
	}

	// Host configuration
	p := filepath.Join(bootPartitionMountPoint, hostConfigurationFile)
	hostConfig, err := loadHostConfig(p, securityConfig.BootMode == Network)
	if err != nil {
		reboot("load host config: %v", err)
	}

	// Boot order
	var bootorder []string
	if securityConfig.BootMode == Local {
		p = filepath.Join(dataPartitionMountPoint, localBootOrderFile)
		bootorder, err = loadBootOrder(p)
		if err != nil {
			reboot("load boot order: %v", err)
		}
	}

	// System time
	p = filepath.Join(dataPartitionMountPoint, timeFixFile)
	buildTime, err := loadSystemTimeFix(p)
	if err != nil {
		reboot("load system time fix: %v", err)
	}
	if err = checkSystemTime(buildTime); err != nil {
		reboot("%v", err)
	}

	// Network interface
	if securityConfig.BootMode == Network {
		switch hostConfig.NetworkMode {
		case Static:
			if err := configureStaticNetwork(hostConfig); err != nil {
				reboot("cannot set up IO: %v", err)
			}
		case DHCP:
			if err := configureDHCPNetwork(hostConfig); err != nil {
				reboot("cannot set up IO: %v", err)
			}
		default:
			reboot("unknown network mode: %s", hostConfig.NetworkMode.String())
		}
		if hostConfig.DNSServer != nil {
			info("set DNS Server %s", hostConfig.DNSServer.String())
			if err := setDNSServer(hostConfig.DNSServer); err != nil {
				reboot("set DNS Server: %v", err)
			}
		}
	}

	// TXT
	info("TXT self tests are not implementet yet.")
	txtHostSuport := false

	//////////////////
	// Load OS package
	//////////////////
	var ospkgSampls []*ospkgSampl

	switch securityConfig.BootMode {
	case Network:
		info("Loading OS package via network")
		provUrls, err := hostConfig.ParseProvisioningURLs()
		if err != nil {
			reboot("parse provisioning URLs: %v", err)
		}
		if *tlsSkipVerify {
			info("WARNING: insecure tlsSkipVerify flag is set. HTTPS certificate verification is not performed!")
		}
		s, err := networkLoad(provUrls, securityConfig.UsePkgCache, httpsRoots, *tlsSkipVerify)
		if err != nil {
			reboot("load OS package via network: %v", err)
		}
		ospkgSampls = append(ospkgSampls, s)
	case Local:
		info("Loading OS package from disk")
		ss, err := diskLoad(bootorder)
		if err != nil {
			reboot("load OS package from disk: %v", err)
		}
		ospkgSampls = append(ospkgSampls, ss...)
	default:
		reboot("unsupported boot mode: %s", securityConfig.BootMode.String())
	}
	if len(ospkgSampls) == 0 {
		reboot("No OS packages found")
	}
	if *doDebug {
		info("OS packages to be processed:")
		for _, s := range ospkgSampls {
			info(" - %s", s.name)
		}
	}

	//////////////////////
	// Process OS packages
	//////////////////////
	var bootImg boot.OSImage
	var ospkg *stboot.OSPackage
	for _, sample := range ospkgSampls {
		info("Processing OS package %s", sample.name)
		aBytes, err := ioutil.ReadAll(sample.archive)
		if err != nil {
			debug("read archive: %v", err)
			continue
		}
		dBytes, err := ioutil.ReadAll(sample.descriptor)
		if err != nil {
			debug("read archive: %v", err)
			continue
		}
		ospkg, err = stboot.NewOSPackage(aBytes, dBytes)
		if err != nil {
			debug("create OS package: %v", err)
			continue
		}

		////////////////////
		// Verify OS package
		////////////////////
		// if *doDebug {
		// 	//TODO: write ospkg.info method
		// }

		n, valid, err := ospkg.Verify(signingRoot)
		if err != nil {
			debug("Error verifying OS package: %v", err)
			continue
		}
		threshold := securityConfig.MinimalSignaturesMatch
		if valid < threshold {
			debug("Not enough valid signatures: %d found, %d valid, %d required", n, valid, threshold)
			continue
		}

		debug("Signatures: %d found, %d valid, %d required", n, valid, threshold)
		info("OS package passed verification")
		info(check)

		/////////////
		// Extract OS
		/////////////
		bootImg, err = ospkg.OSImage(txtHostSuport)
		if err != nil {
			debug("get boot image: %v", err)
			continue
		}
		switch t := bootImg.(type) {
		case *boot.LinuxImage:
			if txtHostSuport {
				debug("TXT is supported on the host, but the os package doesn't provide tboot")
			}
			debug("got linux boot image from os package")
		case *boot.MultibootImage:
			debug("got tboot multiboot image from os package")
		default:
			debug("unknown boot image type %T", t)
			continue
		}

		// write cache
		if securityConfig.BootMode == Network && securityConfig.UsePkgCache {
			dir := filepath.Join(dataPartitionMountPoint, networkOSpkgCache)
			debug("caching OS package in %s", dir)
			// clear
			d, err := os.Open(dir)
			if err != nil {
				reboot("clear cache: %v", err)
			}
			defer d.Close()
			names, err := d.Readdirnames(-1)
			if err != nil {
				reboot("clear cache: %v", err)
			}
			for _, name := range names {
				err = os.RemoveAll(filepath.Join(dir, name))
				if err != nil {
					reboot("clear cache: %v", err)
				}
			}
			// write
			p := filepath.Join(dir, sample.name)
			if err := ioutil.WriteFile(p, aBytes, 0666); err != nil {
				reboot("write pkg cache: %v", err)
			}
		}

		var currentPkgPath string
		if securityConfig.BootMode == Local {
			currentPkgPath = filepath.Join(dataPartitionMountPoint, localOSPkgDir, sample.name)
		} else if securityConfig.BootMode == Network && securityConfig.UsePkgCache {
			currentPkgPath = filepath.Join(dataPartitionMountPoint, networkOSpkgCache, sample.name)
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
		reboot("No usable OS package")
	}
	debug("boot image:\n %s", bootImg.String())

	///////////////////////
	// TPM Measurement
	///////////////////////
	info("Try TPM measurements")
	var toBeMeasured = [][]byte{}

	ospkgBytes, _ := ospkg.ArchiveBytes()
	descriptorBytes, _ := ospkg.DescriptorBytes()
	securityConfigBytes, _ := json.Marshal(securityConfig)

	toBeMeasured = append(toBeMeasured, ospkgBytes)
	debug(" - OS package zip: %d bytes", len(ospkgBytes))
	toBeMeasured = append(toBeMeasured, descriptorBytes)
	debug(" - OS package descriptor: %d bytes", len(descriptorBytes))
	toBeMeasured = append(toBeMeasured, securityConfigBytes)
	debug(" - Security configuration json: %d bytes", len(securityConfigBytes))
	toBeMeasured = append(toBeMeasured, signingRoot.Raw)
	debug(" - Signing root cert ASN1 DER content: %d bytes", len(signingRoot.Raw))
	for n, c := range httpsRoots {
		toBeMeasured = append(toBeMeasured, c.Raw)
		debug(" - HTTPS root %d: %d bytes", n, len(c.Raw))
	}

	// try to measure
	if err = measureTPM(toBeMeasured...); err != nil {
		info("TPM measurements failed: %v", err)
	}

	//////////
	// Boot OS
	//////////
	if *dryRun {
		debug("Dryrun mode: will not boot")
		return
	}
	info("Loading boot image into memory")
	err = bootImg.Load(false)
	if err != nil {
		reboot("%s", err)
	}
	info("Handing over controll - kexec")
	err = boot.Execute()
	if err != nil {
		reboot("%v", err)
	}

	reboot("unexpected return from kexec")
}

func markCurrentOSpkg(pkgPath string) {
	f := filepath.Join(dataPartitionMountPoint, currentOSPkgFile)
	current := pkgPath + string('\n')
	if err := ioutil.WriteFile(f, []byte(current), os.ModePerm); err != nil {
		reboot("write current OS package: %v", err)
	}
}

func networkLoad(urls []*url.URL, useCache bool, httpsRoots []*x509.Certificate, insecure bool) (*ospkgSampl, error) {
	var sample ospkgSampl
	if *doDebug {
		info("Provisioning URLs:")
		for _, u := range urls {
			info(" - %s", u.String())
		}
	}

	if len(httpsRoots) == 0 {
		return nil, fmt.Errorf("httpsRoots must not be empty")
	}
	roots := x509.NewCertPool()
	for _, cert := range httpsRoots {
		roots.AddCert(cert)
	}

	for _, url := range urls {
		debug("downloading %s", url.String())
		dBytes, err := download(url, roots, insecure)
		if err != nil {
			debug("Skip %s: %v", url.String(), err)
			continue
		}
		debug("content type: %s", http.DetectContentType(dBytes))
		debug("parsing descriptor")
		descriptor, err := stboot.DescriptorFromBytes(dBytes)
		if err != nil {
			debug("Skip %s: %v", url.String(), err)
			continue
		}
		if *doDebug {
			info("Package descriptor:")
			info("  Version: %d", descriptor.Version)
			info("  Package URL: %s", descriptor.PkgURL)
			info("  %d signature(s)", len(descriptor.Signatures))
			info("  %d certificate(s)", len(descriptor.Certificates))
		}
		debug("validating descriptor")
		if err = descriptor.Validate(); err != nil {
			debug("Skip %s: %v", url.String(), err)
			continue
		}
		debug("parsing OS package URL form descriptor")
		if descriptor.PkgURL == "" {
			debug("Skip %s: no OS package URL provided in descriptor")
			continue
		}
		pkgURL, err := url.Parse(descriptor.PkgURL)
		if err != nil {
			debug("Skip %s: %v", url.String(), err)
			continue
		}
		s := pkgURL.Scheme
		if s == "" || s != "http" && s != "https" {
			debug("Skip %s: missing or unsupported scheme in OS package URL %s", pkgURL.String())
			continue
		}
		filename := filepath.Base(pkgURL.Path)
		if ext := filepath.Ext(filename); ext != stboot.OSPackageExt {
			debug("Skip %s: package URL must contain a path to a %s file: %s", stboot.OSPackageExt, pkgURL.String())
			continue
		}

		var aBytes []byte
		if useCache {
			debug("look up pkg cache")
			dir := filepath.Join(dataPartitionMountPoint, networkOSpkgCache)
			fis, err := ioutil.ReadDir(dir)
			if err != nil {
				reboot("read cache: %v", err)
			}
			for _, fi := range fis {
				if fi.Name() == filename {
					p := filepath.Join(dir, filename)
					info("using caches OS package %s", p)
					aBytes, err = ioutil.ReadFile(p)
					if err != nil {
						reboot("read cache: %v", err)
					}
					break
				}
			}
			if aBytes == nil {
				debug("%s is not cached", filename)
			}
		}
		if aBytes == nil {
			debug("downloading %s", pkgURL.String())
			aBytes, err = download(pkgURL, roots, insecure)
			if err != nil {
				debug("Skip %s: %v", url.String(), err)
				continue
			}
			debug("content type: %s", http.DetectContentType(aBytes))
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
	dir := filepath.Join(dataPartitionMountPoint, localOSPkgDir)
	if len(names) == 0 {
		return nil, fmt.Errorf("names must not be empty")
	}
	for _, name := range names {
		ap := filepath.Join(dir, name+stboot.OSPackageExt)
		dp := filepath.Join(dir, name+stboot.DescriptorExt)
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

func validatePartitions(mode bootmode) error {
	//STBOOT host config file
	p := filepath.Join(bootPartitionMountPoint, hostConfigurationFile)
	stat, err := os.Stat(p)
	if err != nil {
		return fmt.Errorf("STBOOT: missing file %s", hostConfigurationFile)
	}
	// STDATA /etc dir
	etcDir := filepath.Dir(currentOSPkgFile)
	p = filepath.Join(dataPartitionMountPoint, etcDir)
	stat, err = os.Stat(p)
	if err != nil || !stat.IsDir() {
		return fmt.Errorf("STDATA: missing directory %s", etcDir)
	}
	//STDATA timefix file
	p = filepath.Join(dataPartitionMountPoint, timeFixFile)
	stat, err = os.Stat(p)
	if err != nil {
		return fmt.Errorf("STDATA: missing file %s", timeFixFile)
	}
	if mode == Local {
		// STDATA local packages dir
		p = filepath.Join(dataPartitionMountPoint, localOSPkgDir)
		stat, err := os.Stat(p)
		if err != nil || !stat.IsDir() {
			return fmt.Errorf("STDATA: missing directory %s", localOSPkgDir)
		}
		//STDATA local boot order file
		p = filepath.Join(dataPartitionMountPoint, localBootOrderFile)
		stat, err = os.Stat(p)
		if err != nil {
			return fmt.Errorf("STDATA: missing file %s", localBootOrderFile)
		}
	}
	if mode == Network {
		// STDATA network cache dir
		p = filepath.Join(dataPartitionMountPoint, networkOSpkgCache)
		stat, err := os.Stat(p)
		if err != nil || !stat.IsDir() {
			return fmt.Errorf("STDATA: missing directory %s", networkOSpkgCache)
		}
	}
	return nil
}

func loadSecurityConfig(path string) (*SecurityConfig, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %v", err)
	}
	var sc SecurityConfig
	if err = json.Unmarshal(b, &sc); err != nil {
		return nil, fmt.Errorf("parsing JSON failed: %v", err)
	}
	if *doDebug {
		str, _ := json.MarshalIndent(sc, "", "  ")
		info("Security configuration: %s", str)
	}
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
	debug("signing root certificate:\n%s", string(pemBytes))
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
		if *doDebug {
			info("HTTPS root certificate %d: ", n)
			info("  Version: %d", cert.Version)
			info("  SerialNumber: %s", cert.Issuer.SerialNumber)
			info("  Issuer:")
			info("    Organization: %s, %s", cert.Issuer.Organization, cert.Issuer.Country)
			info("    Common Name: %s", cert.Issuer.CommonName)
			info("  Subject:")
			info("    Organization: %s, %s", cert.Subject.Organization, cert.Subject.Country)
			info("    Common Name: %s", cert.Subject.CommonName)
			info("  Valid from: %s", cert.NotBefore.String())
			info("  Valid until: %s", cert.NotAfter.String())
		}
		roots = append(roots, cert)
		n++
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("no certifiates found")
	}
	return roots, nil
}

func loadHostConfig(path string, validateNetwork bool) (*HostConfig, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %v", err)
	}
	var hc *HostConfig
	err = json.Unmarshal(bytes, &hc)
	if err != nil {
		return nil, fmt.Errorf("parsing JSON failed: %v", err)
	}
	if *doDebug {
		hcCpy := *hc
		hcCpy.Auth = strings.Repeat("*", len(hc.Auth))
		str, _ := json.MarshalIndent(hcCpy, "", "  ")
		info("Host configuration: %s", str)
	}
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
		if ext == stboot.OSPackageExt || ext == stboot.DescriptorExt {
			name = strings.TrimSuffix(name, ext)
		}
		p := filepath.Join(dataPartitionMountPoint, localOSPkgDir, name+stboot.OSPackageExt)
		_, err := os.Stat(p)
		if err != nil {
			debug("skip %s: %v", name, err)
			continue
		}
		p = filepath.Join(dataPartitionMountPoint, localOSPkgDir, name+stboot.DescriptorExt)
		_, err = os.Stat(p)
		if err != nil {
			debug("skip %s: %v", name, err)
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
	t, err = parseUNIXTimestamp(string(raw))
	if err != nil {
		return t, fmt.Errorf("parse UNIX timestamp: %v", err)
	}
	return t, nil
}

//reboot trys to reboot the system in an infinity loop
func reboot(format string, v ...interface{}) {
	if *klog {
		info(format, v...)
		info("REBOOT!")
	}
	for {
		recover := recovery.SecureRecoverer{
			Reboot:   true,
			Debug:    true,
			RandWait: true,
		}
		err := recover.Recover(fmt.Sprintf(format, v...))
		if err != nil {
			continue
		}
	}
}

func info(format string, v ...interface{}) {
	if *klog {
		ulog.KernelLog.Printf("stboot: "+format, v...)
	} else {
		log.Printf(format, v...)
	}
}
