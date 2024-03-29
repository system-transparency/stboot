// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/u-root/u-root/pkg/boot"
	"github.com/u-root/u-root/pkg/uio"
	"system-transparency.org/stboot/host"
	"system-transparency.org/stboot/host/network"
	"system-transparency.org/stboot/metadata"
	"system-transparency.org/stboot/opts"
	"system-transparency.org/stboot/ospkg"
	"system-transparency.org/stboot/stlog"
)

const (
	logLevelHelp = "Log level: e 'errors' w 'warn', i 'info', d 'debug'."
	dryRunHelp   = "Stop before kexec-ing into the loaded OS kernel"
	deadlineHelp = "Timeout in minutes for download operations (default: 20)"
)

// Files at initramfs.
const (
	trustPolicyFile = "/etc/trust_policy/trust_policy.json"
	signingRootFile = "/etc/trust_policy/ospkg_signing_root.pem"

	// For HTTPS roots only Let's Encrypt ISRG Root X1 is used.
	httpsRootsFile = "/etc/ssl/certs/isrgrootx1.pem"

	// OS package files (optional).
	// provisionOSpkgArchiveFile    = "/ospkg/provision.zip".
	// provisionOSpkgDescriptorFile = "/ospkg/provision.json".
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

type ospkgSample struct {
	name       string
	descriptor io.ReadCloser
	archive    io.ReadCloser
}

//nolint:funlen,maintidx,gocyclo,cyclop,gocognit,gomnd
func main() {
	log.SetPrefix("stboot: ")

	logLevel := flag.String("loglevel", "info", logLevelHelp)
	dryRun := flag.Bool("dryrun", false, dryRunHelp)
	deadline := flag.Int("deadline", 20, deadlineHelp)

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

	trustPolicySrc, err := os.Open(trustPolicyFile)
	if err != nil {
		stlog.Error("security configuration: %v", err)
		host.Recover()
	}

	hostCfgSrc, err := host.ConfigAutodetect()
	if err != nil {
		stlog.Error("host configuration autodetect: %v", err)
		host.Recover()
	}

	stOptions, err := opts.NewOpts(
		opts.WithTrustPolicy(trustPolicySrc),
		opts.WithHostCfg(hostCfgSrc),
		opts.WithSigningRootCert(signingRootSrc),
		opts.WithHTTPSRootCerts(httpsRootsSrc))
	if err != nil {
		stlog.Error("load opts: %v", err)
		host.Recover()
	}

	if name := *stOptions.HostCfg.OSPkgPointer; name == host.HostConfigProvisionOSPKGName {
		stOptions.TrustPolicy.FetchMethod = ospkg.FetchFromInitramfs
	}

	optsStr, err := json.MarshalIndent(stOptions, "", "  ")
	if err != nil {
		stlog.Debug("Opts: %v", stOptions)
	} else {
		stlog.Debug("Opts: %s", optsStr)
	}

	if stOptions.TrustPolicy.FetchMethod == ospkg.FetchFromNetwork {
		err := network.SetupNetworkInterface(&stOptions.HostCfg)
		if err != nil {
			stlog.Error("failed to setup network interfaces: %v", err)
			host.Recover()
		}
	}

	//////////////////
	// Load OS package
	//////////////////

	var sample *ospkgSample

	switch stOptions.TrustPolicy.FetchMethod {
	case ospkg.FetchFromNetwork:
		stlog.Info("Loading OS package via network")

		if len(stOptions.HTTPSRoots) == 0 {
			stlog.Error("httpsRoots must not be empty")
			host.Recover()
		}

		client := network.NewHTTPClient(stOptions.HTTPSRoots, false)

		stlog.Debug("OS package pointer: %s", *stOptions.HostCfg.OSPkgPointer)

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*deadline)*time.Minute)
		defer cancel()

		sample, err = fetchOspkgNetwork(ctx, client, &stOptions.HostCfg)
		if err != nil {
			stlog.Error("fetching OS package via network failed: %v", err)
			host.Recover()
		}
	case ospkg.FetchFromInitramfs:
		stlog.Info("Loading OS package from initramfs")

		sample, err = fetchOspkgInitramfs(&stOptions.HostCfg)
		if err != nil {
			stlog.Error("fetching OS package from initramfs failed: %v", err)
			host.Recover()
		}
	default:
		stlog.Error("unknown OS package fetch method %q", stOptions.TrustPolicy.FetchMethod)
		host.Recover()
	}

	//////////////////////
	// Process OS packages
	//////////////////////

	stlog.Info("Processing OS package %q", sample.name)

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

	threshold := stOptions.TrustPolicy.SignatureThreshold
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

	mes := host.NewMeasurements()

	// PCR[12] = Details: OS package zip and manifest
	// PCR[13] = Authority: Security config, Signing root, HTTPS root
	// PCR[14] = Identity: UX identiy string and data channel's public key

	ospkgArchiveHash := osp.ArchiveHash()
	ospkgDescriptorHash := osp.DescriptorHash()

	ospkgDescriptorBytes, err := osp.DescriptorBytes()
	if err != nil {
		stlog.Warn("cannot serialize manifest for measurement: %v", err)
	}

	securityConfigBytes, err := json.Marshal(stOptions.TrustPolicy)
	if err != nil {
		stlog.Warn("cannot serialize security config for measurement: %v", err)
	}

	err = mes.Add(host.DetailPcr, host.OspkgArchive, ospkgArchiveHash, []byte(sample.name))
	if err != nil {
		stlog.Warn("cannot measure archive: %v", err)
	}

	err = mes.Add(host.DetailPcr, host.OspkgManifest, ospkgDescriptorHash, ospkgDescriptorBytes)
	if err != nil {
		stlog.Warn("cannot measure manifest: %v", err)
	}

	err = mes.Add(host.AuthorityPcr, host.SecurityConfig, sha256.Sum256(securityConfigBytes), securityConfigBytes)
	if err != nil {
		stlog.Warn("cannot measure security config: %v", err)
	}

	err = mes.Add(host.AuthorityPcr, host.SigningRoot, sha256.Sum256(stOptions.SigningRoot.Raw), stOptions.SigningRoot.Raw)
	if err != nil {
		stlog.Warn("cannot measure signing root certificate: %v", err)
	}

	buf := bytes.NewBuffer(nil)
	for _, c := range stOptions.HTTPSRoots {
		buf.Write(c.Raw)
	}

	err = mes.Add(host.AuthorityPcr, host.HTTPSRoot, sha256.Sum256(buf.Bytes()), buf.Bytes())
	if err != nil {
		stlog.Warn("cannot measure signing root certificate: %v", err)
	}

	// retrieve and measure identity.
	uxIdentity, err := mes.Identity()
	if err != nil {
		stlog.Warn("cannot fetch identity from TPM: %s", err)

		uxIdentity = ""
	}

	err = mes.Add(host.IdentityPcr, host.UxIdentity, sha256.Sum256([]byte(uxIdentity)), []byte(uxIdentity))
	if err != nil {
		stlog.Warn("cannot measure identity: %s", err)
	}

	// marshal event log and close TPM socket.
	eventlog, err := mes.Finalize()
	if err != nil {
		stlog.Warn("cannot finalize measurements: %v", err)
	}

	stlog.Info("Human-readable device identity: %s\n", uxIdentity)

	/////////////////
	// Build metadata
	/////////////////
	meta, err := metadata.Allocate()
	if err != nil {
		stlog.Warn("cannot allocate metadata: %s", err)
	} else {
		err = meta.Set(metadata.UxIdentity, []byte(uxIdentity))
		if err != nil {
			stlog.Warn("cannot set identity metadata: %s", err)
		}

		err = meta.Set(metadata.EventLog, eventlog)
		if err != nil {
			stlog.Warn("cannot set event log metadata: %s", err)
		}

		err = meta.Close()
		if err != nil {
			stlog.Warn("cannot close metadata: %s", err)
		}

		linuxImg.Cmdline += " " + meta.Cmdline
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

// get an ospkg from the initramfs.
func fetchOspkgInitramfs(hostCfg *host.Config) (*ospkgSample, error) {
	return _fetchOspkgInitramfs(hostCfg, "ospkg")
}
func _fetchOspkgInitramfs(hostCfg *host.Config, dir string) (*ospkgSample, error) {
	var (
		sample                      ospkgSample
		descriptorFile, archiveFile string
	)

	descriptorFile, archiveFile = ospkgFiles(hostCfg)

	descriptor, err := os.Open(filepath.Join(dir, descriptorFile))
	if err != nil {
		return nil, err
	}

	archive, err := os.Open(filepath.Join(dir, archiveFile))
	if err != nil {
		return nil, err
	}

	sample.name = "OS package from initramfs"
	sample.descriptor = descriptor
	sample.archive = archive

	return &sample, nil
}

//nolint:nonamedreturns
func ospkgFiles(cfg *host.Config) (descriptor, archive string) {
	var (
		osPkgPtr, identity, auth string
	)

	if cfg.OSPkgPointer == nil {
		return "", ""
	}

	osPkgPtr = *cfg.OSPkgPointer

	if cfg.ID != nil {
		identity = *cfg.ID
	}

	if cfg.Auth != nil {
		auth = *cfg.Auth
	}

	str := substituteIDandAUTH(osPkgPtr, identity, auth)

	ext := filepath.Ext(str)
	name := strings.TrimSuffix(str, ext)

	return name + ".json", name + ".zip"
}

const errDownload = Error("download failed")

// get an ospkg via the network.
func fetchOspkgNetwork(ctx context.Context, client network.HTTPClient, hostCfg *host.Config) (*ospkgSample, error) {
	var sample ospkgSample

	urls := ospkgURLs(hostCfg)
	if len(urls) == 0 {
		return nil, errors.New("no valid URLs in OS package pointer")
	}

	for _, url := range urls {
		stlog.Debug("Downloading %s", url.String())

		descriptorURL := url

		dBytes, err := client.Download(ctx, &descriptorURL)
		if err != nil {
			stlog.Debug("Skip %s: %v", url.String(), err)

			continue
		}

		descriptor, err := readOspkg(dBytes)
		if err != nil {
			stlog.Debug("Skip %s: %v", url.String(), err)

			continue
		}

		stlog.Debug("Parsing OS package URL form descriptor")

		filename, pkgURL, ok := validatePkgURL(descriptor.PkgURL)

		if !ok {
			continue
		}

		stlog.Debug("Downloading %s", pkgURL.String())

		pkgbytes, err := client.Download(ctx, pkgURL)
		if err != nil {
			stlog.Debug("Skip %s: %v", url.String(), err)

			continue
		}

		// create sample
		archiveReader := uio.NewLazyOpener(func() (io.Reader, error) {
			return bytes.NewReader(pkgbytes), nil
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

func ospkgURLs(cfg *host.Config) []url.URL {
	urls := make([]url.URL, 0)

	var (
		osPkgPtr, identity, auth string
	)

	if cfg.OSPkgPointer == nil {
		return urls
	}

	osPkgPtr = *cfg.OSPkgPointer

	if cfg.ID != nil {
		identity = *cfg.ID
	}

	if cfg.Auth != nil {
		auth = *cfg.Auth
	}

	str := substituteIDandAUTH(osPkgPtr, identity, auth)
	strs := strings.Split(str, ",")

	for _, s := range strs {
		addr, err := url.Parse(s)
		if err != nil {
			stlog.Warn("skip %q: %v", s, err)

			break
		}

		s := addr.Scheme
		if s == "" || s != "http" && s != "https" {
			stlog.Warn("skip %q: empty or unsupported scheme, want http or https", s)

			break
		}

		urls = append(urls, *addr)
	}

	return urls
}

func substituteIDandAUTH(str, id, auth string) string {
	if id != "" {
		str = strings.ReplaceAll(str, "$ID", id)
	}

	if auth != "" {
		str = strings.ReplaceAll(str, "$AUTH", auth)
	}

	return str
}

func readOspkg(b []byte) (*ospkg.Descriptor, error) {
	stlog.Debug("Parsing descriptor")

	descriptor, err := ospkg.DescriptorFromBytes(b)
	if err != nil {
		return nil, err
	}

	stlog.Debug("Package descriptor:")
	stlog.Debug("  Version: %d", descriptor.Version)
	stlog.Debug("  Package URL: %s", descriptor.PkgURL)
	stlog.Debug("  %d signature(s)", len(descriptor.Signatures))
	stlog.Debug("  %d certificate(s)", len(descriptor.Certificates))
	stlog.Info("Validating descriptor")

	if err = descriptor.Validate(); err != nil {
		return nil, err
	}

	return descriptor, nil
}

func validatePkgURL(pkgurl string) (string, *url.URL, bool) {
	stlog.Debug("Parsing OS package URL form descriptor")

	if pkgurl == "" {
		stlog.Debug("No OS package URL provided in descriptor")

		return "", nil, false
	}

	pkgURL, err := url.Parse(pkgurl)
	if err != nil {
		stlog.Debug("Skip %s: %v", pkgurl, err)

		return "", nil, false
	}

	s := pkgURL.Scheme
	if s == "" || s != "http" && s != "https" {
		stlog.Debug("Skip %s: missing or unsupported scheme: %q", pkgurl, s)

		return "", nil, false
	}

	filename := filepath.Base(pkgURL.Path)
	if ext := filepath.Ext(filename); ext != ospkg.OSPackageExt {
		stlog.Debug("Skip %s: package URL must contain a path to a %s file: %s", pkgurl, ospkg.OSPackageExt, pkgURL.String())

		return "", nil, false
	}

	return filename, pkgURL, true
}
