// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package network

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/system-transparency/stboot/opts"
	"github.com/system-transparency/stboot/sterror"
	"github.com/system-transparency/stboot/stlog"
	"github.com/u-root/u-root/pkg/dhclient"
	"github.com/u-root/u-root/pkg/uio"
	"github.com/vishvananda/netlink"
)

// Scope and operations used for raising Errors of this package.
const (
	ErrScope                      sterror.Scope = "Network"
	ErrOpConfigureStatic          sterror.Op    = "ConfigureStatic"
	ErrOpConfigureDHCP            sterror.Op    = "ConfigureDHCP"
	ErrOpConfigureBonding         sterror.Op    = "ConfigureBonding"
	ErrOpSetDNSServer             sterror.Op    = "SetDNSServer"
	ErrOpfindInterface            sterror.Op    = "findInterface"
	ErrOpDownload                 sterror.Op    = "Download"
	ErrInfoFailedForAllInterfaces               = "IP configuration failed for all interfaces"
	ErrInfoFoundNoInterfaces                    = "found no interfaces"
)

// Errors which may be raised and wrapped in this package.
var (
	ErrNetworkConfiguration = errors.New("failed to configure network")
	ErrDownload             = errors.New("failed to download")
	ErrBond                 = errors.New("failed to setup bonding interface")
)

const (
	entropyAvail       = "/proc/sys/kernel/random/entropy_avail"
	interfaceUpTimeout = 6 * time.Second
)

func ConfigureBondInterface(hostCfg *opts.HostCfg) (*netlink.Bond, error) {
	bond, err := SetupBondInterface(*hostCfg.BondName, netlink.StringToBondMode(hostCfg.BondingMode.String()))
	if err != nil {
		return nil, err
	}

	if err := SetBonded(bond, hostCfg.NetworkInterfaces); err != nil {
		return nil, err
	}

	hostCfg.NetworkInterface = &bond.HardwareAddr

	return bond, nil
}

func ConfigureStatic(hostCfg *opts.HostCfg) error {
	var links []netlink.Link

	var err error

	stlog.Info("Setup network interface with static IP: " + hostCfg.HostIP.String())

	if hostCfg.BondingMode != opts.BondingUnset {
		bond, err := ConfigureBondInterface(hostCfg)
		if err != nil {
			return sterror.E(ErrScope, ErrOpConfigureBonding, ErrBond, err.Error())
		}
		// If we use the bond interface we don't know the MAC address the kernel gives it
		// ignore the original device and replace with our bonding interface
		links = []netlink.Link{bond}
	} else {
		links, err = findInterfaces(hostCfg.NetworkInterface)
		if err != nil {
			return sterror.E(ErrScope, ErrOpConfigureStatic, ErrNetworkConfiguration, err.Error())
		}
	}

	for _, link := range links {
		if err = netlink.AddrAdd(link, hostCfg.HostIP); err != nil {
			stlog.Debug("%s: IP config failed: %v", link.Attrs().Name, err)

			continue
		}

		if err = netlink.LinkSetUp(link); err != nil {
			stlog.Debug("%s: IP config failed: %v", link.Attrs().Name, err)

			continue
		}

		if err != nil {
			stlog.Debug("%s: IP config failed: %v", link.Attrs().Name, err)

			continue
		}

		r := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Gw:        *hostCfg.DefaultGateway,
		}
		if err = netlink.RouteAdd(r); err != nil {
			stlog.Debug("%s: IP config failed: %v", link.Attrs().Name, err)

			continue
		}

		stlog.Info("%s: IP configuration successful", link.Attrs().Name)

		return nil
	}

	return sterror.E(ErrScope, ErrOpConfigureStatic, ErrNetworkConfiguration, ErrInfoFailedForAllInterfaces)
}

func ConfigureDHCP(hostCfg *opts.HostCfg) error {
	const (
		retries       = 4
		linkUpTimeout = 30 * time.Second
	)

	var (
		links []netlink.Link
		err   error
	)

	stlog.Info("Configure network interface using DHCP")

	if hostCfg.BondingMode != opts.BondingUnset {
		bond, err := ConfigureBondInterface(hostCfg)
		if err != nil {
			return sterror.E(ErrScope, ErrOpConfigureDHCP, ErrNetworkConfiguration, err.Error())
		}

		links = []netlink.Link{bond}
	} else {
		links, err = findInterfaces(hostCfg.NetworkInterface)
		if err != nil {
			return sterror.E(ErrScope, ErrOpConfigureDHCP, ErrNetworkConfiguration, err.Error())
		}
	}

	var level dhclient.LogLevel
	if stlog.Level() != stlog.InfoLevel {
		level = 1
	} else {
		level = 0
	}

	config := dhclient.Config{
		Timeout:  interfaceUpTimeout,
		Retries:  retries,
		LogLevel: level,
	}

	r := dhclient.SendRequests(context.TODO(), links, true, false, config, linkUpTimeout)
	for result := range r {
		if result.Err != nil {
			stlog.Debug("%s: DHCP response error: %v", result.Interface.Attrs().Name, result.Err)

			continue
		}

		err = result.Lease.Configure()
		if err != nil {
			stlog.Debug("%s: DHCP configuration error: %v", result.Interface.Attrs().Name, err)
		} else {
			stlog.Info("DHCP successful - %s", result.Interface.Attrs().Name)

			return nil
		}
	}

	return sterror.E(ErrScope, ErrOpConfigureDHCP, ErrNetworkConfiguration, ErrInfoFailedForAllInterfaces)
}

func SetDNSServer(dns net.IP) error {
	resolvconf := fmt.Sprintf("nameserver %s\n", dns.String())

	const perm = 0644
	if err := os.WriteFile("/etc/resolv.conf", []byte(resolvconf), perm); err != nil {
		return sterror.E(ErrScope, ErrOpSetDNSServer, ErrNetworkConfiguration, err.Error())
	}

	return nil
}

// nolint:cyclop
func findInterfaces(mac *net.HardwareAddr) ([]netlink.Link, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, sterror.E(ErrScope, ErrOpfindInterface, err.Error())
	}

	if len(interfaces) == 0 {
		return nil, sterror.E(ErrScope, ErrOpfindInterface, ErrInfoFoundNoInterfaces)
	}

	if mac != nil {
		stlog.Info("Looking for specific NIC with MAC addr. %s", mac.String())
	}

	links := make([]netlink.Link, 0, len(interfaces))

	for _, iface := range interfaces {
		stlog.Debug("Found interface %s", iface.Name)
		stlog.Debug("    MTU: %d Hardware Addr: %s", iface.MTU, iface.HardwareAddr.String())
		stlog.Debug("    Flags: %v", iface.Flags)
		// skip loopback
		if iface.Flags&net.FlagLoopback != 0 || bytes.Equal(iface.HardwareAddr, nil) {
			continue
		}

		link, err := netlink.LinkByName(iface.Name)
		if err != nil {
			stlog.Debug("%v", err)
		}

		if mac != nil && bytes.Equal(*mac, iface.HardwareAddr) {
			stlog.Debug("Got it!")

			return []netlink.Link{link}, nil
		}

		links = append(links, link)
	}

	if mac != nil && !bytes.Equal(*mac, links[0].Attrs().HardwareAddr) {
		stlog.Info("No NIC with MAC addr. %s", mac.String())
		stlog.Info("Try to use an existing NIC")
	}

	if len(links) == 0 {
		return nil, sterror.E(ErrScope, ErrOpfindInterface, ErrInfoFoundNoInterfaces)
	}

	return links, nil
}

// Donwnload sets up a HTTP client and downloads sources.
// nolint:funlen
func Download(url *url.URL, httpsRoots *x509.CertPool, insecure bool) ([]byte, error) {
	const (
		timeout             = 30 * time.Second
		keepAlive           = 30 * time.Second
		maxIdleConns        = 100
		idleConnTimeout     = 90 * time.Second
		tlsHandshakeTimeout = 10 * time.Second
	)

	// nolint:gosec
	tls := &tls.Config{
		RootCAs: httpsRoots,
	}
	if insecure {
		tls.InsecureSkipVerify = true
	}

	// setup client with values taken from http.DefaultTransport + RootCAs
	client := http.Client{
		Transport: (&http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   timeout,
				KeepAlive: keepAlive,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          maxIdleConns,
			IdleConnTimeout:       idleConnTimeout,
			TLSHandshakeTimeout:   tlsHandshakeTimeout,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       tls,
		}),
	}

	if stlog.Level() != stlog.InfoLevel {
		CheckEntropy()
	}

	// nolint:noctx
	resp, err := client.Get(url.String())
	if err != nil {
		return nil, sterror.E(ErrScope, ErrOpDownload, ErrDownload, err.Error())
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		stlog.Debug("Bad HTTP status: %s", resp.Status)

		return nil, sterror.E(ErrScope, ErrOpDownload, ErrDownload, "bad HTTP status")
	}

	if stlog.Level() != stlog.InfoLevel {
		const intervall = 5 * 1024 * 1024

		progress := func(rc io.ReadCloser) io.ReadCloser {
			return &uio.ProgressReadCloser{
				RC:       rc,
				Symbol:   ".",
				Interval: intervall,
				W:        os.Stdout,
			}
		}
		resp.Body = progress(resp.Body)
	}

	ret, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, sterror.E(ErrScope, ErrOpDownload, ErrDownload, err.Error())
	}

	if len(ret) == 0 {
		return nil, sterror.E(ErrScope, ErrOpDownload, ErrDownload, "HTTP response body is empty")
	}

	return ret, nil
}

func CheckEntropy() {
	const minEntropy = 128

	e, err := os.ReadFile(entropyAvail)
	if err != nil {
		stlog.Warn("Entropy check failed, %v", err)
	}

	es := strings.TrimSpace(string(e))

	entr, err := strconv.Atoi(es)
	if err != nil {
		stlog.Warn("Entropy check failed, %v", err)
	}

	if entr < minEntropy {
		stlog.Warn("Low entropy:")
		stlog.Warn("%s : %d", entropyAvail, entr)
	}
}

func SetupBondInterface(ifaceName string, mode netlink.BondMode) (*netlink.Bond, error) {
	if link, err := netlink.LinkByName(ifaceName); err == nil {
		if err := netlink.LinkDel(link); err != nil {
			return nil, fmt.Errorf("%s: delete link: %v", link, err)
		}
	}

	la := netlink.NewLinkAttrs()
	la.Name = ifaceName
	bond := netlink.NewLinkBond(la)
	bond.Mode = mode

	if err := netlink.LinkAdd(bond); err != nil {
		return nil, fmt.Errorf("%v: create: %v", bond, err)
	}

	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("%s: not found: %v", ifaceName, err)
	}

	stlog.Debug("bonding link %s created with MAC %s", ifaceName, link.Attrs().HardwareAddr)

	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("%v: set up: %v", link.Attrs().Name, err)
	}

	return bond, nil
}

func SetBonded(bond *netlink.Bond, toBondNames *[]*string) error {
	if *toBondNames == nil {
		return fmt.Errorf("no bonded interfaces supplied")
	}

	stlog.Debug("bonding the following interfaces into %s: %v", bond.Attrs().Name, *toBondNames)

	for _, name := range *toBondNames {
		link, err := netlink.LinkByName(*name)
		if err != nil {
			return fmt.Errorf("%s: to be bonded not found: %v", *name, err)
		}

		if err := netlink.LinkSetDown(link); err != nil {
			return fmt.Errorf("%v: link down: %v", link, err)
		}

		if err := netlink.LinkSetBondSlave(link, bond); err != nil {
			return fmt.Errorf("%v: bonding into %v: %v", link, bond, err)
		}
	}

	return nil
}
