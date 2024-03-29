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

	"github.com/u-root/u-root/pkg/dhclient"
	"github.com/u-root/u-root/pkg/uio"
	"github.com/vishvananda/netlink"
	"system-transparency.org/stboot/host"
	"system-transparency.org/stboot/sterror"
	"system-transparency.org/stboot/stlog"
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

func SetupNetworkInterface(cfg *host.Config) error {
	switch *cfg.IPAddrMode {
	case host.IPStatic:
		if err := configureStatic(cfg); err != nil {
			return err
		}
	case host.IPDynamic:
		if err := configureDHCP(cfg); err != nil {
			return err
		}
	case host.IPUnset:
	default:
		return sterror.E(ErrScope, ErrOpfindInterface, ErrNetworkConfiguration, "IP addr mode is not set")
	}

	if cfg.DNSServer != nil {
		stlog.Info("Set DNS Server")

		for _, ip := range *cfg.DNSServer {
			stlog.Info("- %s", ip.String())
		}

		if err := SetDNSServer(*cfg.DNSServer); err != nil {
			return fmt.Errorf("set DNS Server: %w", err)
		}
	}

	return nil
}

func ConfigureBondInterface(cfg *host.Config) (*netlink.Bond, error) {
	bond, err := SetupBondInterface(*cfg.BondName, netlink.StringToBondMode(cfg.BondingMode.String()))
	if err != nil {
		return nil, err
	}

	if err := SetBonded(bond, *cfg.NetworkInterfaces); err != nil {
		return nil, err
	}

	*cfg.NetworkInterfaces = append(*cfg.NetworkInterfaces,
		&host.NetworkInterface{
			InterfaceName: &bond.Name,
			MACAddress:    &bond.HardwareAddr})

	return bond, nil
}

//nolint:funlen,cyclop
func configureStatic(cfg *host.Config) error {
	var links []netlink.Link

	var err error

	stlog.Info("Setup network interface with static IP: " + cfg.HostIP.String())

	//nolint:nestif
	if cfg.BondingMode != host.BondingUnset {
		bond, err := ConfigureBondInterface(cfg)
		if err != nil {
			return sterror.E(ErrScope, ErrOpConfigureBonding, ErrBond, err.Error())
		}
		// If we use the bond interface we don't know the MAC address the kernel gives it
		// ignore the original device and replace with our bonding interface
		links = []netlink.Link{bond}
	} else {
		if cfg.NetworkInterfaces != nil {
			for _, iface := range *cfg.NetworkInterfaces {
				links, err = findInterfaces(iface.MACAddress)
				if err != nil {
					stlog.Debug("findInterface: finding interface failed: %v", err)

					continue
				}
			}
		} else {
			links, err = findInterfaces(nil)
			if err != nil {
				stlog.Debug("findInterface: finding interface failed: %v", err)
			}
		}

		if len(links) == 0 {
			return sterror.E(ErrScope, ErrOpConfigureDHCP, ErrNetworkConfiguration, err.Error())
		}
	}

	for _, link := range links {
		if err = netlink.AddrAdd(link, cfg.HostIP); err != nil {
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
			Gw:        *cfg.DefaultGateway,
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

//nolint:funlen,cyclop
func configureDHCP(cfg *host.Config) error {
	const (
		retries       = 4
		linkUpTimeout = 30 * time.Second
	)

	var (
		links []netlink.Link
		err   error
	)

	stlog.Info("Configure network interface using DHCP")

	//nolint:nestif
	if cfg.BondingMode != host.BondingUnset {
		bond, err := ConfigureBondInterface(cfg)
		if err != nil {
			return sterror.E(ErrScope, ErrOpConfigureDHCP, ErrNetworkConfiguration, err.Error())
		}

		links = []netlink.Link{bond}
	} else {
		if cfg.NetworkInterfaces != nil {
			for _, iface := range *cfg.NetworkInterfaces {
				links, err = findInterfaces(iface.MACAddress)
				if err != nil {
					stlog.Debug("findInterface: finding interface failed: %v", err)

					continue
				}
			}
		} else {
			links, err = findInterfaces(nil)
			if err != nil {
				stlog.Debug("findInterface: finding interface failed: %v", err)
			}
		}

		if len(links) == 0 {
			return sterror.E(ErrScope, ErrOpConfigureDHCP, ErrNetworkConfiguration, err.Error())
		}
	}

	var level dhclient.LogLevel
	if stlog.Level() != stlog.InfoLevel {
		level = dhclient.LogSummary
	} else {
		level = dhclient.LogInfo
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

// SetDNSServer writes adresses to /etc/resolv.conf file.
func SetDNSServer(addresses []*net.IP) error {
	return setDNSServer(addresses, "/etc/resolv.conf")
}

func setDNSServer(addresses []*net.IP, out string) error {
	var resolvconf string

	for _, addr := range addresses {
		resolvconf += fmt.Sprintf("nameserver %s\n", addr.String())
	}

	const perm = 0644
	if err := os.WriteFile(out, []byte(resolvconf), perm); err != nil {
		return sterror.E(ErrScope, ErrOpSetDNSServer, ErrNetworkConfiguration, err.Error())
	}

	return nil
}

//nolint:cyclop
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

// Download sets up a HTTP client and downloads sources.
//
//nolint:funlen
func Download(url *url.URL, httpsRoots *x509.CertPool) ([]byte, error) {
	const (
		timeout             = 30 * time.Second
		keepAlive           = 30 * time.Second
		maxIdleConns        = 100
		idleConnTimeout     = 90 * time.Second
		tlsHandshakeTimeout = 10 * time.Second
	)

	//nolint:gosec
	tls := &tls.Config{
		RootCAs: httpsRoots,
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

	//nolint:noctx
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
		const intervall = 5 * 1024 * 1024 // 5MiB

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
			// use of sterror.E()
			//nolint:errorlint
			return nil, fmt.Errorf("%s: delete link: %v", link, err)
		}
	}

	la := netlink.NewLinkAttrs()
	la.Name = ifaceName
	bond := netlink.NewLinkBond(la)
	bond.Mode = mode

	bond.Miimon = 100

	if bond.Mode == netlink.BOND_MODE_802_3AD {
		bond.LacpRate = netlink.BOND_LACP_RATE_FAST
	}

	if err := netlink.LinkAdd(bond); err != nil {
		// use of sterror.E()
		//nolint:errorlint
		return nil, fmt.Errorf("%v: create: %v", bond, err)
	}

	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		// use of sterror.E()
		//nolint:errorlint
		return nil, fmt.Errorf("%s: not found: %v", ifaceName, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		// use of sterror.E()
		//nolint:errorlint
		return nil, fmt.Errorf("%v: set up: %v", link.Attrs().Name, err)
	}

	return bond, nil
}

func SetBonded(bond *netlink.Bond, toBondNames []*host.NetworkInterface) error {
	if len(toBondNames) == 0 {
		return fmt.Errorf("no bonded interfaces supplied")
	}

	stlog.Debug("bonding the following interfaces into %s: %v",
		bond.Attrs().Name,
		func(l []*host.NetworkInterface) []string {
			var acc []string
			for _, e := range l {
				acc = append(acc, *e.InterfaceName)
			}

			return acc
		}(toBondNames))

	for _, iface := range toBondNames {
		link, err := netlink.LinkByName(*iface.InterfaceName)
		if err != nil {
			// use of sterror.E()
			//nolint:errorlint
			return fmt.Errorf("%s: to be bonded not found: %v", *iface.InterfaceName, err)
		}

		if err := netlink.LinkSetDown(link); err != nil {
			// use of sterror.E()
			//nolint:errorlint
			return fmt.Errorf("%v: link down: %v", link, err)
		}

		if err := netlink.LinkSetBondSlave(link, bond); err != nil {
			// use of sterror.E()
			//nolint:errorlint
			return fmt.Errorf("%v: bonding into %v: %v", link, bond, err)
		}
	}

	return nil
}
