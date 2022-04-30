// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package network

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/system-transparency/stboot/opts"
	"github.com/system-transparency/stboot/stlog"
	"github.com/u-root/u-root/pkg/dhclient"
	"github.com/u-root/u-root/pkg/uio"
	"github.com/vishvananda/netlink"
)

// Error reports problems regarding stboot's network setup.
type Error string

// Error implements error interface.
func (e Error) Error() string {
	return string(e)
}

const (
	ErrIPStatic          = Error("IP configuration failed for all interfaces")
	ErrIPDynamic         = Error("DHCP configuration failed")
	ErrNoInterfaces      = Error("no network interface found on host")
	ErrEmptyResponseBody = Error("HTTP response body is empty")
	ErrBadHTTPStatus     = Error("Bad HTTP status")
)

const (
	entropyAvail       = "/proc/sys/kernel/random/entropy_avail"
	interfaceUpTimeout = 6 * time.Second
)

func ConfigureStatic(hostCfg *opts.HostCfg) error {
	stlog.Info("Setup network interface with static IP: " + hostCfg.HostIP.String())

	links, err := FindInterfaces(hostCfg.NetworkInterface)
	if err != nil {
		return err
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

	return ErrIPStatic
}

func ConfigureDHCP(hostCfg *opts.HostCfg) error {
	const (
		retries       = 4
		linkUpTimeout = 30 * time.Second
	)

	stlog.Info("Configure network interface using DHCP")

	links, err := FindInterfaces(hostCfg.NetworkInterface)
	if err != nil {
		return err
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

	return ErrIPDynamic
}

func SetDNSServer(dns net.IP) error {
	resolvconf := fmt.Sprintf("nameserver %s\n", dns.String())

	const perm = 0644
	if err := ioutil.WriteFile("/etc/resolv.conf", []byte(resolvconf), perm); err != nil {
		return fmt.Errorf("write resolv.conf: %w", err)
	}

	return nil
}

// nolint:cyclop
func FindInterfaces(mac *net.HardwareAddr) ([]netlink.Link, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("FindInterfaces: %w", err)
	}

	if len(interfaces) == 0 {
		return nil, ErrNoInterfaces
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
		return nil, ErrNoInterfaces
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
		return nil, fmt.Errorf("HTTP client: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		stlog.Debug("Bad HTTP status: %s", resp.Status)

		return nil, ErrBadHTTPStatus
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

	ret, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if len(ret) == 0 {
		return nil, ErrEmptyResponseBody
	}

	return ret, nil
}

func CheckEntropy() {
	const minEntropy = 128

	e, err := ioutil.ReadFile(entropyAvail)
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
