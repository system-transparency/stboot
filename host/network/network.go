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
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/system-transparency/stboot/config"
	"github.com/system-transparency/stboot/stlog"
	"github.com/u-root/u-root/pkg/dhclient"
	"github.com/u-root/u-root/pkg/uio"
	"github.com/vishvananda/netlink"
)

const (
	entropyAvail       = "/proc/sys/kernel/random/entropy_avail"
	interfaceUpTimeout = 6 * time.Second
)

func ConfigureStatic(hc *config.HostConfig) error {
	addr, err := hc.ParseHostIP()
	if err != nil {
		return fmt.Errorf("parsing host IP: %v", err)
	}
	gateway, err := hc.ParseDefaultGateway()
	if err != nil {
		return fmt.Errorf("parsing default gateway: %v", err)
	}
	nic, err := hc.ParseNetworkInterface()
	if err != nil {
		return fmt.Errorf("parsing network interface: %v", err)
	}

	stlog.Info("Setup network interface with static IP: " + addr.String())
	links, err := FindInterfaces(nic)
	if err != nil {
		return err
	}

	for _, link := range links {

		if err = netlink.AddrAdd(link, addr); err != nil {
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

		r := &netlink.Route{LinkIndex: link.Attrs().Index, Gw: *gateway}
		if err = netlink.RouteAdd(r); err != nil {
			stlog.Debug("%s: IP config failed: %v", link.Attrs().Name, err)
			continue
		}

		stlog.Info("%s: IP configuration successful", link.Attrs().Name)
		return nil
	}
	return errors.New("IP configuration failed for all interfaces")
}

func ConfigureDHCP(hc *config.HostConfig, log bool) error {
	stlog.Info("Configure network interface using DHCP")

	nic, err := hc.ParseNetworkInterface()
	if err != nil {
		return fmt.Errorf("parsing network interface: %v", err)
	}

	links, err := FindInterfaces(nic)
	if err != nil {
		return err
	}

	var level dhclient.LogLevel
	if log {
		level = 1
	} else {
		level = 0
	}
	config := dhclient.Config{
		Timeout:  interfaceUpTimeout,
		Retries:  4,
		LogLevel: level,
	}

	r := dhclient.SendRequests(context.TODO(), links, true, false, config, 30*time.Second)
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
	return errors.New("DHCP configuration failed")
}

func SetDNSServer(dns net.IP) error {
	resolvconf := fmt.Sprintf("nameserver %s\n", dns.String())
	if err := ioutil.WriteFile("/etc/resolv.conf", []byte(resolvconf), 0644); err != nil {
		return fmt.Errorf("write resolv.conf: %v", err)
	}
	return nil
}

func FindInterfaces(mac *net.HardwareAddr) ([]netlink.Link, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	if len(interfaces) == 0 {
		return nil, errors.New("no network interface found on host")
	}

	if mac != nil {
		stlog.Info("Looking for specific NIC with MAC addr. %s", mac.String())
	}

	var links []netlink.Link
	var ifnames []string
	for _, i := range interfaces {
		stlog.Debug("Found interface %s", i.Name)
		stlog.Debug("    MTU: %d Hardware Addr: %s", i.MTU, i.HardwareAddr.String())
		stlog.Debug("    Flags: %v", i.Flags)
		ifnames = append(ifnames, i.Name)
		// skip loopback
		if i.Flags&net.FlagLoopback != 0 || bytes.Compare(i.HardwareAddr, nil) == 0 {
			continue
		}
		link, err := netlink.LinkByName(i.Name)
		if err != nil {
			stlog.Debug("%v", err)
		}
		if mac != nil && bytes.Equal(*mac, i.HardwareAddr) {
			stlog.Debug("Got it!")
			return []netlink.Link{link}, nil
		}
		links = append(links, link)
	}

	if mac != nil && !bytes.Equal(*mac, links[0].Attrs().HardwareAddr) {
		stlog.Info("No NIC with MAC addr. %s", mac.String())
		stlog.Info("Try to use an existing NIC")
	}

	if len(links) <= 0 {
		return nil, fmt.Errorf("could not find a non-loopback network interface with hardware address in any of %v", ifnames)
	}

	return links, nil
}

func Download(url *url.URL, httpsRoots *x509.CertPool, insecure, log bool) ([]byte, error) {
	// setup client with values taken from http.DefaultTransport + RootCAs
	tls := &tls.Config{
		RootCAs: httpsRoots,
	}
	if insecure {
		tls.InsecureSkipVerify = true
	}

	client := http.Client{
		Transport: (&http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       tls,
		}),
	}

	if log {
		CheckEntropy()
	}

	resp, err := client.Get(url.String())
	if err != nil {
		return nil, fmt.Errorf("client: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("response: %d", resp.StatusCode)
	}
	if log {
		progress := func(rc io.ReadCloser) io.ReadCloser {
			return &uio.ProgressReadCloser{
				RC:       rc,
				Symbol:   ".",
				Interval: 5 * 1024 * 1024,
				W:        os.Stdout,
			}
		}
		resp.Body = progress(resp.Body)
	}
	ret, err := ioutil.ReadAll(resp.Body)
	if len(ret) == 0 {
		return nil, fmt.Errorf("empty response")
	}
	return ret, nil
}

func CheckEntropy() {
	e, err := ioutil.ReadFile(entropyAvail)
	if err != nil {
		stlog.Warn("Entropy check failed, %v", err)
	}
	es := strings.TrimSpace(string(e))
	entr, err := strconv.Atoi(es)
	if err != nil {
		stlog.Warn("Entropy check failed, %v", err)
	}
	if entr < 128 {
		stlog.Warn("Low entropy:")
		stlog.Warn("%s : %d", entropyAvail, entr)
	}
}
