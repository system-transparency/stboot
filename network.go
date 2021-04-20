package main

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

	"github.com/u-root/u-root/pkg/dhclient"
	"github.com/u-root/u-root/pkg/uio"
	"github.com/vishvananda/netlink"
)

const (
	entropyAvail       = "/proc/sys/kernel/random/entropy_avail"
	interfaceUpTimeout = 6 * time.Second
)

func configureStaticNetwork(hc *HostConfig) error {
	addr, err := hc.ParseHostIP()
	if err != nil {
		return fmt.Errorf("parsing host IP: %v", err)
	}
	gateway, err := hc.ParseDefaultGateway()
	if err != nil {
		return fmt.Errorf("parsing default gateway: %v", err)
	}
	info("Setup network interface with static IP: " + addr.String())
	links, err := findNetworkInterfaces()
	if err != nil {
		return err
	}

	for _, link := range links {

		if err = netlink.AddrAdd(link, addr); err != nil {
			debug("%s: IP config failed: %v", link.Attrs().Name, err)
			continue
		}

		if err = netlink.LinkSetUp(link); err != nil {
			debug("%s: IP config failed: %v", link.Attrs().Name, err)
			continue
		}

		if err != nil {
			debug("%s: IP config failed: %v", link.Attrs().Name, err)
			continue
		}

		r := &netlink.Route{LinkIndex: link.Attrs().Index, Gw: *gateway}
		if err = netlink.RouteAdd(r); err != nil {
			debug("%s: IP config failed: %v", link.Attrs().Name, err)
			continue
		}

		info("%s: IP configuration successful", link.Attrs().Name)
		return nil
	}
	return errors.New("IP configuration failed for all interfaces")
}

func configureDHCPNetwork() error {
	info("Configure network interface using DHCP")

	links, err := findNetworkInterfaces()
	if err != nil {
		return err
	}

	var level dhclient.LogLevel
	if *doDebug {
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
			debug("%s: DHCP response error: %v", result.Interface.Attrs().Name, result.Err)
			continue
		}
		err = result.Lease.Configure()
		if err != nil {
			debug("%s: DHCP configuration error: %v", result.Interface.Attrs().Name, err)
		} else {
			info("DHCP successful - %s", result.Interface.Attrs().Name)
			return nil
		}
	}
	return errors.New("DHCP configuration failed")
}

func setDNSServer(dns net.IP) error {
	resolvconf := fmt.Sprintf("nameserver %s\n", dns.String())
	if err := ioutil.WriteFile("/etc/resolv.conf", []byte(resolvconf), 0644); err != nil {
		return fmt.Errorf("write resolv.conf: %v", err)
	}
	return nil
}

func findNetworkInterfaces() ([]netlink.Link, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	if len(interfaces) == 0 {
		return nil, errors.New("no network interface found")
	}

	var links []netlink.Link
	var ifnames []string
	for _, i := range interfaces {
		debug("Found interface %s", i.Name)
		debug("    MTU: %d Hardware Addr: %s", i.MTU, i.HardwareAddr.String())
		debug("    Flags: %v", i.Flags)
		ifnames = append(ifnames, i.Name)
		// skip loopback
		if i.Flags&net.FlagLoopback != 0 || bytes.Compare(i.HardwareAddr, nil) == 0 {
			continue
		}
		link, err := netlink.LinkByName(i.Name)
		if err != nil {
			debug("%v", err)
		}
		links = append(links, link)
	}

	if len(links) <= 0 {
		return nil, fmt.Errorf("could not find a non-loopback network interface with hardware address in any of %v", ifnames)
	}

	return links, nil
}

func download(url *url.URL, httpsRoots *x509.CertPool, insecure bool) ([]byte, error) {
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

	if *doDebug {
		checkEntropy()
	}

	resp, err := client.Get(url.String())
	if err != nil {
		return nil, fmt.Errorf("client: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("response: %d", resp.StatusCode)
	}
	if *doDebug {
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

func checkEntropy() {
	e, err := ioutil.ReadFile(entropyAvail)
	if err != nil {
		info("entropy check failed, %v", err)
	}
	es := strings.TrimSpace(string(e))
	entr, err := strconv.Atoi(es)
	if err != nil {
		info("entropy check failed, %v", err)
	}
	if entr < 128 {
		info("WARNING: low entropy:")
		info("%s : %d", entropyAvail, entr)
	}
}
