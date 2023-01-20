package network

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"git.glasklar.is/system-transparency/core/stboot/opts"
	"git.glasklar.is/system-transparency/core/stboot/sterror"
	"git.glasklar.is/system-transparency/core/stboot/stlog"
	"github.com/u-root/u-root/pkg/uio"
)

type HTTPClient struct {
	HTTPClient http.Client
	Retries    int
	RetryWait  int
}

func NewHTTPClient(httpsRoots []*x509.Certificate, insecure bool) HTTPClient {
	const (
		timeout             = 30 * time.Second
		keepAlive           = 30 * time.Second
		maxIdleConns        = 100
		idleConnTimeout     = 90 * time.Second
		tlsHandshakeTimeout = 10 * time.Second
	)

	const (
		retries   = 8
		retryWait = 1
	)

	roots := x509.NewCertPool()
	for _, cert := range httpsRoots {
		roots.AddCert(cert)
	}

	//nolint:gosec
	tls := &tls.Config{
		RootCAs: roots,
	}
	if insecure {
		tls.InsecureSkipVerify = true
	}

	// setup client with values taken from http.DefaultTransport + RootCAs
	return HTTPClient{
		Retries:   retries,
		RetryWait: retryWait,
		HTTPClient: http.Client{
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
		},
	}
}

// Wrapper for DownloadObject to deal with retries.
func (h *HTTPClient) Download(url *url.URL) ([]byte, error) {
	var ret []byte

	var err error

	for iter := 0; iter < h.Retries; iter++ {
		ret, err = DownloadObject(h.HTTPClient, url)
		if err == nil {
			break
		}

		time.Sleep(time.Second * time.Duration(h.RetryWait))
	}

	if len(ret) == 0 {
		return nil, fmt.Errorf("hit retries limit")
	}

	return ret, nil
}

func DownloadObject(client http.Client, url *url.URL) ([]byte, error) {
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

	stlog.Debug("Content type: %s", http.DetectContentType(ret))

	return ret, nil
}

func ParsePrivisioningURLs(hostCfg *opts.HostCfg, url *url.URL) *url.URL {
	if strings.Contains(url.String(), "$ID") {
		stlog.Debug("replacing $ID with identity provided by the Host configuration")

		url, _ = url.Parse(strings.ReplaceAll(url.String(), "$ID", *hostCfg.ID))
	}

	if strings.Contains(url.String(), "$AUTH") {
		stlog.Debug("replacing $AUTH with authentication provided by the Host configuration")

		url, _ = url.Parse(strings.ReplaceAll(url.String(), "$AUTH", *hostCfg.Auth))
	}

	return url
}
