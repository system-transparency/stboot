package network

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/u-root/u-root/pkg/uio"
	"system-transparency.org/stboot/sterror"
	"system-transparency.org/stboot/stlog"
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

var (
	ErrDownloadTimeout = errors.New("hit download timeout")
	ErrRetriesLimit    = errors.New("hit retries limit")
)

// Wrapper for DownloadObject to deal with retries.
func (h *HTTPClient) Download(ctx context.Context, url *url.URL) ([]byte, error) {
	var ret []byte

	var err error

	for iter := 0; iter < h.Retries; iter++ {
		ret, err = DownloadObject(ctx, h.HTTPClient, url)
		if err == nil {
			break
		}

		if errors.Is(err, context.DeadlineExceeded) {
			return nil, ErrDownloadTimeout
		}

		time.Sleep(time.Second * time.Duration(h.RetryWait))
	}

	if len(ret) == 0 {
		return nil, ErrRetriesLimit
	}

	return ret, nil
}

func DownloadObject(ctx context.Context, client http.Client, url *url.URL) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, err
	}

	req = req.WithContext(ctx)

	resp, err := client.Do(req)
	if err != nil {
		return nil, sterror.E(ErrScope, ErrOpDownload, err, err.Error())
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
