package network

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"system-transparency.org/stboot/stlog"
)

func mkURL(s string) *url.URL {
	u, _ := url.Parse(s)

	return u
}

func TestHTTPClient(t *testing.T) {
	if !testing.Verbose() {
		stlog.SetLevel(stlog.ErrorLevel)
	}

	expected := "test response"
	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, expected)
	}))

	defer svr.Close()

	var roots []*x509.Certificate
	client := NewHTTPClient(roots, false)

	b, err := client.Download(context.Background(), mkURL(svr.URL))
	if err != nil {
		t.Fatal(err)
	}

	s := string(b)
	if s != expected {
		t.Fatal(err)
	}
}

func TestHTTPClientCancel(t *testing.T) {
	if !testing.Verbose() {
		stlog.SetLevel(stlog.ErrorLevel)
	}

	svr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		fmt.Fprint(w, "")
	}))

	defer svr.Close()

	var roots []*x509.Certificate
	client := NewHTTPClient(roots, false)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := client.Download(ctx, mkURL(svr.URL))
	if !errors.Is(err, ErrDownloadTimeout) {
		t.Fatal(err)
	}
}
