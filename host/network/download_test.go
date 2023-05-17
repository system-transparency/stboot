package network

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

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

	b, err := client.Download(mkURL(svr.URL))
	if err != nil {
		t.Fatal(err)
	}

	s := string(b)
	if s != expected {
		t.Fatal(err)
	}
}
