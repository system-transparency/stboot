package network

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"system-transparency.org/stboot/host"
	"system-transparency.org/stboot/stlog"
)

func strptr(s string) *string {
	return &s
}

func mkURL(s string) *url.URL {
	u, _ := url.Parse(s)

	return u
}

func TestParseProvisioningURLs(t *testing.T) {
	var urlCases = []struct {
		cfg     *host.Config
		url     *url.URL
		testURL *url.URL
	}{
		{
			cfg: &host.Config{
				ID:   strptr("test"),
				Auth: strptr("test"),
			},
			url:     mkURL("https://localhost.com/$ID/$AUTH"),
			testURL: mkURL("https://localhost.com/test/test"),
		},
		{
			cfg: &host.Config{
				ID:   strptr("test1"),
				Auth: strptr("test1"),
			},
			url:     mkURL("https://localhost.com/$ID"),
			testURL: mkURL("https://localhost.com/test1"),
		},
		{
			cfg: &host.Config{
				ID:   strptr("test2"),
				Auth: strptr("test2"),
			},
			url:     mkURL("https://localhost.com/$AUTH"),
			testURL: mkURL("https://localhost.com/test2"),
		},
	}

	for _, c := range urlCases {
		url := ParseProvisioningURLs(c.cfg, c.url)
		if url.String() != c.testURL.String() {
			t.Fatalf("failed parsing %s as %s", c.url, c.testURL)
		}
	}
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
