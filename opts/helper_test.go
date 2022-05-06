package opts

import (
	"net"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

func assert(t *testing.T, gotErr, wantErrType error, got, want interface{}) {
	t.Helper()

	if wantErrType != nil {
		if gotErr == nil {
			t.Fatal("expect an error")
		}

		goterr, wanterr := reflect.TypeOf(gotErr), reflect.TypeOf(wantErrType)
		if goterr != wanterr {
			t.Fatalf("got %+v, want %+v", goterr, wanterr)
		}
	} else if gotErr != nil {
		t.Fatalf("unexpected error: %v", gotErr)
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func s2cidr(t *testing.T, s string) *netlink.Addr {
	t.Helper()

	ip, err := netlink.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}

	return ip
}

func s2ip(t *testing.T, s string) *net.IP {
	t.Helper()

	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("error parsing %s to net.IP", s)
	}

	return &ip
}

func s2mac(t *testing.T, s string) *net.HardwareAddr {
	t.Helper()

	mac, err := net.ParseMAC(s)
	if err != nil {
		t.Fatal(err)
	}

	return &mac
}

func s2url(t *testing.T, s string) *url.URL {
	t.Helper()

	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}

	return u
}

func s2urlArray(t *testing.T, s ...string) *[]*url.URL {
	t.Helper()

	a := []*url.URL{}

	if len(s) == 0 {
		t.Fatal("no string provided")
	}

	for _, str := range s {
		u := s2url(t, str)
		a = append(a, u)
	}

	return &a
}

func s2s(t *testing.T, s string) *string {
	t.Helper()

	return &s
}

func i2time(t *testing.T, i int) *time.Time {
	t.Helper()

	u := time.Unix(int64(i), 0)

	return &u
}
