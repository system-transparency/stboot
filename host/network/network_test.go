// Copyright 2022 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package network

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestSetDNSServer(t *testing.T) {
	ip1 := net.ParseIP("0.0.0.0")
	ip2 := net.ParseIP("8.8.8.8")
	want := "nameserver 0.0.0.0\nnameserver 8.8.8.8\n"

	dest := filepath.Join(t.TempDir(), "resolve.conf")

	err := setDNSServer([]*net.IP{&ip1, &ip2}, dest)
	if err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}

	if string(got) != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
