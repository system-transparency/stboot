// Copyright 2022 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"system-transparency.org/stboot/host"
	"system-transparency.org/stboot/host/network"
	"system-transparency.org/stboot/ospkg"
	"system-transparency.org/stboot/stlog"
)

func Test(t *testing.T) {
	// Empty test to calculate coverage right.
}

func TestFetchOspkgNetwork(t *testing.T) {
	var desc = ospkg.Descriptor{
		Version:      1,
		PkgURL:       "{{SERVER}}/test.zip",
		Certificates: [][]byte{{}},
		Signatures:   [][]byte{{}},
	}

	if !testing.Verbose() {
		stlog.SetLevel(stlog.ErrorLevel)
	}

	// Setup httptest server
	var svr *httptest.Server

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		desc.PkgURL = strings.ReplaceAll(desc.PkgURL, "{{SERVER}}", svr.URL)
		json.NewEncoder(w).Encode(desc) //nolint:errcheck
	})
	mux.HandleFunc("/test.zip", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "test.zip")
	})

	svr = httptest.NewServer(mux)
	defer svr.Close()

	// Initialize client
	var roots []*x509.Certificate
	client := network.NewHTTPClient(roots, false)

	provURL, _ := url.Parse(svr.URL)
	cfg := &host.Config{ProvisioningURLs: &[]*url.URL{provURL}}

	sample, err := fetchOspkgNetwork(client, cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Validate test response
	if sample.name != "test.zip" {
		t.Fatal("not same filename")
	}

	d, _ := io.ReadAll(sample.descriptor)

	var got ospkg.Descriptor

	json.Unmarshal(d, &got) //nolint:errcheck

	if !reflect.DeepEqual(got, desc) {
		t.Errorf("got %+v, want %+v", got, desc)
	}

	a, _ := io.ReadAll(sample.archive)
	if string(bytes.TrimSpace(a)) != "test.zip" {
		t.Errorf("got %s, want %s", a, "test.zip")
	}
}
