// Copyright 2022 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"system-transparency.org/stboot/host"
	"system-transparency.org/stboot/host/network"
	"system-transparency.org/stboot/ospkg"
	"system-transparency.org/stboot/stlog"
)

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

	osPkgPtr := svr.URL
	cfg := &host.Config{OSPkgPointer: &osPkgPtr}

	sample, err := fetchOspkgNetwork(context.Background(), client, cfg)
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

func TestFetchOspkgInitramfs(t *testing.T) {
	var descriptor = ospkg.Descriptor{
		Version:      1,
		PkgURL:       "test.zip",
		Certificates: [][]byte{{}},
		Signatures:   [][]byte{{}},
	}

	var archive = "archive"

	var (
		dir            = t.TempDir()
		descriptorFile = filepath.Join(dir, "test.json")
		archiveFile    = filepath.Join(dir, "test.zip")
	)

	dBytes, err := json.Marshal(descriptor)
	if err != nil {
		t.Fatal(err)
	}

	aBytes := []byte(archive)

	err = os.WriteFile(descriptorFile, dBytes, os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}

	err = os.WriteFile(archiveFile, aBytes, os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}

	osPkgPtr := "test.json"
	cfg := &host.Config{OSPkgPointer: &osPkgPtr}

	sample, err := _fetchOspkgInitramfs(cfg, dir)
	if err != nil {
		t.Fatal(err)
	}

	db, err := io.ReadAll(sample.descriptor)
	if err != nil {
		t.Fatal(err)
	}

	ab, err := io.ReadAll(sample.archive)
	if err != nil {
		t.Fatal(err)
	}

	var gotDescriptor ospkg.Descriptor

	err = json.Unmarshal(db, &gotDescriptor)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(gotDescriptor, descriptor) {
		t.Errorf("got %v, want %v", gotDescriptor, descriptor)
	}

	gotArchive := string(ab)

	if gotArchive != archive {
		t.Errorf("got %v, want %v", gotArchive, archive)
	}
}
func TestSubstituteIDandAUTH(t *testing.T) {
	tests := []struct {
		id   string
		auth string
		str  string
		want string
	}{
		{
			id:   "id123",
			auth: "auth123",
			str:  "No ID and no Auth",
			want: "No ID and no Auth",
		},
		{
			id:   "id123",
			auth: "auth123",
			str:  "Pointer with/$ID/included",
			want: "Pointer with/id123/included",
		},
		{
			id:   "id123",
			auth: "auth123",
			str:  "pointer with/$AUTH",
			want: "pointer with/auth123",
		},
		{
			id:   "id123",
			auth: "auth123",
			str:  "pointer with/$ID/and/$AUTH",
			want: "pointer with/id123/and/auth123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.str, func(t *testing.T) {
			got := substituteIDandAUTH(tt.str, tt.id, tt.auth)
			if got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestOSpkgFiles(t *testing.T) {
	tests := []struct {
		ospkgptr string
		desc     string
		archive  string
	}{
		{
			ospkgptr: "my-ospkg",
			desc:     "my-ospkg.json",
			archive:  "my-ospkg.zip",
		},
		{
			ospkgptr: "my-ospkg.zip",
			desc:     "my-ospkg.json",
			archive:  "my-ospkg.zip",
		},
		{
			ospkgptr: "my-ospkg.json",
			desc:     "my-ospkg.json",
			archive:  "my-ospkg.zip",
		},
		{
			ospkgptr: "some_folder/my-ospkg.zip",
			desc:     "some_folder/my-ospkg.json",
			archive:  "some_folder/my-ospkg.zip",
		},
	}

	for _, tt := range tests {
		t.Run(tt.ospkgptr, func(t *testing.T) {
			cfg := host.Config{
				OSPkgPointer: &tt.ospkgptr,
			}
			desc, archive := ospkgFiles(&cfg)
			if desc != tt.desc {
				t.Errorf("got %s, want %s", desc, tt.desc)
			}
			if archive != tt.archive {
				t.Errorf("got %s, want %s", archive, tt.archive)
			}
		})
	}
}
