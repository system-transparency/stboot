// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ospkg

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"

	"github.com/system-transparency/stboot/stlog"
)

const (
	ErrZip   = Error("zip ospkg failed")
	ErrUnzip = Error("unzip ospkg failed")
)

func zipDir(archive *zip.Writer, name string) error {
	if name[len(name)-1:] != "/" {
		name += "/"
	}

	if _, err := archive.Create(name); err != nil {
		return fmt.Errorf("zipDir: %w", err)
	}

	return nil
}

func zipFile(archive *zip.Writer, name string, src []byte) error {
	f, err := archive.Create(name)
	if err != nil {
		return fmt.Errorf("zipFile: %w", err)
	}

	if _, err = io.Copy(f, bytes.NewReader(src)); err != nil {
		return fmt.Errorf("zipFile: %w", err)
	}

	return nil
}

func unzipFile(archive *zip.Reader, name string) ([]byte, error) {
	for _, file := range archive.File {
		if file.Name == name {
			src, err := file.Open()
			if err != nil {
				return nil, fmt.Errorf("cannot open %s in archive: %w", name, err)
			}

			buf := new(bytes.Buffer)
			// nolint:gosec
			if _, err = io.Copy(buf, src); err != nil {
				return nil, fmt.Errorf("reading %s failed: %w", name, err)
			}

			return buf.Bytes(), nil
		}
	}

	stlog.Debug("cannot find %s in archive", name)

	return nil, ErrUnzip
}
