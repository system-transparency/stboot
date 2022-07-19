// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ospkg

import (
	"archive/zip"
	"bytes"
	"io"

	"github.com/system-transparency/stboot/sterror"
	"github.com/system-transparency/stboot/stlog"
)

func zipDir(archive *zip.Writer, name string) error {
	if name[len(name)-1:] != "/" {
		name += "/"
	}

	if _, err := archive.Create(name); err != nil {
		return err
	}

	return nil
}

func zipFile(archive *zip.Writer, name string, src []byte) error {
	f, err := archive.Create(name)
	if err != nil {
		return err
	}

	if _, err = io.Copy(f, bytes.NewReader(src)); err != nil {
		return err
	}

	return nil
}

func unzipFile(archive *zip.Reader, name string) ([]byte, error) {
	for _, file := range archive.File {
		if file.Name == name {
			src, err := file.Open()
			if err != nil {
				return nil, err
			}

			buf := new(bytes.Buffer)
			// nolint:gosec
			if _, err = io.Copy(buf, src); err != nil {
				return nil, err
			}

			return buf.Bytes(), nil
		}
	}

	stlog.Debug("cannot find %s in archive", name)

	return nil, sterror.ErrFailedToUnzip
}
