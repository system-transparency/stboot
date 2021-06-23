// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ospkg

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
)

func zipDir(archive *zip.Writer, name string) error {
	if name[len(name)-1:] != "/" {
		name += "/"
	}
	_, err := archive.Create(name)
	return err
}

func zipFile(archive *zip.Writer, name string, src []byte) error {
	f, err := archive.Create(name)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, bytes.NewReader(src))
	return err
}

func unzipFile(archive *zip.Reader, name string) ([]byte, error) {
	for _, file := range archive.File {
		if file.Name == name {
			f, err := file.Open()
			if err != nil {
				return nil, fmt.Errorf("cannot open %s in archive: %v", name, err)
			}

			buf := new(bytes.Buffer)
			if _, err = io.Copy(buf, f); err != nil {
				return nil, fmt.Errorf("reading %s failed: %v", name, err)
			}
			return buf.Bytes(), nil
		}
	}
	return nil, fmt.Errorf("cannot find %s in archive", name)
}
