// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ospkg

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBytes(t *testing.T) {
	var d = Descriptor{
		PkgURL:       "test.com",
		Certificates: [][]byte{{1, 2, 3}, {1, 2, 3}},
		Signatures:   [][]byte{{'a', 'b', 'c'}, {'a', 'b', 'c'}},
	}

	b, err := d.Bytes()
	t.Log(b)
	require.NoError(t, err)
}

func TestDescriptorFromBytes(t *testing.T) {
	var b = []byte{
		123, 34, 111, 115, 95, 112, 107, 103, 95, 117, 114, 108,
		34, 58, 34, 116, 101, 115, 116, 46, 99, 111, 109, 34, 44,
		34, 99, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 115,
		34, 58, 91, 34, 65, 81, 73, 68, 34, 44, 34, 65, 81, 73, 68,
		34, 93, 44, 34, 115, 105, 103, 110, 97, 116, 117, 114, 101,
		115, 34, 58, 91, 34, 89, 87, 74, 106, 34, 44, 34, 89, 87, 74,
		106, 34, 93, 125,
	}

	d, err := DescriptorFromBytes(b)
	t.Log(d)
	require.NoError(t, err)
}
