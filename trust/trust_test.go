// Copyright 2022 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trust

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorWrapping(t *testing.T) {
	wrappedError := fmt.Errorf("%v: %w", ErrSign, ErrED25519Signer)
	higher_error := wrappedError.Error()
	lower_error := errors.Unwrap(wrappedError).Error()
	assert.Equal(t,higher_error,"sign: ED25519Signer error")
	assert.Equal(t,lower_error,"ED25519Signer error")
}