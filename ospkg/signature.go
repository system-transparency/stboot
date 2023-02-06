// Copyright 2021 the System Transparency Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ospkg

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"

	"system-transparency.org/stboot/sterror"
)

// Scope and operations used for raising Errors of this package.
const (
	ErrOpDSSign       sterror.Op = "DummySigner.Sign"
	ErrOpRSASSign     sterror.Op = "RSAPSSSigner.Sign"
	ErrOpRSASVerify   sterror.Op = "RSAPSSSigner.Verify"
	ErrOpEDSSign      sterror.Op = "ED25519Signer.Sign"
	ErrOpEDSVerify    sterror.Op = "ED25519Signer.Verify"
	ErrInfoInvalidKey            = "got key of type %T, expected %v"
)

// Errors which may be raised and wrapped in this package.
var (
	ErrSigning      = errors.New("signature creation failed")
	ErrVerification = errors.New("signature verification failed")
	ErrInvalidKey   = errors.New("invalid key type")
)

// Signer is used by OSPackage to sign and varify the OSPackage.
type Signer interface {
	Sign(key crypto.PrivateKey, data []byte) ([]byte, error)
	Verify(sig, hash []byte, key crypto.PublicKey) error
}

// DummySigner implements the Signer interface. It creates signatures
// that are always valid.
type DummySigner struct{}

var _ Signer = DummySigner{}

// Sign returns a signature containing just 8 random bytes.
func (DummySigner) Sign(key crypto.PrivateKey, data []byte) ([]byte, error) {
	const n = 8
	sig := make([]byte, n)

	if _, err := rand.Read(sig); err != nil {
		return nil, sterror.E(ErrScope, ErrOpDSSign, ErrSigning, err.Error())
	}

	return sig, nil
}

// Verify will never return an error.
func (DummySigner) Verify(sig, hash []byte, key crypto.PublicKey) error {
	return nil
}

// RSAPSSSigner implements the Signer interface. It uses SHA256 hashes
// and PSS signatures along with x509 certificates.
type RSAPSSSigner struct{}

var _ Signer = RSAPSSSigner{}

// Sign signes the provided data with the key named by privKey. The returned
// byte slice contains a PSS signature value.
// Problems are reported by an error wrapping SigningError.
func (RSAPSSSigner) Sign(key crypto.PrivateKey, data []byte) ([]byte, error) {
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, sterror.E(ErrScope, ErrOpRSASSign, ErrInvalidKey, fmt.Sprintf(ErrInfoInvalidKey, key, "rsa.PublicKey"))
	}

	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}

	ret, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, data, opts)
	if err != nil {
		return nil, sterror.E(ErrScope, ErrOpRSASSign, ErrSigning, err.Error())
	}

	return ret, nil
}

// Verify checks if sig contains a valid signature of hash.
func (RSAPSSSigner) Verify(sig, hash []byte, key crypto.PublicKey) error {
	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return sterror.E(ErrScope, ErrOpRSASVerify, ErrInvalidKey, fmt.Sprintf(ErrInfoInvalidKey, key, "rsa.PublicKey"))
	}

	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}

	err := rsa.VerifyPSS(pub, crypto.SHA256, hash, sig, opts)
	if err != nil {
		return sterror.E(ErrScope, ErrOpRSASVerify, ErrVerification)
	}

	return nil
}

type ED25519Signer struct{}

var _ Signer = ED25519Signer{}

// Sign signes the provided data with the key named by privKey.
// Problems are reported by an error wrapping SigningError.
func (ED25519Signer) Sign(key crypto.PrivateKey, data []byte) ([]byte, error) {
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, sterror.E(ErrScope, ErrOpEDSSign, ErrInvalidKey, fmt.Sprintf(ErrInfoInvalidKey, key, "ed25519.PublicKey"))
	}

	return ed25519.Sign(priv, data), nil
}

// Verify checks if sig contains a valid signature of hash.
func (ED25519Signer) Verify(sig, hash []byte, key crypto.PublicKey) error {
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return sterror.E(ErrScope, ErrOpEDSVerify, ErrInvalidKey, fmt.Sprintf(ErrInfoInvalidKey, key, "ed25519.PublicKey"))
	}

	isValid := ed25519.Verify(pub, hash, sig)
	if !isValid {
		return sterror.E(ErrScope, ErrOpEDSVerify, ErrVerification)
	}

	return nil
}
