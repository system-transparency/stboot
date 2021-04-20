package stboot

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
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
	sig := make([]byte, 8)
	_, err := rand.Read(sig)
	if err != nil {
		return nil, err
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
func (RSAPSSSigner) Sign(key crypto.PrivateKey, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("RSAPSSSigner: input data has zero length")
	}

	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("RSAPSSSigner: invalid key type %T", key)
	}

	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}

	return rsa.SignPSS(rand.Reader, priv, crypto.SHA256, data, opts)
}

// Verify checks if sig contains a valid signature of hash.
func (RSAPSSSigner) Verify(sig, hash []byte, key crypto.PublicKey) error {
	if len(sig) == 0 {
		return errors.New("RSAPSSSigner: signature has zero length")
	}
	if len(hash) == 0 {
		return errors.New("RSAPSSSigner: hash has zero length")
	}

	pub, ok := key.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("RSAPSSSigner: invalid key type %T", key)
	}

	opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
	return rsa.VerifyPSS(pub, crypto.SHA256, hash, sig, opts)
}

type ED25519Signer struct{}

var _ Signer = ED25519Signer{}

// Sign signes the provided data with the key named by privKey.
func (ED25519Signer) Sign(key crypto.PrivateKey, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("ED25519Signer: input data has zero length")
	}

	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ED25519Signer: invalid key type %T", key)
	}

	return ed25519.Sign(priv, data), nil
}

// Verify checks if sig contains a valid signature of hash.
func (ED25519Signer) Verify(sig, hash []byte, key crypto.PublicKey) error {
	if len(sig) == 0 {
		return errors.New("ED25519Signer: signature has zero length")
	}
	if len(hash) == 0 {
		return errors.New("ED25519Signer: hash has zero length")
	}

	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("ED25519Signer: invalid key type %T", key)
	}

	ok = ed25519.Verify(pub, hash, sig)
	if !ok {
		return errors.New("ED25519Signer: verification failed")
	}
	return nil
}
