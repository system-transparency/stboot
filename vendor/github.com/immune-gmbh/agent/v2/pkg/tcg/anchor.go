package tcg

import (
	"crypto/x509"

	"github.com/google/go-tpm/tpm2"
	"github.com/immune-gmbh/agent/v2/pkg/api"
	"github.com/immune-gmbh/agent/v2/pkg/state"
)

type Handle interface {
	Flush(owner TrustAnchor)
}

type TrustAnchor interface {
	// Expects Public and Auth to be set
	CreateAndLoadRoot(endorsementAuth string, rootAuth string, tmpl *api.PublicKey) (Handle, api.PublicKey, error)
	// Create and load a new key under `parent` based on `template`. Certifies the
	// binding between outsideInfo and the key. "template" must allow signing.
	CreateAndCertifyDeviceKey(rootHandle Handle, rootAuth string, template api.KeyTemplate, authValue string) (api.Key, api.Buffer, error)
	LoadDeviceKey(rootHandle Handle, rootAuth string, public api.PublicKey, private api.Buffer) (Handle, error)
	ActivateDeviceKey(cred api.EncryptedCredential, endorsementAuth string, auth string, keyHandle Handle, ekHandle Handle, state *state.State) (string, error)

	ReadEKCertificate() (*x509.Certificate, error)
	GetEndorsementKey() (Handle, tpm2.Public, error)

	PCRValues(tpm2.Algorithm, []int) (map[string]api.Buffer, error)
	Quote(aikHandle Handle, aikAuth string, additional api.Buffer, bank tpm2.Algorithm, pcrs []int) (api.Attest, api.Signature, error)

	FlushAllHandles()
	Close()
}
