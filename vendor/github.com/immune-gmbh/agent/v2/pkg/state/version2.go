package state

import (
	"github.com/google/go-tpm/tpm2"
	"github.com/immune-gmbh/agent/v2/pkg/api"
)

var (
	rootKeyTemplate = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:     2048,
			ExponentRaw: 0,
			ModulusRaw:  make([]byte, 256),
		},
	}
)

type StateTpmKey struct {
	Public      api.PublicKey `json:"public"`
	Private     api.Buffer    `json:"private"`
	Auth        string        `json:"auth"`
	Certificate string        `json:"certificate"`
}

// Mutable run time data.
type StateV2 struct {
	Ty                     string           `json:"type"`
	EndorsementKey         api.PublicKey    `json:"ek"`
	EndorsementCertificate *api.Certificate `json:"ek-certificate"`
	RootKeyAuth            string           `json:"root-key-auth"`
	QuoteKey               StateTpmKey      `json:"quote-key"`
}
