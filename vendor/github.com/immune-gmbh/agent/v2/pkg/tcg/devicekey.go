package tcg

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	log "github.com/sirupsen/logrus"

	"github.com/immune-gmbh/agent/v2/pkg/api"
	"github.com/immune-gmbh/agent/v2/pkg/state"
)

var ErrInvalid = errors.New("invalid arg")

var (
	defaultRSASigningScheme = tpm2.SigScheme{
		Alg:  tpm2.AlgRSAPSS,
		Hash: tpm2.AlgSHA256,
	}
	defaultECCSigningScheme = tpm2.SigScheme{
		Alg:  tpm2.AlgECDSA,
		Hash: tpm2.AlgSHA256,
	}
)

func fromTPMCurve(cv tpm2.EllipticCurve) (elliptic.Curve, bool) {
	switch cv {
	case tpm2.CurveNISTP224:
		return elliptic.P224(), true
	case tpm2.CurveNISTP256:
		return elliptic.P256(), true
	case tpm2.CurveNISTP384:
		return elliptic.P384(), true
	case tpm2.CurveNISTP521:
		return elliptic.P521(), true
	default:
		return nil, false
	}
}

// Expects Public and Auth to be set
func (a *TCGAnchor) CreateAndLoadRoot(endorsementAuth string, rootAuth string, tmpl *api.PublicKey) (Handle, api.PublicKey, error) {
	log.Traceln("load root key")
	public := *tmpl

	// quick sanity check
	if public.Attributes&tpm2.FlagDecrypt == 0 {
		log.Debug("Root key must be a encryption-capable key")
		return nil, public, fmt.Errorf("invalid template")
	}

	// TPM2_CreatePrimary: create the key
	handle, pub, err := tpm2.CreatePrimary(
		a.Conn, tpm2.HandleEndorsement, tpm2.PCRSelection{}, endorsementAuth,
		rootAuth, tpm2.Public(public))
	if err != nil {
		log.Debugf("Failed to create device key: %s", err)
		return nil, public, err
	}

	if public.Type == tpm2.AlgRSA {
		rsaPub := *pub.(*rsa.PublicKey)
		rsaParms := tpm2.RSAParams{
			ModulusRaw:  rsaPub.N.Bytes(),
			ExponentRaw: 0,
			Symmetric:   public.RSAParameters.Symmetric,
			KeyBits:     public.RSAParameters.KeyBits,
		}
		public.RSAParameters = &rsaParms
	} else if public.Type == tpm2.AlgECC {
		eccPub := *pub.(*ecdsa.PublicKey)
		eccParms := tpm2.ECCParams{
			Point: tpm2.ECPoint{
				XRaw: eccPub.X.Bytes(),
				YRaw: eccPub.Y.Bytes(),
			},
			CurveID:   public.ECCParameters.CurveID,
			Symmetric: public.ECCParameters.Symmetric,
		}
		public.ECCParameters = &eccParms
	} else {
		log.Debug("Root key must be a RSA or ECC key")
		return nil, public, fmt.Errorf("invalid template")
	}

	return &TCGHandle{Handle: handle}, public, nil
}

// Create and load a new key under `parent` based on `template`. Certifies the
// binding between outsideInfo and the key. "template" must allow signing.
func (a *TCGAnchor) CreateAndCertifyDeviceKey(rootHandle Handle, rootAuth string, template api.KeyTemplate, authValue string) (api.Key, api.Buffer, error) {
	rootH := rootHandle.(*TCGHandle).Handle

	if template.Public.Attributes&tpm2.FlagSign == 0 {
		log.Debug("Must be a siging-capable key")
		return api.Key{}, api.Buffer{}, ErrInvalid
	}

	// TPM2_Create: create the key
	privBlob, pubBlob, _, hash, ticket, err := tpm2.CreateKeyWithOutsideInfo(
		a.Conn, rootH, tpm2.PCRSelection{}, rootAuth, authValue, tpm2.Public(template.Public), []byte(template.Label))
	if err != nil {
		log.Debugf("Failed to create device key: %s", err)
		return api.Key{}, api.Buffer{}, err
	}

	pub, err := tpm2.DecodePublic(pubBlob)
	if err != nil {
		log.Debugf("Failed to decode public area of the newly created key: %s", err)
		return api.Key{}, api.Buffer{}, err
	}

	// select the correct signing scheme for CertifyCreation
	var scheme tpm2.SigScheme
	if pub.Type == tpm2.AlgRSA {
		if pub.RSAParameters.Sign != nil {
			scheme = *pub.RSAParameters.Sign
		} else {
			scheme = defaultRSASigningScheme
		}
	} else if pub.Type == tpm2.AlgECC {
		if pub.ECCParameters.Sign != nil {
			scheme = *pub.ECCParameters.Sign
		} else {
			scheme = defaultECCSigningScheme
		}
	} else {
		log.Debugf("Unknown key type %v. Needs to be ECC or RSA", pub.Type)
		return api.Key{}, api.Buffer{}, ErrInvalid
	}

	// load the key into the TPM
	handle, _, err := tpm2.Load(a.Conn, rootH, rootAuth, pubBlob, privBlob)
	if err != nil {
		log.Debugf("Failed to load key after creation: %s", err)
		return api.Key{}, api.Buffer{}, err
	}

	// TPM2_CertifyCreation: create a proof that outsideInfo was part of TPM2_Create
	attestBlob, sigData, err := tpm2.CertifyCreation(a.Conn, authValue, handle, handle, []byte{}, hash, scheme, ticket)
	tpm2.FlushContext(a.Conn, handle)
	if err != nil {
		log.Debugf("Failed to attest key creation: %s", err)
		return api.Key{}, api.Buffer{}, err
	}

	// decode attestation structure
	attestRef, err := tpm2.DecodeAttestationData(attestBlob)
	if err != nil {
		log.Debugf("Failed to decode newly created attestation data: %s", err)
		return api.Key{}, api.Buffer{}, err
	}
	sigRef, err := tpm2.DecodeSignature(bytes.NewBuffer(sigData))
	if err != nil {
		log.Debugf("Failed to decode newly created attestation signature: %s", err)
		return api.Key{}, api.Buffer{}, err
	}

	key := api.Key{
		Public:                 api.PublicKey(pub),
		CreationProof:          api.Attest(*attestRef),
		CreationProofSignature: api.Signature(*sigRef),
	}

	return key, api.Buffer(privBlob), nil
}

func (a *TCGAnchor) LoadDeviceKey(rootHandle Handle, rootAuth string, public api.PublicKey, private api.Buffer) (Handle, error) {
	log.Traceln("loading device key")
	rootH := rootHandle.(*TCGHandle).Handle

	blob, err := tpm2.Public(public).Encode()
	if err != nil {
		return nil, err
	}

	// load the key into the TPM
	handle, _, err := tpm2.Load(a.Conn, rootH, rootAuth, blob, private)
	if err != nil {
		log.Debugf("Failed to load key: %s", err)
	}

	return &TCGHandle{Handle: handle}, err
}

func (a *TCGAnchor) ActivateDeviceKey(cred api.EncryptedCredential, endorsementAuth string, auth string, keyHandle Handle, ekHandle Handle, state *state.State) (string, error) {
	keyH := keyHandle.(*TCGHandle).Handle
	ekH := ekHandle.(*TCGHandle).Handle

	ekSession, _, err := tpm2.StartAuthSession(
		a.Conn,
		tpm2.HandleNull,  /*tpmKey*/
		tpm2.HandleNull,  /*bindKey*/
		make([]byte, 16), /*nonceCaller*/
		nil,              /*secret*/
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return "", fmt.Errorf("creating ek session: %v", err)
	}

	defer tpm2.FlushContext(a.Conn, ekSession)

	if len(cred.Secret) < 2 {
		return "", fmt.Errorf("credential secret not a TPM2B structure")
	}

	authCmd := tpm2.AuthCommand{
		Session:    tpm2.HandlePasswordSession,
		Attributes: tpm2.AttrContinueSession,
		Auth:       []byte(endorsementAuth),
	}

	_, err = tpm2.PolicySecret(a.Conn, tpm2.HandleEndorsement, authCmd, ekSession, nil, nil, nil, 0)
	if err != nil {
		return "", fmt.Errorf("tpm2.PolicySecret() failed: %v", err)
	}

	authCmds := []tpm2.AuthCommand{
		{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession, Auth: []byte(auth)},
		{Session: ekSession, Attributes: tpm2.AttrContinueSession},
	}
	certKey, err := tpm2.ActivateCredentialUsingAuth(
		a.Conn, authCmds, keyH, ekH, cred.KeyID, cred.Secret[2:])
	if err != nil {
		return "", fmt.Errorf("Activate device key certificate: %v", err)
	}
	block, err := aes.NewCipher(certKey)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	c, err := aesgcm.Open(nil, cred.Nonce, cred.Credential, nil)
	if err != nil {
		return "", err
	}

	return string(c), nil
}

// Generates a string with at least 128 bits of entrophy
func GenerateAuthValue() (string, error) {
	auth := make([]byte, 32)

	l, err := crand.Read(auth)
	if l != 32 || err != nil {
		return "", err
	}

	for i := range auth {
		// clamp the byte to [0, 64)
		auth[i] &= 0x3f

		if auth[i] < 26 {
			// [0, 26) -> A-Z
			auth[i] += 0x41
		} else if auth[i] < 52 {
			// [26, 52) -> a-z
			auth[i] = auth[i] - 26 + 0x61
		} else if auth[i] < 62 {
			// [52, 62) -> 0-9
			auth[i] = auth[i] - 52 + 0x30
		} else {
			// [62, 64) -> #,$
			auth[i] = auth[i] - 62 + 0x23
		}
	}

	return string(auth), nil
}
