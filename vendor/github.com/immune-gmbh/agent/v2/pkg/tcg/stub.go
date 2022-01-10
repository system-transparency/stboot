package tcg

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/immune-gmbh/agent/v2/pkg/api"
	"github.com/immune-gmbh/agent/v2/pkg/state"
)

var (
	endorsmentRSAKeyTemplate = api.PublicKey{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagDecrypt,
		AuthPolicy: nil,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				Mode:    tpm2.AlgCFB,
				KeyBits: 128,
			},
			KeyBits: 2048,
		},
	}
	endorsmentECCKeyTemplate = api.PublicKey{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagDecrypt,
		AuthPolicy: nil,
		ECCParameters: &tpm2.ECCParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				Mode:    tpm2.AlgCFB,
				KeyBits: 128,
			},
			CurveID: tpm2.CurveNISTP256,
			KDF: &tpm2.KDFScheme{
				Alg:  tpm2.AlgKDF2,
				Hash: tpm2.AlgSHA256,
			},
		},
	}
)

type SoftwareHandle struct {
	ty      string
	public  *api.PublicKey
	private crypto.PrivateKey
	qn      *api.Name
}

func (*SoftwareHandle) Flush(TrustAnchor) {
	return
}

const (
	SoftwareAnchorStateType = "software-anchor/1"
)

type SoftwareAnchor struct {
	rootKey        crypto.PrivateKey
	endorsementKey *SoftwareHandle
}

func NewSoftwareAnchor() (TrustAnchor, error) {
	eh, err := ComputeName(tpm2.HandleEndorsement)
	ek, err := generateKey("ek", (*api.Name)(&eh), &endorsmentRSAKeyTemplate)
	if err != nil {
		return nil, err
	}

	ret := SoftwareAnchor{
		endorsementKey: ek,
	}
	return &ret, nil
}

func (s *SoftwareAnchor) Store() (*state.StubState, error) {
	ek, err := x509.MarshalPKCS8PrivateKey(s.endorsementKey.private)
	if err != nil {
		return nil, err
	}
	root, err := x509.MarshalPKCS8PrivateKey(s.rootKey)
	if err != nil {
		return nil, err
	}

	ret := state.StubState{
		Type:           SoftwareAnchorStateType,
		EndorsementKey: api.Buffer(ek),
		RootKey:        api.Buffer(root),
	}

	return &ret, nil
}

func LoadSoftwareAnchor(state *state.StubState) (TrustAnchor, error) {
	eh, err := ComputeName(tpm2.HandleEndorsement)
	if err != nil {
		return nil, err
	}
	ekpriv, err := x509.ParsePKCS8PrivateKey(state.EndorsementKey)
	if err != nil {
		return nil, err
	}
	ek, err := wrapKey("ek", (*api.Name)(&eh), &endorsmentRSAKeyTemplate, ekpriv)
	if err != nil {
		return nil, err
	}

	rootpriv, err := x509.ParsePKCS8PrivateKey(state.RootKey)
	if err != nil {
		return nil, err
	}

	ret := SoftwareAnchor{
		endorsementKey: ek,
		rootKey:        rootpriv,
	}
	return &ret, nil
}

func (s *SoftwareAnchor) FlushAllHandles() {
	return
}

func (s *SoftwareAnchor) Close() {
	return
}

func (a *SoftwareAnchor) Quote(aikHandle Handle, aikAuth string, additional api.Buffer, bank tpm2.Algorithm, pcrs []int) (api.Attest, api.Signature, error) {
	aikH := aikHandle.(*SoftwareHandle)
	if aikH.ty != "dev" {
		return api.Attest{}, api.Signature{}, errors.New("wrong aik")
	}

	pcrHash, err := bank.Hash()
	if err != nil {
		return api.Attest{}, api.Signature{}, err
	}
	pcrHasher := pcrHash.New()
	digest := make([]byte, pcrHash.Size())
	for range pcrs {
		pcrHasher.Write(digest)
	}

	attest := tpm2.AttestationData{
		Magic:           0xff544347,
		Type:            tpm2.TagAttestQuote,
		QualifiedSigner: tpm2.Name(*aikH.qn),
		ExtraData:       []byte(additional),
		ClockInfo:       tpm2.ClockInfo{},
		FirmwareVersion: 0,
		AttestedQuoteInfo: &tpm2.QuoteInfo{
			PCRSelection: tpm2.PCRSelection{
				Hash: bank,
				PCRs: pcrs,
			},
			PCRDigest: pcrHasher.Sum([]byte{}),
		},
	}

	attestBuf, err := attest.Encode()
	if err != nil {
		return api.Attest{}, api.Signature{}, err
	}
	attestDst := sha256.Sum256(attestBuf)
	eccPriv := aikH.private.(*ecdsa.PrivateKey)
	rr, ss, err := ecdsa.Sign(rand.Reader, eccPriv, attestDst[:])
	if err != nil {
		return api.Attest{}, api.Signature{}, err
	}

	sig := api.Signature{
		Alg: tpm2.AlgECDSA,
		ECC: &tpm2.SignatureECC{
			HashAlg: tpm2.AlgSHA256,
			R:       rr,
			S:       ss,
		},
	}

	return api.Attest(attest), sig, nil
}

func (s *SoftwareAnchor) PCRValues(bank tpm2.Algorithm, pcrs []int) (map[string]api.Buffer, error) {
	ret := make(map[string]api.Buffer)
	hash, err := bank.Hash()
	if err != nil {
		return nil, err
	}

	for _, pcr := range pcrs {
		ret[fmt.Sprintf("%d", pcr)] = make([]byte, hash.Size())
	}

	return ret, nil
}

func (s *SoftwareAnchor) ReadEKCertificate() (*x509.Certificate, error) {
	return nil, errors.New("no ek")
}

func (s *SoftwareAnchor) GetEndorsementKey() (Handle, tpm2.Public, error) {
	return s.endorsementKey, tpm2.Public(*s.endorsementKey.public), nil
}

func (s *SoftwareAnchor) CreateAndLoadRoot(endorsementAuth string, rootAuth string, tmpl *api.PublicKey) (Handle, api.PublicKey, error) {
	if tmpl.Type != tpm2.AlgECC || tmpl.NameAlg != tpm2.AlgSHA256 {
		return nil, api.PublicKey{}, errors.New("wrong template")
	}

	qn, err := ComputeName(tpm2.HandleEndorsement)
	if err != nil {
		return nil, api.PublicKey{}, err
	}

	if s.rootKey == nil {
		handle, err := generateKey("root", (*api.Name)(&qn), tmpl)
		if err == nil {
			s.rootKey = handle.private
		}
		return handle, *handle.public, err
	} else {
		handle, err := wrapKey("root", (*api.Name)(&qn), tmpl, s.rootKey)
		return handle, *handle.public, err
	}
}

func (s *SoftwareAnchor) CreateAndCertifyDeviceKey(rootHandle Handle, rootAuth string, template api.KeyTemplate, authValue string) (api.Key, api.Buffer, error) {
	if template.Public.Type != tpm2.AlgECC || template.Public.NameAlg != tpm2.AlgSHA256 {
		return api.Key{}, nil, errors.New("wrong template")
	}

	rootH := rootHandle.(*SoftwareHandle)
	if rootH.ty != "root" {
		return api.Key{}, nil, errors.New("wrong parent")
	}

	handle, err := generateKey("dev", rootH.qn, &template.Public)
	if err != nil {
		return api.Key{}, nil, err
	}
	pub := handle.public
	nam, err := pub.Name()
	if err != nil {
		return api.Key{}, nil, err
	}

	// creation data
	rootNam, err := rootH.public.Name()
	if err != nil {
		return api.Key{}, nil, err
	}
	nameAlgHash, err := pub.NameAlg.Hash()
	if err != nil {
		return api.Key{}, nil, err
	}

	creationData := tpm2.CreationData{
		PCRSelection: tpm2.PCRSelection{},
		// in part 2, table 212 it says "[..] pcrDigest.size shall be zero if
		// the pcrSelect list is empty." but the code in part 4 8.7.3.22 sets
		// pcrDigest to the hash of nothing.
		PCRDigest:           nameAlgHash.New().Sum([]byte{}),
		Locality:            1, // XXX: only applies to swtpm
		ParentNameAlg:       rootH.public.NameAlg,
		ParentName:          tpm2.Name(rootNam),
		ParentQualifiedName: tpm2.Name(*rootH.qn),
		OutsideInfo:         []byte(template.Label),
	}
	creationDataBlob, err := creationData.EncodeCreationData()
	if err != nil {
		return api.Key{}, nil, err
	}
	opaqueHasher := nameAlgHash.New()
	opaqueHasher.Write(creationDataBlob)

	attest := tpm2.AttestationData{
		Magic:           0xff544347,
		Type:            tpm2.TagAttestCreation,
		QualifiedSigner: tpm2.Name(*handle.qn),
		ExtraData:       []byte{},
		ClockInfo:       tpm2.ClockInfo{},
		FirmwareVersion: 0,
		AttestedCreationInfo: &tpm2.CreationInfo{
			Name:         tpm2.Name(nam),
			OpaqueDigest: opaqueHasher.Sum([]byte{}),
		},
	}

	attestBuf, err := attest.Encode()
	if err != nil {
		return api.Key{}, nil, err
	}
	attestDst := sha256.Sum256(attestBuf)

	var sig api.Signature
	switch handle.private.(type) {
	case *ecdsa.PrivateKey:
		eccPriv := handle.private.(*ecdsa.PrivateKey)
		rr, ss, err := ecdsa.Sign(rand.Reader, eccPriv, attestDst[:])
		if err != nil {
			return api.Key{}, nil, err
		}
		sig = api.Signature{
			Alg: tpm2.AlgECDSA,
			ECC: &tpm2.SignatureECC{
				HashAlg: tpm2.AlgSHA256,
				R:       rr,
				S:       ss,
			},
		}

	case *rsa.PrivateKey:
		return api.Key{}, nil, errors.New("rsa is not implemented")

	default:
		return api.Key{}, nil, errors.New("unknown key type")
	}

	key := api.Key{
		Public:                 *pub,
		CreationProof:          api.Attest(attest),
		CreationProofSignature: sig,
	}

	buf, err := x509.MarshalPKCS8PrivateKey(handle.private)
	return key, api.Buffer(buf), err
}

func (s *SoftwareAnchor) LoadDeviceKey(rootHandle Handle, rootAuth string, public api.PublicKey, private api.Buffer) (Handle, error) {
	rootH := rootHandle.(*SoftwareHandle)
	if rootH.ty != "root" {
		return nil, errors.New("wrong parent key")
	}

	handle, err := loadKey("dev", rootH.qn, &public, &private)
	if err != nil {
		return nil, err
	}

	return handle, nil
}

func (s *SoftwareAnchor) ActivateDeviceKey(cred api.EncryptedCredential, endorsementAuth string, auth string, keyHandle Handle, ekHandle Handle, state *state.State) (string, error) {
	ekH := ekHandle.(*SoftwareHandle)
	if ekH.ty != "ek" {
		return "", errors.New("wrong parent key")
	}
	keyH := keyHandle.(*SoftwareHandle)
	if keyH.ty != "dev" {
		return "", errors.New("wrong aik")
	}
	nam, err := keyH.public.Name()
	if err != nil {
		return "", err
	}
	namBuf, err := tpm2.Name(nam).Encode()
	if err != nil {
		return "", err
	}

	ekRsaPriv := ekH.private.(*rsa.PrivateKey)

	keyNameAlg, err := keyH.public.NameAlg.Hash()
	if err != nil {
		return "", err
	}
	label := append([]byte("IDENTITY"), 0)
	encSecret := []byte(cred.Secret)[2:]
	seedValue, err := rsa.DecryptOAEP(keyNameAlg.New(), rand.Reader, ekRsaPriv, encSecret, label)
	if err != nil {
		return "", err
	}

	symKey, err := tpm2.KDFa(keyH.public.NameAlg, seedValue, "STORAGE", namBuf[2:], nil, len(seedValue)*8)
	if err != nil {
		return "", err
	}

	// XXX: we don't check the HMAC

	var idObject tpm2.IDObject
	buf := bytes.NewBuffer(cred.KeyID)
	err = tpmutil.UnpackBuf(buf, &idObject.IntegrityHMAC)
	if err != nil {
		return "", err
	}
	idObject.EncIdentity, err = io.ReadAll(buf)
	if err != nil {
		return "", err
	}

	blk, err := aes.NewCipher(symKey)
	if err != nil {
		return "", err
	}
	iv := make([]byte, blk.BlockSize())
	cfb := cipher.NewCFBDecrypter(blk, iv)
	aesKey := make([]byte, len(idObject.EncIdentity))
	cfb.XORKeyStream(aesKey, idObject.EncIdentity)

	blk, err = aes.NewCipher(aesKey[2:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return "", err
	}

	plaincred, err := gcm.Open(nil, cred.Nonce, cred.Credential, nil)
	return string(plaincred), err
}

// poor man's deep copy
func copyPublic(template *api.PublicKey) (*api.PublicKey, error) {
	buf, err := template.Encode()
	if err != nil {
		return nil, err
	}
	if pub, err := tpm2.DecodePublic(buf); err != nil {
		return nil, err
	} else {
		return (*api.PublicKey)(&pub), nil
	}
}

func loadKey(ty string, parentQN *api.Name, pub *api.PublicKey, buf *api.Buffer) (*SoftwareHandle, error) {
	key, err := x509.ParsePKCS8PrivateKey([]byte(*buf))
	if err != nil {
		return nil, err
	}

	switch pub.Type {
	case tpm2.AlgECC:
		if _, ok := key.(*ecdsa.PrivateKey); !ok {
			return nil, errors.New("wrong key type")
		}

	case tpm2.AlgRSA:
		if _, ok := key.(*rsa.PrivateKey); !ok {
			return nil, errors.New("wrong key type")
		}

	default:
		return nil, errors.New("unknown key type")
	}

	qn, err := ComputeName(tpm2.Name(*parentQN), tpm2.Public(*pub))
	if err != nil {
		return nil, err
	}
	handle := SoftwareHandle{
		ty:      ty,
		qn:      (*api.Name)(&qn),
		private: key,
		public:  pub,
	}

	return &handle, nil
}

func generateKey(ty string, parentQN *api.Name, template *api.PublicKey) (*SoftwareHandle, error) {
	var key crypto.PrivateKey

	switch template.Type {
	case tpm2.AlgECC:
		eckey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		key = eckey

	case tpm2.AlgRSA:
		rsakey, err := rsa.GenerateKey(rand.Reader, int(template.RSAParameters.KeyBits))
		if err != nil {
			return nil, err
		}
		key = rsakey

	default:
		return nil, errors.New("unknown key type")
	}

	return wrapKey(ty, parentQN, template, key)
}

func wrapKey(ty string, parentQN *api.Name, template *api.PublicKey, private crypto.PrivateKey) (*SoftwareHandle, error) {
	pub, err := copyPublic(template)
	if err != nil {
		return nil, err
	}

	switch pub.Type {
	case tpm2.AlgECC:
		eckey, ok := private.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("wrong key type")
		}
		pub.ECCParameters.Point = tpm2.ECPoint{
			XRaw: eckey.X.Bytes(),
			YRaw: eckey.Y.Bytes(),
		}

	case tpm2.AlgRSA:
		rsakey, ok := private.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("wrong key type")
		}
		pub.RSAParameters.ModulusRaw = rsakey.PublicKey.N.Bytes()
		pub.RSAParameters.ExponentRaw = uint32(rsakey.PublicKey.E)

	default:
		return nil, errors.New("unknown key type")
	}

	qn, err := ComputeName(tpm2.Name(*parentQN), tpm2.Public(*pub))
	if err != nil {
		return nil, err
	}
	handle := SoftwareHandle{
		ty:      ty,
		qn:      (*api.Name)(&qn),
		private: private,
		public:  pub,
	}

	return &handle, nil
}
