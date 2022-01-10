package api

import (
	"bytes"
	"crypto/x509"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

type Buffer []byte

func (a Buffer) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.StdEncoding.EncodeToString(a))
}

func (a *Buffer) UnmarshalJSON(data []byte) error {
	var str string

	err := json.Unmarshal(data, &str)
	if err != nil {
		return fmt.Errorf("Buffer.UnmarshalJSON('%s'): %s", string(data), err)
	}

	x, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return fmt.Errorf("Buffer.UnmarshalJSON('%s'): %s", string(data), err)
	}

	*a = Buffer(x)
	return nil
}

// TPM2_Name wrapper type
type Name tpm2.Name

func (nam Name) Value() (driver.Value, error) {
	buf, err := tpm2.Name(nam).Encode()
	if err != nil {
		return buf, err
	}
	return driver.Value(buf), nil
}

func (nam *Name) Scan(src interface{}) error {
	var buf []byte
	// let's support string and []byte
	switch src.(type) {
	case string:
		buf = []byte(src.(string))
	case []byte:
		buf = src.([]byte)
	default:
		return errors.New("Incompatible type for api.Name")
	}
	newnam, err := tpm2.DecodeName(bytes.NewBuffer(buf))
	if err == nil {
		*nam = Name(*newnam)
	}
	return err
}

func (n Name) MarshalJSON() ([]byte, error) {
	buf, err := tpm2.Name(n).Encode()
	if err != nil {
		return nil, err
	}

	return json.Marshal(hex.EncodeToString(buf))
}

func (n *Name) UnmarshalJSON(data []byte) error {
	var str string

	err := json.Unmarshal(data, &str)
	if err != nil {
		return fmt.Errorf("Name.UnmarshalJSON('%s'): %s", string(data), err)
	}

	x, err := hex.DecodeString(str)
	if err != nil {
		return fmt.Errorf("Name.UnmarshalJSON('%s'): %s", string(data), err)
	}

	nam, err := tpm2.DecodeName(bytes.NewBuffer(x))
	if err != nil {
		return fmt.Errorf("Name.UnmarshalJSON('%s'): %s", string(data), err)
	}

	if nam != nil {
		*n = Name(*nam)
		return nil
	}

	return fmt.Errorf("failed to scan Name from %v", data)
}

func EqualNames(n1 *Name, n2 *Name) bool {
	nam1 := (*tpm2.Name)(n1)
	nam2 := (*tpm2.Name)(n2)
	if nam1.Handle != nil && nam2.Handle != nil {
		return *(nam1.Handle) == *(nam2.Handle)
	} else if nam1.Digest != nil && nam2.Digest != nil {
		return nam1.Digest.Alg == nam2.Digest.Alg && bytes.Compare([]byte(nam1.Digest.Value), []byte(nam2.Digest.Value)) == 0
	} else {
		return false
	}
}

// Comptes the TCG Name and Qualified Name of TPM 2.0 entities.
func ComputeName(path ...interface{}) (Name, error) {
	// TPM 2.0 spec part 1, section 16
	// Name(PCR)       = Handle
	// Name(Session)   = Handle
	// Name(Permanent) = Handle
	// Name(NV Index)  = NameAlg || H_NameAlg(NVPublic)
	// Name(Object)    = NameAlg || H_NameAlg(Public)

	// TPM 2.0 spec part 1, section 26.5
	// QN(B) = H_NameAlg_B(QN(Parent(A)) || Name(B))
	// QN(Hierarchy) = Name(Hierarchy) = Hierarchy Handle
	var prevQN *Name

	for _, entity := range path {
		var name Name

		switch entity.(type) {
		case tpmutil.Handle:
			handle := entity.(tpmutil.Handle)

			switch handle & 0xff000000 {
			// PCR, HMAC session, Policy session, Permanent values
			case 0x00000000, 0x02000000, 0x03000000, 0x40000000:
				name.Handle = &handle

				// NV Index
			default:
				return Name{}, errors.New("Need NVPublic to compute QName  of NV Index")
			}

		case tpm2.NVPublic:
			pub := entity.(tpm2.NVPublic)
			blob, err := tpmutil.Pack(pub)
			if err != nil {
				return Name{}, err
			}

			hsh, err := pub.NameAlg.Hash()
			if err != nil {
				return Name{}, err
			}

			name.Digest.Value = hsh.New().Sum([]byte(blob))
			name.Digest.Alg = pub.NameAlg

		case PublicKey:
			pub := entity.(PublicKey)
			nam, err := tpm2.Public(pub).Name()
			if err != nil {
				return Name{}, err
			}
			name = Name(nam)

		case tpm2.Public:
			pub := entity.(tpm2.Public)
			nam, err := pub.Name()
			if err != nil {
				return Name{}, err
			}
			name = Name(nam)

		case Name:
			name = entity.(Name)

		case tpm2.Name:
			name = Name(entity.(tpm2.Name))

		default:
			return Name{}, fmt.Errorf("Cannot compute Name of %#v", entity)
		}

		// special case: root entity
		if prevQN == nil {
			prevQN = &name
			continue
		}

		if name.Digest == nil {
			return Name{}, errors.New("derived object is a handle")
		}

		// general case
		// QN(B) = H_NameAlg_B(QN(A) || Name(B))
		buf, err := tpm2.Name(name).Encode()
		if err != nil {
			return Name{}, err
		}
		qbuf, err := tpm2.Name(*prevQN).Encode()
		if err != nil {
			return Name{}, err
		}

		hshTy, err := name.Digest.Alg.Hash()
		if err != nil {
			return Name{}, err
		}
		hsh := hshTy.New()
		hsh.Write(qbuf[2:])
		hsh.Write(buf[2:])

		prevQN.Handle = nil
		prevQN.Digest = &tpm2.HashValue{
			Value: hsh.Sum([]byte{}),
			Alg:   name.Digest.Alg,
		}
	}

	if prevQN == nil {
		return Name{}, errors.New("no entities given")
	}

	return *prevQN, nil
}

// TPM2B_ATTEST wrapper type
type Attest tpm2.AttestationData

func (a Attest) MarshalJSON() ([]byte, error) {
	buf, err := tpm2.AttestationData(a).Encode()
	if err != nil {
		return nil, err
	}

	return json.Marshal(base64.StdEncoding.EncodeToString(buf))
}

func (a *Attest) UnmarshalJSON(data []byte) error {
	var str string

	err := json.Unmarshal(data, &str)
	if err != nil {
		return fmt.Errorf("Attest.UnmarshalJSON('%s'): %s", string(data), err)
	}

	x, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return fmt.Errorf("Attest.UnmarshalJSON('%s'): %s", string(data), err)
	}

	att, err := tpm2.DecodeAttestationData(x)
	if err != nil {
		return fmt.Errorf("Attest.UnmarshalJSON('%s'): %s", string(data), err)
	}

	if att != nil {
		*a = Attest(*att)
		return nil
	}

	return fmt.Errorf("failed to decode Attest from %v", data)
}

// TPMT_SIGNATURE wrapper type
type Signature tpm2.Signature

func (a Signature) MarshalJSON() ([]byte, error) {
	var buf []byte
	var err error

	if a.ECC != nil {
		buf, err = tpmutil.Pack(a.Alg, a.ECC.HashAlg, tpmutil.U16Bytes(a.ECC.R.Bytes()), tpmutil.U16Bytes(a.ECC.S.Bytes()))
	} else if a.RSA != nil {
		buf, err = tpmutil.Pack(a.Alg, a.RSA.HashAlg, a.RSA.Signature)
	} else {
		buf, err = tpmutil.Pack(a.Alg)
	}

	if err == nil {
		return json.Marshal(base64.StdEncoding.EncodeToString(buf))
	} else {
		return []byte{}, err
	}
}

func (a *Signature) UnmarshalJSON(data []byte) error {
	var str string

	err := json.Unmarshal(data, &str)
	if err != nil {
		return fmt.Errorf("Signature.UnmarshalJSON('%s'): %s", string(data), err)
	}

	x, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return fmt.Errorf("Signature.UnmarshalJSON('%s'): %s", string(data), err)
	}

	att, err := tpm2.DecodeSignature(bytes.NewBuffer(x))
	if err != nil {
		return fmt.Errorf("Signature.UnmarshalJSON('%s'): %s", string(data), err)
	}

	if att != nil {
		*a = Signature(*att)
		return nil
	}

	return fmt.Errorf("failed to decode Signature from %v", data)
}

// TPMT_PUBLIC wrapper type
type PublicKey tpm2.Public

func (pub PublicKey) Value() (driver.Value, error) {
	buf, err := tpm2.Public(pub).Encode()
	if err != nil {
		return nil, err
	}
	return driver.Value(buf), nil
}

func (pub *PublicKey) Scan(src interface{}) error {
	var buf []byte
	switch src.(type) {
	case string:
		buf = []byte(src.(string))
	case []byte:
		buf = src.([]byte)
	default:
		return errors.New("Incompatible type for api.Name")
	}
	newpub, err := tpm2.DecodePublic(buf)
	if err == nil {
		*pub = PublicKey(newpub)
	}
	return err
}

func (a PublicKey) MarshalJSON() ([]byte, error) {
	buf, err := tpm2.Public(a).Encode()
	if err == nil {
		return json.Marshal(base64.StdEncoding.EncodeToString(buf))
	} else {
		return []byte{}, err
	}
}

func (a *PublicKey) UnmarshalJSON(data []byte) error {
	var str string

	err := json.Unmarshal(data, &str)
	if err != nil {
		return fmt.Errorf("PublicKey.UnmarshalJSON('%s'): %s", string(data), err)
	}

	x, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return fmt.Errorf("PublicKey.UnmarshalJSON('%s'): %s", string(data), err)
	}

	att, err := tpm2.DecodePublic(x)
	if err != nil {
		return fmt.Errorf("PublicKey.UnmarshalJSON('%s'): %s", string(data), err)
	}

	*a = PublicKey(att)
	return nil
}

func (p *PublicKey) Encode() (Buffer, error) {
	buf, err := (*tpm2.Public)(p).Encode()
	return Buffer(buf), err
}

func (p *PublicKey) Name() (Name, error) {
	nam, err := (*tpm2.Public)(p).Name()
	return Name(nam), err
}

// TPMS_NV_PUBLIC wrapper type
type NVPublic tpm2.NVPublic

func (pub NVPublic) Value() (driver.Value, error) {
	buf, err := tpmutil.Pack(tpm2.NVPublic(pub))
	if err != nil {
		return nil, err
	}

	return driver.Value(buf), nil
}

func (pub *NVPublic) Scan(src interface{}) error {
	var buf []byte
	switch src.(type) {
	case string:
		buf = []byte(src.(string))
	case []byte:
		buf = src.([]byte)
	default:
		return errors.New("Incompatible type for api.Name")
	}
	var p tpm2.NVPublic
	_, err := tpmutil.Unpack(buf, &p)
	if err == nil {
		*pub = NVPublic(p)
	}

	return err
}

func (a NVPublic) MarshalJSON() ([]byte, error) {
	buf, err := tpmutil.Pack(tpm2.NVPublic(a))
	if err == nil {
		return json.Marshal(base64.StdEncoding.EncodeToString(buf))
	} else {
		return []byte{}, err
	}
}

func (a *NVPublic) UnmarshalJSON(data []byte) error {
	var str string

	err := json.Unmarshal(data, &str)
	if err != nil {
		return fmt.Errorf("NVPublic.UnmarshalJSON('%s'): %s", string(data), err)
	}

	x, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		return fmt.Errorf("NVPublic.UnmarshalJSON('%s'): %s", string(data), err)
	}

	var p tpm2.NVPublic
	_, err = tpmutil.Unpack(x, &p)
	if err != nil {
		return fmt.Errorf("NVPublic.UnmarshalJSON('%s'): %s", string(data), err)
	}

	*a = NVPublic(p)
	return nil
}

// Certificate wrapper type
type Certificate x509.Certificate

func (c Certificate) MarshalJSON() ([]byte, error) {
	s := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	return json.Marshal(s)
}

func (c *Certificate) UnmarshalJSON(data []byte) error {
	var str string

	err := json.Unmarshal(data, &str)
	if err != nil {
		return fmt.Errorf("Certificate.UnmarshalJSON('%s'): %s", string(data), err)
	}

	cc, err := unmarshalPemCertificate([]byte(str))
	if err == nil {
		*c = Certificate(*cc)
		return nil
	} else {
		return fmt.Errorf("Certificate.UnmarshalJSON('%s'): %s", string(data), err)
	}
}

func unmarshalPemCertificate(data []byte) (*x509.Certificate, error) {
	ekPemBlock, _ := pem.Decode(data)
	if ekPemBlock == nil || ekPemBlock.Type != "CERTIFICATE" {
		return &x509.Certificate{}, fmt.Errorf("Certificate is not valid Base64")
	}

	if ekPemBlock.Bytes == nil || len(ekPemBlock.Bytes) == 0 {
		return &x509.Certificate{}, nil
	} else {
		return x509.ParseCertificate(ekPemBlock.Bytes)
	}
}
