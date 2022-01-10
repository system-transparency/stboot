package tcg

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"runtime"
	"strconv"

	"github.com/sirupsen/logrus"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/google/go-tpm/tpmutil/mssim"
	"github.com/immune-gmbh/agent/v2/pkg/api"
	"github.com/immune-gmbh/agent/v2/pkg/tcg/sgxtpm"
)

const (
	mssimCommandPort    = "2321"
	mssimPlatformPort   = "2322"
	mssimURLScheme      = "mssim"
	sgxTpmCommandPort   = "2321"
	sgxTpmPlatformPort  = "2322"
	sgxTpmURLScheme     = "sgx"
	netTpmURLScheme     = "net"
	maxCababilityBuffer = 1024
	maxCapapilityAlgs   = ((maxCababilityBuffer - 8) / 8)
	maxTpmProperties    = ((maxCababilityBuffer - 8) / 8)
)

type TCGHandle struct {
	Handle tpmutil.Handle
}

func (h *TCGHandle) Flush(a TrustAnchor) {
	tpm2.FlushContext(a.(*TCGAnchor).Conn, h.Handle)
}

type TCGAnchor struct {
	Conn io.ReadWriteCloser
}

func NewTCGAnchor(conn io.ReadWriteCloser) TrustAnchor {
	return &TCGAnchor{Conn: conn}
}

func (a *TCGAnchor) FlushAllHandles() {
	FlushTransientHandles(a.Conn)
}

func (a *TCGAnchor) Close() {
	a.Conn.Close()
}

func (a *TCGAnchor) Quote(aikHandle Handle, aikAuth string, additional api.Buffer, bank tpm2.Algorithm, pcrs []int) (api.Attest, api.Signature, error) {
	logrus.Traceln("tpm quote")

	aikH := aikHandle.(*TCGHandle).Handle
	pcrSel := tpm2.PCRSelection{
		Hash: bank,
		PCRs: pcrs,
	}

	// generate quote
	attestBuf, sig, err := tpm2.Quote(a.Conn, aikH, aikAuth, "" /*unused*/, []byte(additional), pcrSel, tpm2.AlgNull)
	if err != nil {
		logrus.Debugf("TPM2_Quote failed: %s", err)
		logrus.Error("TPM 2.0 attestation failed")
		return api.Attest{}, api.Signature{}, err
	}
	aikHandle.Flush(a)

	// fill evidence struct
	attest, err := tpm2.DecodeAttestationData(attestBuf)
	if err != nil {
		logrus.Debugf("TPM2_Quote did not return a valid TPM2B_ATTEST: %s", err)
		logrus.Error("Failed to decode TPM response")
		return api.Attest{}, api.Signature{}, err
	}

	return api.Attest(*attest), api.Signature(*sig), nil
}

func (a *TCGAnchor) PCRValues(bank tpm2.Algorithm, pcrsel []int) (map[string]api.Buffer, error) {
	logrus.Traceln("read PCRs")

	// get available PCR banks and convert it to a map of PCRs per hash
	tmp, err := CapabilityPCRs(a.Conn)
	if err != nil {
		return nil, err
	}
	pcrBankMap := make(map[tpm2.Algorithm][]int)
	for _, t := range tmp {
		pcrBankMap[t.Hash] = t.PCRs
	}

	// if a PCR does not return a value, check capabilities if it should be there
	pcrs := make(map[string]api.Buffer)
	for _, pcrIndex := range pcrsel {
		pcrSelection := tpm2.PCRSelection{
			Hash: bank,
			PCRs: []int{pcrIndex},
		}
		pcrVals, err := tpm2.ReadPCRs(a.Conn, pcrSelection)
		if err != nil {
			return nil, fmt.Errorf("unable to read PCRs from TPM: %v", err)
		}
		pcrVal, present := pcrVals[pcrIndex]
		if !present {
			pcrBank := pcrBankMap[bank]
			shouldBePresent := false
			for _, v := range pcrBank {
				shouldBePresent = v == pcrIndex
			}
			if shouldBePresent {
				return nil, fmt.Errorf("PCR %d value missing from response", pcrIndex)
			}
		}
		if pcrVal != nil {
			pcrs[strconv.Itoa(pcrIndex)] = api.Buffer(pcrVal)
		}
	}

	return pcrs, nil
}

func CapabilityAlgorithms(conn io.ReadWriteCloser) (algs []tpm2.AlgorithmDescription, err error) {
	var tmp []interface{}
	more := true
	fa := uint32(1)
	for more {
		var newTmp []interface{}
		newTmp, more, err = tpm2.GetCapability(conn, tpm2.CapabilityAlgs, maxCapapilityAlgs, fa)
		if err != nil {
			return nil, fmt.Errorf("tpm get capability (algorithms) failed: %w", err)
		}
		fa = uint32(newTmp[len(newTmp)-1].(tpm2.AlgorithmDescription).ID) + 1
		tmp = append(tmp, newTmp...)
	}

	for _, t := range tmp {
		a := t.(tpm2.AlgorithmDescription)
		algs = append(algs, a)
	}

	return
}

func CapabilityPCRs(conn io.ReadWriteCloser) (pcrs []tpm2.PCRSelection, err error) {
	var tmp []interface{}
	more := true
	fa := uint32(0)
	for more {
		var newTmp []interface{}
		newTmp, more, err = tpm2.GetCapability(conn, tpm2.CapabilityPCRs, maxTpmProperties, fa)
		if err != nil {
			return nil, fmt.Errorf("tpm get capability (algorithms) failed: %w", err)
		}
		fa = uint32(newTmp[len(newTmp)-1].(tpm2.PCRSelection).Hash)
		tmp = append(tmp, newTmp...)
	}

	for _, t := range tmp {
		p := t.(tpm2.PCRSelection)
		pcrs = append(pcrs, p)
	}

	return
}

func Property(conn io.ReadWriteCloser, prop uint32) (uint32, error) {
	caps, _, err := tpm2.GetCapability(conn, tpm2.CapabilityTPMProperties, 1, prop)
	if err != nil {
		return 0, err
	}

	if len(caps) == 0 {
		return 0, fmt.Errorf("TPM GetCapability returned invalid data")
	}
	if p, ok := caps[0].(tpm2.TaggedProperty); !ok || uint32(p.Tag) != prop {
		return 0, fmt.Errorf("TPM GetCapability returned invalid data")
	} else {
		return p.Value, nil
	}
}

func GetTPM2FamilyIndicator(conn io.ReadWriteCloser) (uint32, error) {
	return Property(conn, uint32(tpm2.FamilyIndicator))
}

func openNetTPM(url *url.URL) (io.ReadWriteCloser, error) {
	var rwc io.ReadWriteCloser
	sock, err := net.Dial("tcp", url.Hostname()+":"+url.Port())
	if err != nil {
		return nil, err
	}
	rwc = io.ReadWriteCloser(sock)
	_ = tpm2.Startup(rwc, tpm2.StartupClear)

	return rwc, nil
}

func openMsimTPM(url *url.URL) (io.ReadWriteCloser, error) {
	var config mssim.Config
	host := url.Hostname()
	config.CommandAddress = host + ":" + mssimCommandPort
	config.PlatformAddress = host + ":" + mssimPlatformPort
	rwc, err := mssim.Open(config)
	if err != nil {
		return nil, err
	}

	_ = tpm2.Startup(rwc, tpm2.StartupClear)
	return rwc, nil
}

func openSgxTPM(url *url.URL) (io.ReadWriteCloser, error) {
	var config sgxtpm.Config
	host := url.Hostname()
	config.CommandAddress = host + ":" + sgxTpmCommandPort
	config.PlatformAddress = host + ":" + sgxTpmPlatformPort
	rwc, err := sgxtpm.Open(config)
	if err != nil {
		return nil, err
	}

	_ = tpm2.Startup(rwc, tpm2.StartupClear)
	return rwc, nil
}

func FlushTransientHandles(conn io.ReadWriteCloser) error {
	vals, _, err := tpm2.GetCapability(conn, tpm2.CapabilityHandles, 100, uint32(tpm2.HandleTypeTransient)<<24)
	if err != nil {
		return err
	}

	if len(vals) > 0 {
		logrus.Debugf("Flushing %d transient objects off the TPM\n", len(vals))

		for _, handle := range vals {
			switch t := handle.(type) {
			default:

			case tpmutil.Handle:
				tpm2.FlushContext(conn, t)
			}
		}
	}

	return nil
}

// OpenTPM opens a connection to the TPM.
func OpenTPM(tpmPath string) (io.ReadWriteCloser, error) {
	if tpmPath == "builtin" {
		return NewSimulator()
	}
	if tpmPath == "system" {
		if runtime.GOOS == "windows" {
			return openTPM("")
		} else {
			return openTPM("/dev/tpm0")
		}
	}

	url, err := url.Parse(tpmPath)
	if err != nil {
		return nil, err
	}
	switch url.Scheme {
	case mssimURLScheme:
		return openMsimTPM(url)
	case sgxTpmURLScheme:
		return openSgxTPM(url)
	case netTpmURLScheme:
		return openNetTPM(url)
	default:
		return openTPM(tpmPath)
	}
}

// Comptes the TCG Name and Qualified Name of TPM 2.0 entities.
func ComputeName(path ...interface{}) (tpm2.Name, error) {
	// TPM 2.0 spec part 1, section 16
	// Name(PCR)       = Handle
	// Name(Session)   = Handle
	// Name(Permanent) = Handle
	// Name(NV Index)  = NameAlg || H_NameAlg(NVPublic)
	// Name(Object)    = NameAlg || H_NameAlg(Public)

	// TPM 2.0 spec part 1, section 26.5
	// QN(B) = H_NameAlg_B(QN(Parent(A)) || Name(B))
	// QN(Hierarchy) = Name(Hierarchy) = Hierarchy Handle
	var prevQN *tpm2.Name

	for _, entity := range path {
		var name tpm2.Name

		switch entity.(type) {
		case tpmutil.Handle:
			handle := entity.(tpmutil.Handle)

			switch handle & 0xff000000 {
			// PCR, HMAC session, Policy session, Permanent values
			case 0x00000000, 0x02000000, 0x03000000, 0x40000000:
				name.Handle = &handle

				// NV Index
			default:
				return tpm2.Name{}, errors.New("Need NVPublic to compute QName  of NV Index")
			}

		case tpm2.NVPublic:
			pub := entity.(tpm2.NVPublic)
			blob, err := tpmutil.Pack(pub)
			if err != nil {
				return tpm2.Name{}, err
			}

			hsh, err := pub.NameAlg.Hash()
			if err != nil {
				return tpm2.Name{}, err
			}

			name.Digest.Value = hsh.New().Sum([]byte(blob))
			name.Digest.Alg = pub.NameAlg

		case tpm2.Public:
			pub := entity.(tpm2.Public)
			nam, err := pub.Name()
			if err != nil {
				return tpm2.Name{}, err
			}
			name = nam

		case *tpm2.Public:
			pub := *(entity.(*tpm2.Public))
			nam, err := pub.Name()
			if err != nil {
				return tpm2.Name{}, err
			}
			name = nam

		case tpm2.Name:
			name = entity.(tpm2.Name)

		case *tpm2.Name:
			name = *(entity.(*tpm2.Name))

		default:
			return tpm2.Name{}, fmt.Errorf("Cannot compute Name of %#v", entity)
		}

		// special case: root entity
		if prevQN == nil {
			prevQN = &name
			continue
		}

		if name.Digest == nil {
			return tpm2.Name{}, errors.New("derived object is a handle")
		}

		// general case
		// QN(B) = H_NameAlg_B(QN(A) || Name(B))
		buf, err := tpm2.Name(name).Encode()
		if err != nil {
			return tpm2.Name{}, err
		}
		qbuf, err := tpm2.Name(*prevQN).Encode()
		if err != nil {
			return tpm2.Name{}, err
		}

		hshTy, err := name.Digest.Alg.Hash()
		if err != nil {
			return tpm2.Name{}, err
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
		return tpm2.Name{}, errors.New("no entities given")
	}

	return *prevQN, nil
}
