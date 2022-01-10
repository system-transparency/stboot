package attestation

import (
	"context"
	"errors"
	"path"

	tpm1 "github.com/google/go-tpm/tpm"
	"github.com/immune-gmbh/agent/v2/pkg/api"
	"github.com/immune-gmbh/agent/v2/pkg/attestation"
	"github.com/immune-gmbh/agent/v2/pkg/state"
	"github.com/immune-gmbh/agent/v2/pkg/tcg"
)

const (
	stateDir string = "/tmp/immune"
	tpmPath         = "/dev/tpm0"
)

type ImmuneConnection struct {
	// on-disk state
	State *state.State

	// derived from cli opts
	Client          api.Client
	Anchor          tcg.TrustAnchor
	EndorsementAuth string
}

// load and migrate on-disk state
func loadFreshState(stateDir string, ic *ImmuneConnection) error {
	st, err := state.LoadState(stateDir)
	if errors.Is(err, state.ErrNotExist) {
		ic.State = state.NewState()
	} else if errors.Is(err, state.ErrNoPerm) {
		return err
	} else if err != nil {
		return err
	} else {
		ic.State = st
	}

	if err := ic.State.EnsureFresh(&ic.Client); err != nil {
		return err
	}

	return nil
}

// open TPM 2.0 connection and flush stale handles
func openAndClearTPM(tpmUrl string, ic *ImmuneConnection) error {
	conn, err := tcg.OpenTPM(tpmUrl)
	if err != nil {
		if ic.State.StubState != nil {
			anch, err := tcg.LoadSoftwareAnchor(ic.State.StubState)
			if err != nil {
				ic.State.StubState = nil
			} else {
				ic.Anchor = anch
			}
		}

		if ic.Anchor == nil {
			anch, err := tcg.NewSoftwareAnchor()
			if err != nil {
				return err
			}
			ic.Anchor = anch
		}
	} else {
		// try to get TPM2 family indicator (should be 2.0) to test if this is a TPM2
		_, err := tcg.GetTPM2FamilyIndicator(conn)
		if err != nil {
			_, err := tpm1.GetCapVersionVal(conn)
			if err != nil {
				return errors.New("TPM1.2 is not supported")
			}
		}
		ic.Anchor = tcg.NewTCGAnchor(conn)
	}

	// We need all memory the TPM can offer
	ic.Anchor.FlushAllHandles()

	return nil
}

func (ic *ImmuneConnection) Attest(token string) error {
	ctx := context.Background()
	if err := loadFreshState(stateDir, ic); err != nil {
		return err
	}
	if err := openAndClearTPM(tpmPath, ic); err != nil {
		return err
	}
	if err := attestation.Enroll(ctx, &ic.Client, token, ic.EndorsementAuth, "Server", ic.Anchor, ic.State); err != nil {
		return err
	}
	if err := ic.State.Store(path.Join(stateDir, "keys")); err != nil {
		return err
	}
	_, err := attestation.Attest(ctx, &ic.Client, ic.EndorsementAuth, ic.Anchor, ic.State)
	if err != nil {
		return err
	}
	return nil
}
