package attestation

import (
	"fmt"

	"github.com/system-transparency/stboot/config"
)

type Attestor interface {
	Attest(string) error
}

func NewAttestor(sc *config.SecurityCfg) (Attestor, error) {
	switch sc.AttestationService {
	case config.Immune:
		return &ImmuneConnection{}, nil
	}
	return nil, fmt.Errorf("no attestor found")
}
