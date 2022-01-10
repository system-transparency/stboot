package state

import (
	"context"
	"encoding/json"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/immune-gmbh/agent/v2/pkg/api"
)

type RootKeyV3 struct {
	Auth string   `json:"auth"`
	Name api.Name `json:"name"`
}

type DeviceKeyV3 struct {
	Public     api.PublicKey `json:"public"`
	Private    api.Buffer    `json:"private"`
	Auth       string        `json:"auth"`
	Credential string        `json:"credential"`
}

type StubState struct {
	Type           string
	RootKey        api.Buffer `json:"root"`
	EndorsementKey api.Buffer `json:"ek"`
}

type StateV3 struct {
	Ty string `json:"type"`

	// v3.1 (deprecated)
	StubSeed api.Buffer `json:"stub-seed,omitempty"`
	// v3.2
	StubState *StubState `json:"stub-state,omitempty"`

	// /v2/enroll
	Keys                   map[string]DeviceKeyV3 `json:"keys"`
	Root                   RootKeyV3              `json:"root"`
	EndorsementKey         api.PublicKey          `json:"ek"`
	EndorsementCertificate *api.Certificate       `json:"ek-certificate"`

	// /v2/configuration
	LastUpdate time.Time         `json:"last_update,string"`
	Config     api.Configuration `json:"config"`
}

func (s *StateV3) EnsureFresh(cl *api.Client) error {
	ctx := context.Background()
	now := time.Now()
	cfg, err := cl.Configuration(ctx, &s.LastUpdate)
	if err != nil {
		return err
	}

	// if cfg is nil then there is no new config and we should use a cached version
	if cfg != nil {
		s.Config = *cfg
		s.LastUpdate = now
	}

	return nil
}

func (s *StateV3) IsEnrolled() bool {
	return s.Root != RootKeyV3{}
}

func newStateV3() *StateV3 {
	return &StateV3{
		Ty: ClientStateTypeV3,
	}
}

func migrateStateV2(raw []byte) (*StateV3, error) {
	var st2 StateV2

	if err := json.Unmarshal(raw, &st2); err != nil {
		log.Debugf("State file corrupted: %s", err)
		return nil, ErrInvalid
	}

	st3 := StateV3{
		Ty: ClientStateTypeV3,
		Keys: map[string]DeviceKeyV3{
			"aik": {
				Public:     st2.QuoteKey.Public,
				Private:    st2.QuoteKey.Private,
				Auth:       st2.QuoteKey.Auth,
				Credential: st2.QuoteKey.Certificate,
			},
		},
		Root: RootKeyV3{
			Auth: st2.RootKeyAuth,
		},
		EndorsementKey:         st2.EndorsementKey,
		EndorsementCertificate: st2.EndorsementCertificate,
		LastUpdate:             time.Time{},
		Config:                 api.Configuration{},
	}

	return &st3, nil
}
