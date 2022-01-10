package state

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"

	"github.com/immune-gmbh/agent/v2/pkg/api"
)

const (
	ClientStateTypeV2 = "client-state/2"
	ClientStateTypeV3 = "client-state/3"
	ClientStateType   = ClientStateTypeV3

	// DefaultVendorSubdir is the name of the subdirectory we create in various common locations (f.e. /var, /etc) to store our data
	// note: if you change this name, you also have to modify the reference in the windows installer wix main xml file
	DefaultVendorSubdir string = "immune-guard"
)

var (
	ErrNotExist = errors.New("non existent")
	ErrInvalid  = errors.New("invalid data")
	ErrNoPerm   = errors.New("no permissions")
)

// Current "head" state struct definition
type State StateV3
type DeviceKey DeviceKeyV3

func (s *State) EnsureFresh(cl *api.Client) error {
	return (*StateV3)(s).EnsureFresh(cl)
}

func LoadState(dir string) (*State, error) {
	logrus.Traceln("load on-disk state")
	keysPath := path.Join(dir, "keys")
	if _, err := os.Stat(keysPath); os.IsNotExist(err) {
		return nil, ErrNotExist
	} else if os.IsPermission(err) {
		return nil, ErrNoPerm
	} else if err != nil {
		return nil, err
	}

	file, err := ioutil.ReadFile(keysPath)
	if err != nil {
		return nil, err
	}

	return migrateState(file)
}

func migrateState(raw []byte) (*State, error) {
	var dict map[string]interface{}

	if err := json.Unmarshal(raw, &dict); err != nil {
		log.Debugf("State file is not a JSON dict: %s", err)
		return nil, ErrInvalid
	}

	if val, ok := dict["type"]; ok {
		if str, ok := val.(string); ok {
			switch str {
			case ClientStateTypeV2:
				log.Debugf("Migrating state from v2 to v3")
				if st3, err := migrateStateV2(raw); err != nil {
					return nil, err
				} else {
					st := State(*st3)
					return &st, err
				}
			case ClientStateTypeV3:
				var st State
				err := json.Unmarshal(raw, &st)
				return &st, err
			default:
				log.Debugf("Unknown state type '%s'", str)
				return nil, ErrInvalid
			}
		} else {
			log.Debugf("State file type is not a string")
		}
	} else {
		log.Debugf("State file has no type")
	}

	return nil, ErrInvalid
}

func (st *State) Store(keysPath string) error {
	str, err := json.Marshal(*st)
	if err != nil {
		return err
	}

	err = os.MkdirAll(filepath.Dir(keysPath), 0755)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(keysPath, str, 0600)
}

func NewState() *State {
	return (*State)(newStateV3())
}

func (s *State) IsEnrolled() bool {
	return (*StateV3)(s).IsEnrolled()
}
