package opts

import (
	"crypto/x509"
	"fmt"
)

// OptsVersion is the Version of Opts. It can be used for validation.
const OptsVersion int = 0

// Loader wraps the Load function.
// Load fills particular fields of Opts depending on its source.
type Loader interface {
	Load(*Opts) error
}

// Opts controls the operation of stboot.
type Opts struct {
	Version int
	Security
	HostCfg
	SigningRoot *x509.Certificate
	HTTPSRoots  []*x509.Certificate
}

// NewOpts return a new Opts initialized by the provided Loaders.
func NewOpts(loaders ...Loader) (*Opts, error) {
	opts := &Opts{Version: OptsVersion}
	for _, l := range loaders {
		if err := l.Load(opts); err != nil {
			return nil, fmt.Errorf("new opts: %w", err)
		}
	}

	return opts, nil
}
