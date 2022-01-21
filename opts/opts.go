package opts

// OptsVersion is the Version of Opts. It can be used for validation
const OptsVersion int = 0

// InvalidError reports invalid data of Opts
type InvalidError string

// Error implements error interface
func (e InvalidError) Error() string {
	return string(e)
}

type validator func(*Opts) error

// Loader wraps the Load function.
// Load fills particular fields of Opts depending on its source.
type Loader interface {
	Load(*Opts) error
}

// Opts controls the operation of stboot
type Opts struct {
	Version int
	Security
	HostCfg
}

// NewOpts return a new Opts initialized by the provided Loaders
func NewOpts(loaders ...Loader) (*Opts, error) {
	opts := &Opts{Version: OptsVersion}
	for _, l := range loaders {
		if err := l.Load(opts); err != nil {
			return nil, err
		}
	}
	return opts, nil
}
