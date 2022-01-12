package opts

const OptsVersion int = 0

type InvalidError string

func (e InvalidError) Error() string {
	return string(e)
}

type validator func(*Opts) error

// Loader wraps the Load funktion.
// Load fills particular fields of Opts depending on its source.
type Loader interface {
	Load(*Opts) error
}

// Opts controlls the operation of stboot
type Opts struct {
	Version int
	Security
	HostCfg
}

// NewOpts return a new Opts initialized by the provided Loaders
func NewOpts(loaders ...Loader) (*Opts, error) {
	opts := &Opts{Version: 0}
	for _, l := range loaders {
		if err := l.Load(opts); err != nil {
			return nil, err
		}
	}
	return opts, nil
}
