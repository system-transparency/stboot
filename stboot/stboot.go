package stboot

const OptsVersion int = 1

type InvalidOptsError string

func (e InvalidOptsError) Error() string {
	return string(e)
}

type validator func(*Opts) error

type Opts struct {
	Version int
	securityCfg
	hostCfg
}

func (o *Opts) validate(v ...validator) error {
	for _, f := range v {
		if err := f(o); err != nil {
			return err
		}
	}
	return nil
}
