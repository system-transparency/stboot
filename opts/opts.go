package opts

import (
	"fmt"
)

const OptsVersion int = 0

type InvalidError string

func (e InvalidError) Error() string {
	return string(e)
}

type ParseError struct {
	wrongType interface{}
	key       string
	err       error
}

func (p *ParseError) Error() string {
	if p.wrongType != nil {
		return fmt.Sprintf("value of JSON key %q has wrong type %T", p.key, p.wrongType)
	}
	return fmt.Sprintf("parsing value of JSON key %q failed: %v", p.key, p.err)
}

type validator func(*Opts) error

type Opts struct {
	Version int
	SecurityCfg
	HostCfg
}
