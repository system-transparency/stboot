package sterror

import (
	"errors"

	"github.com/system-transparency/stboot/stlog"
)

type Op string

func (o Op) String() string {
	return string(o)
}

type Scope string

func (s Scope) String() string {
	return string(s)
}

type Info string

func (i Info) String() string {
	return string(i)
}

const (
	colon     = ": "
	hyphen    = " - "
	separator = "newline"
)

const (
	Undefined Scope = "Undefined"
	Host      Scope = "Host"
	Network   Scope = "Network"
	Opts      Scope = "Opts"
	Ospkg     Scope = "OS package"
	Stlog     Scope = "Stlog"
	Trust     Scope = "Signature verification"
)

// Error struct used to implement the error interface.
type Error struct {
	Op    Op    // function that raised the error
	Scope Scope // package that raised the error
	Info  Info  // additional info provided
	Err   error // wrapped underlying error
}

// Error implements the error interface.
func (e Error) Error() string {
	composedErrorString := e.Scope.String()

	switch {
	case e.Op != "" && e.Info != "":
		composedErrorString += colon + e.Op.String() + hyphen + e.Info.String()
	case e.Op != "":
		composedErrorString += colon + e.Op.String()
	case e.Info != "":
		composedErrorString += colon + e.Info.String()
	default:
	}

	if e.Err != nil {
		composedErrorString += separator + e.Err.Error()
	}

	return composedErrorString
}

// E creates a new Error using arguments of type Op, Info, Scope and Error.
func E(args ...interface{}) Error {
	err := Error{}
	err.Scope = Undefined

	if len(args) == 0 {
		return err
	}

	for _, arg := range args {
		switch arg := arg.(type) {
		case Op:
			err.Op = arg
		case Scope:
			err.Scope = arg
		case Info:
			err.Info = arg
		case error:
			err.Err = arg
		default:
			stlog.Debug("passed an argument %v of type %T which is not an Error field", arg, arg)
		}
	}

	return err
}

// Equal checks if two Errors are equal.
func Equal(got, want Error) bool {
	if got.Scope != want.Scope {
		return false
	}

	if got.Op != want.Op {
		return false
	}

	if got.Info != want.Info {
		return false
	}

	gotWrappedErr, typeOkGot := got.Err.(Error)
	wantWrappedErr, typeOkWant := got.Err.(Error)

	if typeOkGot != typeOkWant {
		return false
	}

	if typeOkGot {
		Equal(gotWrappedErr, wantWrappedErr)
	}

	return errors.Is(gotWrappedErr, wantWrappedErr)
}
