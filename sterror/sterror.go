// Package strror provides the error handling used in stboot.
// The core part is the constructor function E().
package sterror

import (
	"errors"
)

// Op describes an operation, usually as the name of the method.
type Op string

// Scope defines the scope of error this is, mostly to identify
// the subsystem where the error occured.
type Scope string

// Scopes of errors.
const (
	Host    Scope = "Host"
	Network Scope = "Network"
	Opts    Scope = "Opts"
	Ospkg   Scope = "OS package"
	Stlog   Scope = "Stlog"
	Trust   Scope = "Signature verification"
)

// Error provides strctured and detailed context. However, some fields
// may be left unset.
//
// An Error value should be created using the E() function.
type Error struct {
	// Op is operation beeing executed while the error occurde.
	Op Op
	// Scope is the subsytem of stboot causing the error.
	Scope Scope
	// Err is the underlying wrapped error.
	Err error
	// Info provides further context to the error or holds the string
	// value of the triggering error if it is not wrapped.
	Info string
}

const (
	colon   string = ": "
	hyphen  string = " - "
	newline string = "\n"
)

// Error implements the error interface.
func (e Error) Error() string {
	var composedErrorString string

	switch {
	case e.Op != "" && e.Info != "":
		composedErrorString += colon + string(e.Op) + hyphen + string(e.Info)
	case e.Op != "":
		composedErrorString += colon + string(e.Op)
	case e.Info != "":
		composedErrorString += colon + string(e.Info)
	default:
	}

	if e.Err != nil {
		composedErrorString += newline + e.Err.Error()
	}

	return composedErrorString
}

// E returns an Error constructed from its arguments.
// There should be at least one argument, or E returns an unspecifed error.
// The type of each argument determines its meaning.
// If more than one argument of a given type is presented,
// only the last one is recorded.
//
// The types are:
//		sterror.OP
//				The performed operation.
// 		sterror.Scope
//				The subsystem where the error occured.
// 		error
// 				The underlying error if it should be wrapped.
//		string
// 				Treated as error message of an error that should
// 				not be wrapped or as additional information to the
// 				provided error.
//
// Further types will be ignored.
func E(args ...interface{}) Error {
	if len(args) == 0 {
		return Error{Info: "unspecified"}
	}

	var err = Error{}

	for _, arg := range args {
		switch arg := arg.(type) {
		case Op:
			err.Op = arg
		case Scope:
			err.Scope = arg
		case error:
			err.Err = arg
		case string:
			err.Info = arg
		default:
		}
	}

	return err
}

// Equal returns true if the two provided Errors are equal.
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
