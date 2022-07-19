// Package sterror provides the error handling used in stboot.
// The core part is the constructor function E().
package sterror

import (
	"bytes"
	"errors"
)

// Op describes an operation, usually as the name of the method.
type Op string

// Scope defines the scope of error this is, mostly to identify
// the subsystem where the error occurred.
// Each subsystem should define exactly one constant as its Scope.
type Scope string

// Error provides structured and detailed context. However, some fields
// may be left unset.
//
// An Error value should be created using the E() function.
type Error struct {
	// Op is operation being executed while the error occurde.
	Op Op
	// Scope is the subsytem of stboot causing the error.
	Scope Scope
	// Err is the underlying wrapped error.
	Err error
	// Info provides further context to the error or holds the string
	// value of the triggering error if it is not wrapped.
	Info string
}

// General errors.
var (
	ErrSigning         = errors.New("signature creation failed")
	ErrVerification    = errors.New("signature verification failed")
	ErrInvalidKey      = errors.New("invalid key type")
	ErrParse           = errors.New("failed to parse")
	ErrSerialize       = errors.New("failed to serialize")
	ErrValidate        = errors.New("failed to validate")
	ErrSign            = errors.New("failed to sign")
	ErrWriteToFile     = errors.New("failed to write to file")
	ErrLogger          = errors.New("initializing logger failed")
	ErrFailedToUnzip   = errors.New("failed to unzip")
	ErrFailedToZip     = errors.New("failed to zip")
	ErrDataNotHashable = errors.New("data not hashable")
	ErrGenerateData    = errors.New("failed to generate data")
	ErrMissingData     = errors.New("missing data")
	ErrOverwriteData   = errors.New("failed to overwrite data")
)

// General additional error information.
const (
	InfoFailedToWriteTo  = "failed to write to %v"
	InfoFailedToReadFrom = "failed to read from %v"
	InfoInvalidVersion   = "invalid version: %d, expected %d"
	InfoInvalidPkgURL    = "invalid package url"
	InfoMissingScheme    = "missing scheme"
	InfoInvalidPath      = "missing %v path"
	InfoNotADir          = "%v is not a directory"
	InfoInvalidKey       = "got key of type %T, expected %v"
	InfoLengthOfZero     = "data %v has length of zero"
	InfoNotVerified      = "data is not verified"
)

const (
	colon   string = ": "
	newline string = "\n"
)

// pad appends str to the buffer if it already contains data.
func pad(buf *bytes.Buffer, str string) {
	if buf.Len() == 0 {
		return
	}

	buf.WriteString(str)
}

// Error implements the error interface.
func (e Error) Error() string {
	buf := &bytes.Buffer{}

	if e.Scope != "" {
		buf.WriteString(string(e.Scope))
	}

	if e.Op != "" {
		pad(buf, colon)
		buf.WriteString(string(e.Op))
	}

	if e.Err != nil {
		pad(buf, newline)
		buf.WriteString(e.Err.Error())
	}

	if e.Info != "" {
		pad(buf, newline)
		buf.WriteString(e.Info)
	}

	return buf.String()
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
//				The subsystem where the error occurred.
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
		fillError(&err, arg)
	}

	if err.Scope == "" && err.Info == "" && err.Op == "" && err.Err == nil {
		return Error{Info: "unspecified"}
	}

	return err
}

// fillError fills the passed Error with any valid argument specified in E.
func fillError(err *Error, arg interface{}) {
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
