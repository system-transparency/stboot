package opts

// Error reports problems while lodasing and validating configuration data.
type Error string

// Error implements error interface.
func (e Error) Error() string {
	return string(e)
}

// ErrNonNil is used for testing.
const ErrNonNil = Error("")
