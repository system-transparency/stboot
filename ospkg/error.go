package ospkg

// Error reports problems with OS packages.
type Error string

// Error implements error interface.
func (e Error) Error() string {
	return string(e)
}
