package host

// Error reports problems regarding the host environment and hardware.
type Error string

// Error implements error interface.
func (e Error) Error() string {
	return string(e)
}
