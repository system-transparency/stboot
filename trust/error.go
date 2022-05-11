package trust

// Error reports problems regarding signature verification.
type Error string

// Error implements error interface.
func (e Error) Error() string {
	return string(e)
}

const (
	ErrRSAPSSSigner  = Error("RSAPSSSigner error")
	ErrED25519Signer = Error("ED25519Signer error")
	ErrSign          = Error("sign")
	ErrVrfy 	     = Error("verify")
	SignZeroLength = "signature has zero length"
	HashZeroLength = "hash has zero length"
	InvalidKeyType = "invalid key type"
	VerificationFailed = "verification failed"
	InputDataZeroLength = "input data has zero length"
)
