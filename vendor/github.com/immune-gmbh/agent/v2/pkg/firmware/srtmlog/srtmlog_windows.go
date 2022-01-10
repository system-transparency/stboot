package srtmlog

import (
	"io"

	"github.com/google/go-tpm/tpmutil/tbs"
)

func readTPM2EventLog(conn io.ReadWriteCloser) ([]byte, error) {
	context, err := tbs.CreateContext(tbs.TPMVersion20, tbs.IncludeTPM20|tbs.IncludeTPM12)
	if err != nil {
		return nil, err
	}
	defer context.Close()

	// Run command first with nil buffer to get required buffer size.
	logLen, err := context.GetTCGLog(nil)
	if err != nil {
		return nil, err
	}
	logBuffer := make([]byte, logLen)
	if _, err = context.GetTCGLog(logBuffer); err != nil {
		return nil, err
	}
	return logBuffer, nil
}
