package tcg

import (
	"io"

	"github.com/google/go-tpm/tpmutil"
)

const DefaultTPMDevice = "none"

func openTPM(tpmPath string) (io.ReadWriteCloser, error) {
	conn, err := tpmutil.OpenTPM()
	if err != nil {
		return nil, err
	}
	return conn, nil
}
