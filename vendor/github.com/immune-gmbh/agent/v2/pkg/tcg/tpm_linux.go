package tcg

import (
	"io"

	"github.com/google/go-tpm/tpmutil"
)

const DefaultTPMDevice = "/dev/tpm0"

func openTPM(tpmPath string) (io.ReadWriteCloser, error) {
	conn, err := tpmutil.OpenTPM(tpmPath)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
