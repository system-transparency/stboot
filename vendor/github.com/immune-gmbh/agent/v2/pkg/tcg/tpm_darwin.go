package tcg

import (
	"fmt"
	"io"
)

const DefaultTPMDevice = "none"

func openTPM(tpmPath string) (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("Not implemented yet")
}
