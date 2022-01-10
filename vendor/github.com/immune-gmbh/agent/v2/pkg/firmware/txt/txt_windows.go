package txt

import "github.com/immune-gmbh/agent/v2/pkg/firmware/immunecpu"

func readTXTPublicSpace() ([]byte, error) {
	return immunecpu.ReadTxtPublicSpace()
}
