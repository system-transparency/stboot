package biosflash

import (
	"github.com/immune-gmbh/agent/v2/pkg/firmware/immunecpu"
)

func readBiosFlashMMap() (outBuf []byte, err error) {
	return immunecpu.ReadBiosFlashMMap()
}
