package uefivars

import (
	"fmt"
	"os"
	"path"
)

var efivars = "/sys/firmware/efi/efivars"

func readUEFIVariable(name, guid string) ([]byte, error) {

	buf, err := os.ReadFile(path.Join(efivars, fmt.Sprintf("%s-%s", name, guid)))
	if err != nil {
		return nil, err
	}

	// strip first 32 bits because they are attributes not variable data
	if len(buf) > 3 {
		buf = buf[4:]
	}

	return buf, nil
}
