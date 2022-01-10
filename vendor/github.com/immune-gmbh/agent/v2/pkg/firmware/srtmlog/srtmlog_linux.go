package srtmlog

import (
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path"

	"github.com/immune-gmbh/agent/v2/pkg/firmware/common"
)

func readTPM2EventLog(conn io.ReadWriteCloser) ([]byte, error) {
	f, ok := conn.(*os.File)
	if ok {
		p := path.Join("/sys/kernel/security/", path.Base(f.Name()), "/binary_bios_measurements")
		return ioutil.ReadFile(p)
	}

	return nil, common.ErrorNoResponse(errors.New("no event log found"))
}
