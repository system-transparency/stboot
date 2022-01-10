package acpi

import (
	"io"
	"io/ioutil"
	"os"
	"path"

	"github.com/immune-gmbh/agent/v2/pkg/firmware/common"
	log "github.com/sirupsen/logrus"
)

var (
	sysfsDir = "/sys/firmware/acpi/tables"
)

func readACPITables() (map[string][]byte, error) {
	files, err := ioutil.ReadDir(sysfsDir)
	if err != nil {
		return nil, err
	}

	tables := make(map[string][]byte)
	completeFailure := true
	for _, f := range files {
		if f.IsDir() {
			continue
		}

		path := path.Join(sysfsDir, f.Name())
		buf, err := readACPITableFile(path)
		if err != nil {
			log.Debugf("error getting acpi table '%s': %s", f.Name(), err.Error())
			continue
		}
		completeFailure = false
		tables[f.Name()] = buf
	}

	if completeFailure {
		return nil, common.MapFSErrors(err)
	}

	return tables, nil
}

func readACPITableFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return buf, nil
}
