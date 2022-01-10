package osinfo

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
)

const (
	etcOSRelease     = "/etc/os-release"
	prettyNamePrefix = "PRETTY_NAME=\""
	prettyNameSplit  = "\""
)

func readOSReleasePrettyName() (string, error) {
	f, err := os.OpenFile(etcOSRelease, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return "", fmt.Errorf("error opening %v: %w", etcOSRelease, err)
	}
	defer f.Close()

	rd := bufio.NewReader(f)
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err
		}

		if strings.HasPrefix(line, prettyNamePrefix) {
			tmp := strings.Split(line, prettyNameSplit)
			if len(tmp) > 1 {
				return tmp[1], nil
			} else {
				return "", fmt.Errorf("unexpected format in %s", etcOSRelease)
			}
		}
	}

	return runtime.GOOS, nil
}
