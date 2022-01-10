package util

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"
)

const procModules = "/proc/modules"

// WinAddTokenPrivilege dummy implementation for other OSes
func WinAddTokenPrivilege(name string) error {
	return nil
}

func IsKernelModuleLoaded(name string) (bool, error) {
	f, err := os.OpenFile(procModules, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return false, fmt.Errorf("error opening %v: %w", procModules, err)
	}
	defer f.Close()

	rd := bufio.NewReader(f)
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return false, err
		}

		if strings.HasPrefix(line, name) {
			return true, nil
		}
	}

	return false, nil
}

func IsRoot() (ret bool, err error) {
	currentUser, err := user.Current()
	ret = currentUser.Username == "root"
	return
}
