package osinfo

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/windows/registry"
)

func readOSReleasePrettyName() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return runtime.GOOS, fmt.Errorf(`can't read open reg key 'SOFTWARE\Microsoft\Windows NT\CurrentVersion': %w`, err)
	}
	defer k.Close()

	pn, _, err := k.GetStringValue("ProductName")
	if err != nil {
		return runtime.GOOS, fmt.Errorf("can't read reg val 'ProductName': %w", err)
	}

	maj, _, err := k.GetIntegerValue("CurrentMajorVersionNumber")
	if err != nil {
		return runtime.GOOS, fmt.Errorf("can't read reg val 'CurrentMajorVersionNumber': %w", err)
	}

	min, _, err := k.GetIntegerValue("CurrentMinorVersionNumber")
	if err != nil {
		return runtime.GOOS, fmt.Errorf("can't read reg val 'CurrentMinorVersionNumber': %w", err)
	}

	rid, _, err := k.GetStringValue("ReleaseId")
	if err != nil {
		return runtime.GOOS, fmt.Errorf("can't read reg val 'ReleaseId': %w", err)
	}

	return fmt.Sprintf("%s %v.%v id %s", pn, maj, min, rid), nil
}
