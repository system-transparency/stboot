package ospkg

import "testing"

var (
	testOSManifestDataForPackage = &OSManifest{
		Version:       1,
		Label:         "System Tarnsparency OS Package dummy_kernel.bin",
		KernelPath:    "../testdata/kernel/dummy_kernel.bin",
		InitramfsPath: "../testdata/initramfs/dummy_initramfs.bin",
		Cmdline:       "",
		TbootPath:     "",
		TbootArgs:     "",
		ACMPaths:      []string{"../testdata/acms/dummy_acm.bin"},
	}
)

func TestCreateOSManifest(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   *OSManifest
		wantErr error
	}{
		{
			name:  "Create OSManifest",
			input: testOSManifestDataForPackage,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CreateOSPackage("", tt.input)
			if err != nil {
				t.Errorf("creating OSPackage failed: %v", err)
			}

		})
	}
}
