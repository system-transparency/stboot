// +build !amd64

package cpuid

func readCPUID(arg1, arg2 uint32) (uint32, uint32, uint32, uint32) {
	return 0, 0, 0, 0
}
