package cpuid

func low(arg1, arg2 uint32) (eax, ebx, ecx, edx uint32)

func readCPUID(arg1, arg2 uint32) (eax, ebx, ecx, edx uint32) {
	eax, ebx, ecx, edx = low(arg1, arg2)
	return
}
