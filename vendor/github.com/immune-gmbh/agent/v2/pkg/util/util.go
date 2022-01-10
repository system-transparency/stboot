package util

func Uint32ToStr(in uint32) string {
	return string([]uint8{uint8(in & 0xFF), uint8((in >> 8) & 0xFF), uint8((in >> 16) & 0xFF), uint8((in >> 24) & 0xFF)})
}
