package heci

type Hecihdr [4]byte

func (hh Hecihdr) MEAddr() uint8 {
	return hh[0]
}

func (hh *Hecihdr) SetMEAddr(v uint8) {
	hh[0] = v
}

func (hh Hecihdr) HostAddr() uint8 {
	return hh[1]
}

func (hh *Hecihdr) SetHostAddr(v uint8) {
	hh[1] = v
}

func (hh Hecihdr) Length() uint16 {
	return uint16(hh[2] | (hh[3] & 1))
}

func (hh *Hecihdr) SetLength(v uint16) {
	hh[2] = uint8(v & 0xff)
	hh[3] = (hh[3] & (0xfe)) | uint8(((v >> 8) & 1))
}

func (hh Hecihdr) MsgComplete() bool {
	return (hh[3]>>7)&1 != 0
}

func (hh *Hecihdr) SetMsgComplete(v bool) {
	var vi uint8
	if v {
		vi = 0x80
	}
	hh[3] = (hh[3] & (0x7F)) | vi
}
