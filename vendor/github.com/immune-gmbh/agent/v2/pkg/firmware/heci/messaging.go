package heci

import (
	"encoding/binary"
	"fmt"
	"time"
)

func (m *heci) recvMsg() ([]byte, error) {
	// check if ME is ready and wait to read msg header
	retries := heciRetries
	for {
		if retries < 0 {
			return nil, fmt.Errorf("HECI RcvMsg header timeout")
		}
		retries--
		if err := m.readCtrl(meiCtrlOffset); err != nil {
			return nil, err
		}
		// reset and return only return when reset had errors
		if !m.mei.IsReady() {
			err := m.reset()
			if err != nil {
				return nil, fmt.Errorf("mei not ready: %w", err)
			}
			if err := m.readCtrl(meiCtrlOffset); err != nil {
				return nil, err
			}
		}
		filledSlots := uint8(m.mei.Writer - m.mei.Reader)
		if filledSlots > m.mei.BufferSize {
			err := m.reset()
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("HECI communication error in RecvMsg")
		} else if filledSlots == 0 {
			time.Sleep(time.Millisecond * heciTimeoutMs)
			continue
		} else {
			break
		}
	}

	// parse header to determine message length
	var hdr Hecihdr
	header, err := m.readAt(meiCircularReadWindow)
	if err != nil {
		return nil, err
	}
	var data []byte
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, header)
	data = append(data, tmp...)
	copy(hdr[:], tmp)
	rounds := uint8((hdr.Length() + 3) / 4)

	// read message slot by slot
	retries = heciRetries
	for {
		if retries < 0 {
			return nil, fmt.Errorf("HECI RcvMsg body timeout")
		}
		retries--
		if err := m.readCtrl(meiCtrlOffset); err != nil {
			return nil, err
		}
		if !m.mei.IsReady() {
			err := m.reset()
			if err != nil {
				return nil, fmt.Errorf("mei not ready: %w", err)
			}
			return nil, fmt.Errorf("mei not ready")
		}

		// on buffer overflow we must reset and return (no more messages are expected after reset)
		filledSlots := uint8(m.mei.Writer - m.mei.Reader)
		if filledSlots > m.mei.BufferSize {
			err := m.reset()
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("HECI communication error in RecvMsg")
		} else if filledSlots == 0 {
			time.Sleep(time.Millisecond * heciTimeoutMs)
			continue
		} else {
			retries = heciRetries
			rounds--
			raw, err := m.readAt(meiCircularReadWindow)
			tmp := make([]byte, 4)
			binary.LittleEndian.PutUint32(tmp, raw)
			if err != nil {
				return nil, err
			}
			data = append(data, tmp...)
			if rounds == 0 {
				break
			}
		}
	}

	// notify ME message was read
	m.host.SetClear()
	m.host.SetInterrupt()
	if err := m.writeCtrl(hostCtrlOffset); err != nil {
		return nil, err
	}
	return data, nil
}

func (m *heci) sendMsg(data []byte) error {
	retries := heciRetries
restart:
	if err := m.readCtrl(meiCtrlOffset); err != nil {
		return err
	}
	if err := m.readCtrl(hostCtrlOffset); err != nil {
		return err
	}
	if !m.host.IsReady() || !m.mei.IsReady() {
		err := m.reset()
		if err != nil {
			return fmt.Errorf("mei or host side not ready: %w", err)
		}
	}
	for {
		if retries < 0 {
			return fmt.Errorf("HECI SendMsg timeout")
		}
		retries--
		if err := m.readCtrl(hostCtrlOffset); err != nil {
			return err
		}
		filledSlots := uint8(m.host.Writer - m.host.Reader)
		emptySlots := uint8(m.host.BufferSize - filledSlots)
		if filledSlots > m.host.BufferSize {
			err := m.reset()
			if err != nil {
				return err
			}
			continue
		} else if ((len(data) + 3) / 4) > int(emptySlots) {
			time.Sleep(time.Millisecond * heciTimeoutMs)
			// it is required to check readyness again when there are not enough slots
			goto restart
		} else {
			break
		}
	}
	rounds := uint8((len(data) + 3) / 4)
	var i uint8
	for i = 0; i < rounds; i++ {
		var tmp [4]byte
		copy(tmp[:], data[i*4:])
		val := binary.LittleEndian.Uint32(tmp[:])
		if err := m.writeAt32(val, hostCircularWriteWindow); err != nil {
			return err
		}
	}
	m.host.SetInterrupt()
	if err := m.writeCtrl(hostCtrlOffset); err != nil {
		return err
	}
	if err := m.readCtrl(meiCtrlOffset); err != nil {
		return err
	}
	if !m.mei.IsReady() {
		return fmt.Errorf("send failed")
	}
	return nil
}

func (u *heci) runCommand(command []byte) ([]byte, error) {
	if err := u.sendMsg(command); err != nil {
		return nil, err
	}
	return u.recvMsg()
}
