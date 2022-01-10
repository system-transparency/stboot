package tcg

import (
	"io"

	"github.com/google/go-tpm-tools/simulator"
)

type Simulator struct {
	simulator *simulator.Simulator
}

func (s *Simulator) Read(p []byte) (n int, err error) {
	return s.simulator.Read(p)
}

func (s *Simulator) Write(p []byte) (n int, err error) {
	return s.simulator.Write(p)
}

func (s Simulator) Close() error {
	return s.simulator.Close()
}

func NewSimulator() (io.ReadWriteCloser, error) {
	simulator, err := simulator.Get()
	if err != nil {
		return nil, err
	}
	return &Simulator{simulator: simulator}, nil
}
