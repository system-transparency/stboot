package testing

import (
	"testing"

	"github.com/google/go-tpm-tools/simulator"
)

func GetTpmSimulator(t *testing.T) *simulator.Simulator {
	t.Helper()
	simulator, err := simulator.Get()
	if err != nil {
		t.Fatal(err)
	}
	return simulator
}
