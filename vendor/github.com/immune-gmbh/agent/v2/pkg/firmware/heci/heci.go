package heci

import (
	"errors"
	"fmt"

	"github.com/immune-gmbh/agent/v2/pkg/api"
	"github.com/immune-gmbh/agent/v2/pkg/firmware/common"
	"github.com/sirupsen/logrus"
)

// ME variant register values
const (
	skuIgnition = iota
	skuTXE
	skuMEConsumer
	skuMEBusiness
	_
	skuLight
	skuSPS
)

// HECI PCI config space registers
const (
	heci1MMIOOffset = 0x10
	heci1Options    = 0x04
)

type MECommandIntf interface {
	runCommand(command []byte) ([]byte, error)
	close() error
}

func reportMEClientCommands(command *api.MEClientCommands) (err error) {
	m, err := openMEClientInterface(command)
	if err != nil {
		return
	}
	defer m.close()

	for i, v := range command.Commands {
		var buf []byte
		buf, err = m.runCommand(v.Command)
		if err != nil {
			err = fmt.Errorf("error running cmd: %w", err)
			break
		}
		command.Commands[i].Response = buf
	}

	return
}

func ReportMECommands(commands []api.MEClientCommands) (err error) {
	logrus.Traceln("ReportMECommands()")

	allFailed := true
	for i := range commands {
		v := &commands[i]
		err = reportMEClientCommands(v)
		allFailed = allFailed && err != nil
		if err != nil {
			v.Error = common.ServeApiError(common.MapFSErrors(err))
			logrus.Debugf("heci.ReportMECommands(): %s", err.Error())
		}
	}
	if allFailed && len(commands) > 0 {
		logrus.Warnf("Failed to contact Intel ME")
		return
	}

	err = nil
	return
}

// openMEClientInterface tries to open a HECI device or raw messaging via memory mapping as fallback
// Inside cmd parameter, GUID is required for the connection via device, the client address is required for raw messaging.
// If any is not supplied, then there will be no connection via that method.
// Address is expected to be < 0 if it is not present.
func openMEClientInterface(cmd *api.MEClientCommands) (MECommandIntf, error) {
	if cmd.GUID != nil {
		m, err := openMEI("", *cmd.GUID)
		if err != nil {
			return nil, err
		}
		return m, nil
	}

	if cmd.Address != nil {
		m, err := openHECI1(*cmd.Address)
		if err != nil {
			return nil, err
		}
		return m, nil
	}

	return nil, errors.New("neither GUID nor Address specified")
}
