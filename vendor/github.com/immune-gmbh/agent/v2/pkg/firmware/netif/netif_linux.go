package netif

import (
	"net"
)

func readMACAddresses() ([]string, error) {
	ifas, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	macAddrs := []string{}
	for _, ifa := range ifas {
		f := ifa.Flags
		s := ifa.HardwareAddr.String()
		if f&net.FlagLoopback != 0 {
			continue
		}
		if f&net.FlagPointToPoint != 0 {
			continue
		}
		if s == "" {
			continue
		}
		macAddrs = append(macAddrs, s)
	}
	return macAddrs, nil
}
