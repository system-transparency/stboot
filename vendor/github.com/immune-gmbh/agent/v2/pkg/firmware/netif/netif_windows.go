package netif

import (
	"strings"

	"github.com/StackExchange/wmi"
)

const (
	wmiQuery               = "SELECT AdapterType,MACAddress,PNPDeviceId FROM Win32_NetworkAdapter"
	wmiAdapterTypeEthernet = "Ethernet 802.3"
	pnpClassSoftwareDevice = "SWD\\"
	pnpClassVirtNetDevice  = "ROOT\\NET"
)

type wmiAdapterEntity struct {
	AdapterType *string
	MACAddress  *string
	PNPDeviceId *string
}

func readMACAddresses() ([]string, error) {
	var results []wmiAdapterEntity
	if err := wmi.Query(wmiQuery, &results); err != nil {
		return nil, err
	}

	ret := make([]string, 0)
	for _, val := range results {
		if *val.AdapterType != wmiAdapterTypeEthernet {
			continue
		}

		// filter out software devices
		if strings.HasPrefix(*val.PNPDeviceId, pnpClassSoftwareDevice) ||
			strings.HasPrefix(*val.PNPDeviceId, pnpClassVirtNetDevice) {
			continue
		}

		if *val.MACAddress == "" {
			continue
		}

		ret = append(ret, *val.MACAddress)
	}

	return ret, nil
}
