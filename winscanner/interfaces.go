package winscanner

import (
	"net"
	"vuln/structs"

	"github.com/jackpal/gateway"
)

func ListNetworkInterfaces() ([]structs.Interfaces, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var interfaceList []structs.Interfaces
	for _, iface := range interfaces {
		var ipv4List []string
		var ipv6List []string
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue // Skip non-IP addresses
			}

			// Check if the IP address is IPv4
			if ipNet.IP.To4() != nil {
				ipv4List = append(ipv4List, ipNet.IP.String())
			} else {
				ipv6List = append(ipv6List, ipNet.IP.String())
			}
		}

		defaultIP := ""
		ipGW, dfgw, _ := getDefaultGateway()
		for _, ipString := range ipv4List {
			if ipString == ipGW {
				defaultIP = dfgw
				break
			}
		}

		info := structs.Interfaces{
			Name:           iface.Name,
			Ipv4Address:    ipv4List,
			Ipv6Address:    ipv6List,
			DefaultGateway: defaultIP,
		}
		interfaceList = append(interfaceList, info)
	}

	return interfaceList, nil
}

func getDefaultGateway() (string, string, error) {
	ipAddress, _ := gateway.DiscoverInterface()
	gatewayIP, err := gateway.DiscoverGateway()
	return ipAddress.String(), gatewayIP.String(), err
}
