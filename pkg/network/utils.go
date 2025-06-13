package network

import (
	"fmt"
	"net"
	"strings"
)

func GetLocalNetworks() ([]*net.IPNet, error) {
	var networks []*net.IPNet

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get network interfaces: %w", err)
	}

	for _, iface := range interfaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				// Only include IPv4 networks for now
				if ipNet.IP.To4() != nil {
					networks = append(networks, ipNet)
				}
			}
		}
	}
	return networks, nil
}

// GenerateIPRange generates all IP addresses in a network range
func GenerateIPRange(network *net.IPNet) []net.IP {
	var ips []net.IP

	// Convert network to 4-byte representation
	ip := network.IP.To4()
	if ip == nil {
		return ips // Not IPv4
	}

	mask := network.Mask

	// Calculate network and broadcast addresses
	networkAddr := ip.Mask(mask)
	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = networkAddr[i] | ^mask[i]
	}

	// Generate all IPs in range (excluding network and broadcast)
	current := make(net.IP, 4)
	copy(current, networkAddr)

	for {
		// Increment IP
		current[3]++
		if current[3] == 0 {
			current[2]++
			if current[2] == 0 {
				current[1]++
				if current[1] == 0 {
					current[0]++
				}
			}
		}

		// Check if we've reached broadcast address
		if current.Equal(broadcast) {
			break
		}

		// Add IP to list (make a copy)
		ip := make(net.IP, 4)
		copy(ip, current)
		ips = append(ips, ip)
	}

	return ips
}

// IsPrivateIP checks if an IP address is in a private range
func IsPrivateIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		// Check RFC 1918 private ranges
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	return false
}

// ParseMACAddress parses and formats MAC address
func ParseMACAddress(mac string) string {
	// Remove common separators and normalize
	mac = strings.ReplaceAll(mac, "-", ":")
	mac = strings.ReplaceAll(mac, ".", ":")
	mac = strings.ToUpper(mac)

	// Validate format
	if _, err := net.ParseMAC(mac); err != nil {
		return ""
	}

	return mac
}
