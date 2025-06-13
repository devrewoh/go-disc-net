package network

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// ARPEntry represents an entry in the ARP table
type ARPEntry struct {
	IP       net.IP
	MAC      string
	Vendor   string
	Complete bool
}

// GetARPTable retrieves the system ARP table
func GetARPTable() (map[string]ARPEntry, error) {
	entries := make(map[string]ARPEntry)

	switch runtime.GOOS {
	case "linux":
		return parseLinuxARP()
	case "darwin": // macOS
		return parseDarwinARP()
	case "windows":
		return parseWindowsARP()
	default:
		return entries, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// parseLinuxARP parses /proc/net/arp on Linux
func parseLinuxARP() (map[string]ARPEntry, error) {
	entries := make(map[string]ARPEntry)

	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return entries, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Skip header line
	if scanner.Scan() {
		// Skip "IP address       HW type     Flags       HW address            Mask     Device"
	}

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) >= 4 {
			ipStr := fields[0]
			macStr := fields[3]
			flags := fields[2]

			// Only include complete entries (flags 0x2)
			if flags == "0x2" && macStr != "00:00:00:00:00:00" {
				ip := net.ParseIP(ipStr)
				if ip != nil {
					vendor := LookupMACVendor(macStr)
					entries[ipStr] = ARPEntry{
						IP:       ip,
						MAC:      strings.ToUpper(macStr),
						Vendor:   vendor,
						Complete: true,
					}
				}
			}
		}
	}

	return entries, scanner.Err()
}

// parseDarwinARP parses arp command output on macOS
func parseDarwinARP() (map[string]ARPEntry, error) {
	entries := make(map[string]ARPEntry)

	cmd := exec.Command("arp", "-a")
	output, err := cmd.Output()
	if err != nil {
		return entries, err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Parse lines like: "gateway (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
		// or: "? (192.168.1.100) at bb:cc:dd:ee:ff:aa on en0 ifscope [ethernet]"

		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}

		// Find IP address in parentheses
		var ipStr string
		for _, part := range parts {
			if strings.HasPrefix(part, "(") && strings.HasSuffix(part, ")") {
				ipStr = strings.Trim(part, "()")
				break
			}
		}

		// Find MAC address (contains colons)
		var macStr string
		for _, part := range parts {
			if strings.Count(part, ":") == 5 {
				macStr = part
				break
			}
		}

		if ipStr != "" && macStr != "" && macStr != "(incomplete)" {
			ip := net.ParseIP(ipStr)
			if ip != nil {
				vendor := LookupMACVendor(macStr)
				entries[ipStr] = ARPEntry{
					IP:       ip,
					MAC:      strings.ToUpper(macStr),
					Vendor:   vendor,
					Complete: true,
				}
			}
		}
	}

	return entries, nil
}

// parseWindowsARP parses arp command output on Windows
func parseWindowsARP() (map[string]ARPEntry, error) {
	entries := make(map[string]ARPEntry)

	cmd := exec.Command("arp", "-a")
	output, err := cmd.Output()
	if err != nil {
		return entries, err
	}

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "Interface:") || strings.Contains(line, "Internet Address") {
			continue
		}

		// Parse lines like: "  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic"
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			ipStr := fields[0]
			macStr := strings.ReplaceAll(fields[1], "-", ":")
			entryType := fields[2]

			if entryType == "dynamic" || entryType == "static" {
				ip := net.ParseIP(ipStr)
				if ip != nil {
					vendor := LookupMACVendor(macStr)
					entries[ipStr] = ARPEntry{
						IP:       ip,
						MAC:      strings.ToUpper(macStr),
						Vendor:   vendor,
						Complete: true,
					}
				}
			}
		}
	}

	return entries, nil
}

// ForceARPResolution attempts to populate ARP table for a given IP
func ForceARPResolution(ip net.IP) error {
	// Send a ping to force ARP resolution
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", "-n", "1", "-w", "1000", ip.String())
	case "darwin", "linux":
		cmd = exec.Command("ping", "-c", "1", "-W", "1000", ip.String())
	default:
		return fmt.Errorf("unsupported OS for ping: %s", runtime.GOOS)
	}

	// We don't care about the output, just want to trigger ARP
	cmd.Run()

	// Give ARP table time to update
	time.Sleep(time.Millisecond * 100)

	return nil
}

// GetMACForIP retrieves MAC address for a specific IP
func GetMACForIP(ip net.IP) (string, string, error) {
	// First try to force ARP resolution
	ForceARPResolution(ip)

	// Get ARP table
	arpTable, err := GetARPTable()
	if err != nil {
		return "", "", err
	}

	// Look up the IP
	if entry, exists := arpTable[ip.String()]; exists {
		return entry.MAC, entry.Vendor, nil
	}

	return "", "", fmt.Errorf("MAC address not found for IP %s", ip.String())
}

// RefreshARPForNetwork forces ARP resolution for entire network
func RefreshARPForNetwork(network *net.IPNet) error {
	// Generate IPs in network
	ips := GenerateIPRange(network)

	// Limit concurrent pings to avoid overwhelming the network
	semaphore := make(chan struct{}, 20)

	for _, ip := range ips {
		go func(targetIP net.IP) {
			semaphore <- struct{}{}
			ForceARPResolution(targetIP)
			<-semaphore
		}(ip)
	}

	// Wait a bit for ARP table to populate
	time.Sleep(time.Second * 2)

	return nil
}
