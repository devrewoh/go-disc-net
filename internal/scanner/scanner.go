package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/devrewoh/go-disc-net/internal/device"
	"github.com/devrewoh/go-disc-net/pkg/network"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

// SecurityScanner performs comprehensive network security scanning
type SecurityScanner struct {
	store       *device.DeviceStore
	concurrency int
	timeout     time.Duration
}

// NewScanner creates a new security scanner
func NewScanner(store *device.DeviceStore) *SecurityScanner {
	return &SecurityScanner{
		store:       store,
		concurrency: 20, // Reduced for thorough scanning
		timeout:     time.Second * 5,
	}
}

// ScanNetwork performs comprehensive security scanning
func (s *SecurityScanner) ScanNetwork(ctx context.Context, network *net.IPNet) error {
	fmt.Printf("🔍 Starting comprehensive security scan of %s...\n", network.String())

	// Add local machine first
	s.addLocalMachine(network)

	// Generate all IPs to scan
	ips := generateIPRange(network)
	fmt.Printf("📡 Scanning %d IP addresses with deep inspection...\n", len(ips))

	// Create channels for work distribution
	ipChan := make(chan net.IP, len(ips))
	resultChan := make(chan *device.Device, len(ips))

	// Send all IPs to channel
	for _, ip := range ips {
		ipChan <- ip
	}
	close(ipChan)

	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < s.concurrency; i++ {
		wg.Add(1)
		go s.securityScanWorker(ctx, &wg, ipChan, resultChan)
	}

	// Collect results
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Process results with detailed output
	discovered := 0
	for result := range resultChan {
		if result != nil {
			s.store.AddOrUpdate(result)
			discovered++
			s.printDeviceDiscovery(result)
		}
	}

	fmt.Printf("✅ Security scan complete. Discovered %d devices.\n", discovered)
	return nil
}

// securityScanWorker performs comprehensive scanning on individual IPs
func (s *SecurityScanner) securityScanWorker(ctx context.Context, wg *sync.WaitGroup, ipChan <-chan net.IP, resultChan chan<- *device.Device) {
	defer wg.Done()

	for ip := range ipChan {
		select {
		case <-ctx.Done():
			return
		default:
			if dev := s.comprehensiveScan(ip); dev != nil {
				resultChan <- dev
			} else {
				resultChan <- nil
			}
		}
	}
}

// comprehensiveScan performs deep inspection of a single device
func (s *SecurityScanner) comprehensiveScan(ip net.IP) *device.Device {
	// Perform port scan first
	openPorts := s.scanAllPorts(ip)
	if len(openPorts) == 0 {
		return nil
	}

	// Create device
	dev := &device.Device{
		IP:        ip,
		LastSeen:  time.Now(),
		IsOnline:  true,
		OpenPorts: openPorts,
		Services:  make(map[int]string),
		Banners:   make(map[int]string),
	}

	// Perform service detection and banner grabbing
	s.detectServices(dev)

	// OS fingerprinting
	s.detectOS(dev)

	// Hostname resolution
	s.resolveHostname(dev)

	// MAC address and vendor detection
	s.detectMAC(dev)

	// Security assessment
	s.assessSecurity(dev)

	// Device type identification
	dev.DeviceType = s.identifyDeviceType(dev)

	return dev
}

// scanAllPorts scans comprehensive port ranges
func (s *SecurityScanner) scanAllPorts(ip net.IP) []device.PortInfo {
	var openPorts []device.PortInfo

	// Common ports for thorough scanning
	commonPorts := []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
		1723, 3389, 5353, 5900, 8080, 8443, 8888, 9100,
		// Additional security-relevant ports
		20, 69, 88, 389, 636, 1433, 1521, 2049, 3306, 5432, 5985, 5986,
		// IoT and modern service ports
		1883, 8883, 502, 102, 44818, 47808, 7547, 37777, 2323,
	}

	for _, port := range commonPorts {
		if portInfo := s.scanPort(ip, port); portInfo != nil {
			openPorts = append(openPorts, *portInfo)
		}
	}

	return openPorts
}

// scanPort performs detailed port scanning with service detection
func (s *SecurityScanner) scanPort(ip net.IP, port int) *device.PortInfo {
	address := fmt.Sprintf("%s:%d", ip.String(), port)
	conn, err := net.DialTimeout("tcp", address, time.Millisecond*500)
	if err != nil {
		return nil
	}
	defer conn.Close()

	portInfo := &device.PortInfo{
		Port:     port,
		Protocol: "tcp",
		Service:  s.identifyService(port),
	}

	// Try to grab banner
	banner := s.grabBanner(conn, port)
	if banner != "" {
		portInfo.Banner = banner
		portInfo.Version = s.extractVersion(banner)
	}

	return portInfo
}

// grabBanner attempts to grab service banners
func (s *SecurityScanner) grabBanner(conn net.Conn, port int) string {
	conn.SetReadDeadline(time.Now().Add(time.Second * 2))

	// Send appropriate probe based on port
	switch port {
	case 80, 8080, 8443:
		conn.Write([]byte("GET / HTTP/1.1\r\nHost: test\r\n\r\n"))
	case 443:
		// For HTTPS, we need TLS
		return s.grabHTTPSBanner(conn)
	case 22:
		// SSH sends banner immediately
	case 21:
		// FTP sends banner immediately
	case 25:
		// SMTP sends banner immediately
	default:
		// Try a generic probe
		conn.Write([]byte("\r\n"))
	}

	// Read response
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(buffer[:n]))
}

// grabHTTPSBanner handles HTTPS banner grabbing
func (s *SecurityScanner) grabHTTPSBanner(conn net.Conn) string {
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	defer tlsConn.Close()

	if err := tlsConn.Handshake(); err != nil {
		return ""
	}

	tlsConn.Write([]byte("GET / HTTP/1.1\r\nHost: test\r\n\r\n"))

	buffer := make([]byte, 1024)
	n, err := tlsConn.Read(buffer)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(buffer[:n]))
}

// detectServices performs service detection
func (s *SecurityScanner) detectServices(dev *device.Device) {
	for _, portInfo := range dev.OpenPorts {
		dev.Services[portInfo.Port] = portInfo.Service
		if portInfo.Banner != "" {
			dev.Banners[portInfo.Port] = portInfo.Banner
		}
	}
}

// detectOS performs OS fingerprinting
func (s *SecurityScanner) detectOS(dev *device.Device) {
	// Analyze banners and services for OS detection
	for _, banner := range dev.Banners {
		banner = strings.ToLower(banner)

		if strings.Contains(banner, "windows") || strings.Contains(banner, "microsoft") {
			dev.OS = "Windows"
			if strings.Contains(banner, "windows server") {
				dev.OS = "Windows Server"
			}
		} else if strings.Contains(banner, "ubuntu") {
			dev.OS = "Ubuntu Linux"
		} else if strings.Contains(banner, "debian") {
			dev.OS = "Debian Linux"
		} else if strings.Contains(banner, "centos") {
			dev.OS = "CentOS Linux"
		} else if strings.Contains(banner, "linux") {
			dev.OS = "Linux"
		} else if strings.Contains(banner, "macos") || strings.Contains(banner, "darwin") {
			dev.OS = "macOS"
		} else if strings.Contains(banner, "freebsd") {
			dev.OS = "FreeBSD"
		}
	}

	// Additional OS detection based on open ports
	if dev.OS == "" {
		if s.hasPort(dev, 3389) { // RDP
			dev.OS = "Windows"
		} else if s.hasPort(dev, 22) && s.hasPort(dev, 80) {
			dev.OS = "Linux/Unix"
		} else if s.hasPort(dev, 548) { // AFP
			dev.OS = "macOS"
		}
	}
}

// resolveHostname performs hostname resolution
func (s *SecurityScanner) resolveHostname(dev *device.Device) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, dev.IP.String())
	if err == nil && len(names) > 0 {
		dev.Hostname = names[0]
	}
}

// detectMAC attempts MAC address detection using ARP table
func (s *SecurityScanner) detectMAC(dev *device.Device) {
	mac, vendor, err := network.GetMACForIP(dev.IP)
	if err == nil {
		dev.MAC = mac
		dev.Vendor = vendor
	} else {
		dev.MAC = "Not detected"
		dev.Vendor = "Unknown"
	}
}

// assessSecurity performs security assessment
func (s *SecurityScanner) assessSecurity(dev *device.Device) {
	secInfo := &device.SecurityInfo{}

	// Check for common security-relevant services
	secInfo.HasSSH = s.hasPort(dev, 22)
	secInfo.HasRDP = s.hasPort(dev, 3389)
	secInfo.HasSMB = s.hasPort(dev, 445) || s.hasPort(dev, 139)
	secInfo.HasWebServices = s.hasPort(dev, 80) || s.hasPort(dev, 443) || s.hasPort(dev, 8080)

	// Identify potentially vulnerable services
	for _, portInfo := range dev.OpenPorts {
		switch portInfo.Port {
		case 23: // Telnet
			secInfo.WeakServices = append(secInfo.WeakServices, "Telnet (unencrypted)")
		case 21: // FTP
			secInfo.WeakServices = append(secInfo.WeakServices, "FTP (potentially unencrypted)")
		case 135, 139, 445: // Windows services
			secInfo.VulnerablePorts = append(secInfo.VulnerablePorts, portInfo.Port)
		}
	}

	// Extract version information
	for port, banner := range dev.Banners {
		if port == 22 && strings.Contains(banner, "SSH") {
			secInfo.SSHVersion = s.extractVersion(banner)
		}
		if (port == 80 || port == 443) && strings.Contains(banner, "Server:") {
			secInfo.WebServerVersion = s.extractVersion(banner)
		}
	}

	dev.SecurityInfo = *secInfo
}

// Helper functions
func (s *SecurityScanner) hasPort(dev *device.Device, port int) bool {
	for _, portInfo := range dev.OpenPorts {
		if portInfo.Port == port {
			return true
		}
	}
	return false
}

func (s *SecurityScanner) identifyService(port int) string {
	services := map[int]string{
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		110:  "POP3",
		135:  "RPC",
		139:  "NetBIOS",
		143:  "IMAP",
		443:  "HTTPS",
		445:  "SMB",
		993:  "IMAPS",
		995:  "POP3S",
		1433: "MSSQL",
		3306: "MySQL",
		3389: "RDP",
		5432: "PostgreSQL",
		5900: "VNC",
		8080: "HTTP-Alt",
	}

	if service, exists := services[port]; exists {
		return service
	}
	return "Unknown"
}

func (s *SecurityScanner) extractVersion(banner string) string {
	// Simple version extraction using regex
	versionRegex := regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)`)
	matches := versionRegex.FindStringSubmatch(banner)
	if len(matches) > 1 {
		return matches[1]
	}
	return "Unknown"
}

func (s *SecurityScanner) identifyDeviceType(dev *device.Device) string {
	hostname := strings.ToLower(dev.Hostname)
	vendor := strings.ToLower(dev.Vendor)

	// Check MAC vendor first for better identification
	switch {
	case strings.Contains(vendor, "apple"):
		if s.hasPort(dev, 548) { // AFP
			return "🍎 Mac Computer"
		}
		if s.hasPort(dev, 62078) || strings.Contains(hostname, "iphone") {
			return "📱 iPhone"
		}
		if strings.Contains(hostname, "ipad") {
			return "📱 iPad"
		}
		return "🍎 Apple Device"

	case strings.Contains(vendor, "gigabyte"):
		if s.hasPort(dev, 80) && s.hasPort(dev, 53) {
			return "🌐 Gigabyte Router/Gateway"
		}
		return "💻 Gigabyte Device"

	case strings.Contains(vendor, "samsung"):
		if strings.Contains(hostname, "galaxy") || s.hasPort(dev, 8443) {
			return "📱 Samsung Phone/Tablet"
		}
		return "📱 Samsung Device"

	case strings.Contains(vendor, "microsoft"):
		return "💻 Microsoft Device"

	case strings.Contains(vendor, "asus"):
		if s.hasPort(dev, 80) && s.hasPort(dev, 53) {
			return "🌐 ASUS Router"
		}
		return "💻 ASUS Device"

	case strings.Contains(vendor, "netgear"):
		return "🌐 Netgear Router"

	case strings.Contains(vendor, "google"):
		return "🏠 Google Device (Nest/Chromecast)"
	}

	// Check hostname patterns
	if strings.Contains(hostname, "router") || strings.Contains(hostname, "gateway") {
		return "🌐 Router/Gateway"
	}
	if strings.Contains(hostname, "modem") {
		return "📡 Modem"
	}
	if strings.Contains(hostname, "printer") {
		return "🖨️ Printer"
	}

	// Check based on OS and services
	if dev.OS == "Windows" || dev.OS == "Windows Server" {
		if s.hasPort(dev, 3389) {
			return "💻 Windows Computer (RDP enabled)"
		}
		return "💻 Windows Computer"
	}
	if strings.Contains(dev.OS, "Linux") {
		if s.hasPort(dev, 22) && s.hasPort(dev, 80) {
			return "🖥️ Linux Server"
		}
		return "🐧 Linux Computer"
	}
	if dev.OS == "macOS" {
		return "🍎 Mac Computer"
	}

	// Check based on services
	if s.hasPort(dev, 80) && s.hasPort(dev, 443) && s.hasPort(dev, 22) {
		return "🖥️ Web Server"
	}
	if s.hasPort(dev, 631) || s.hasPort(dev, 9100) {
		return "🖨️ Network Printer"
	}
	if s.hasPort(dev, 80) && s.hasPort(dev, 53) {
		return "🌐 Router/Network Device"
	}

	return "❓ Unknown Device"
}

func (s *SecurityScanner) printDeviceDiscovery(dev *device.Device) {
	fmt.Printf("🎯 Found: %s", dev.IP.String())
	if dev.Hostname != "" {
		fmt.Printf(" (%s)", dev.Hostname)
	}
	fmt.Printf(" [%s]", dev.DeviceType)
	if dev.OS != "" {
		fmt.Printf(" - OS: %s", dev.OS)
	}
	fmt.Println()
}

func (s *SecurityScanner) addLocalMachine(network *net.IPNet) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && network.Contains(ipNet.IP) {
				localDevice := &device.Device{
					IP:         ipNet.IP,
					Hostname:   "localhost",
					DeviceType: "💻 Local Machine",
					OS:         "Current System",
					LastSeen:   time.Now(),
					IsOnline:   true,
					OpenPorts:  []device.PortInfo{},
					Services:   make(map[int]string),
					Banners:    make(map[int]string),
				}
				s.store.AddOrUpdate(localDevice)
				fmt.Printf("📍 Local machine detected: %s\n", ipNet.IP.String())
				return
			}
		}
	}
}

func generateIPRange(network *net.IPNet) []net.IP {
	var ips []net.IP

	ip := network.IP.To4()
	if ip == nil {
		return ips
	}

	mask := network.Mask
	networkAddr := ip.Mask(mask)
	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = networkAddr[i] | ^mask[i]
	}

	current := make(net.IP, 4)
	copy(current, networkAddr)

	for {
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

		if current.Equal(broadcast) {
			break
		}

		newIP := make(net.IP, 4)
		copy(newIP, current)
		ips = append(ips, newIP)
	}

	return ips
}
