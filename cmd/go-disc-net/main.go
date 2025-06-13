package main

import (
	"context"
	"fmt"
	"github.com/devrewoh/go-disc-net/internal/device"
	"github.com/devrewoh/go-disc-net/internal/scanner"
	"github.com/devrewoh/go-disc-net/pkg/network"
	"log"
	"strings"
	"time"
)

func main() {
	fmt.Println("GoDiscNet - Go Network Discovery Tool")
	fmt.Println("=================================")

	// Create device store and scanner
	store := device.NewDeviceStore()
	scan := scanner.NewScanner(store)

	// Discover local networks
	networks, err := network.GetLocalNetworks()
	if err != nil {
		log.Fatalf("Failed to get local networks: %v", err)
	}

	fmt.Printf("Found %d local networks to scan:\n", len(networks))
	for i, net := range networks {
		fmt.Printf("  %d. %s\n", i+1, net.String())
	}
	fmt.Println()

	// Scan each network
	ctx := context.Background()
	startTime := time.Now()

	for _, net := range networks {
		if err := scan.ScanNetwork(ctx, net); err != nil {
			log.Printf("Error scanning network %s: %v", net.String(), err)
			continue
		}
	}

	// Show results
	devices := store.GetOnline()
	fmt.Printf("\n🔒 SECURITY SCAN RESULTS\n")
	fmt.Printf("========================\n")
	fmt.Printf("Found %d online devices:\n\n", len(devices))

	for i, dev := range devices {
		fmt.Printf("📱 Device #%d: %s", i+1, dev.IP.String())
		if dev.Hostname != "" {
			fmt.Printf(" (%s)", dev.Hostname)
		}
		fmt.Printf("\n")

		fmt.Printf("   🏷️  Type: %s\n", dev.DeviceType)
		if dev.OS != "" {
			fmt.Printf("   💿 OS: %s\n", dev.OS)
		}
		if dev.Architecture != "" {
			fmt.Printf("   🏗️  Architecture: %s\n", dev.Architecture)
		}

		if len(dev.OpenPorts) > 0 {
			fmt.Printf("   🔓 Open Ports (%d found):\n", len(dev.OpenPorts))
			for _, port := range dev.OpenPorts {
				fmt.Printf("      • %d/%s (%s)", port.Port, port.Protocol, port.Service)
				if port.Version != "" && port.Version != "Unknown" {
					fmt.Printf(" - v%s", port.Version)
				}
				fmt.Printf("\n")
				if port.Banner != "" {
					// Truncate long banners
					banner := port.Banner
					if len(banner) > 60 {
						banner = banner[:60] + "..."
					}
					fmt.Printf("        Banner: %s\n", banner)
				}
			}
		}

		// Security Assessment
		sec := dev.SecurityInfo
		if sec.HasSSH || sec.HasRDP || sec.HasSMB || len(sec.WeakServices) > 0 {
			fmt.Printf("   🛡️  Security Assessment:\n")
			if sec.HasSSH {
				fmt.Printf("      ✅ SSH available")
				if sec.SSHVersion != "" && sec.SSHVersion != "Unknown" {
					fmt.Printf(" (v%s)", sec.SSHVersion)
				}
				fmt.Printf("\n")
			}
			if sec.HasRDP {
				fmt.Printf("      ⚠️  RDP enabled (potential security risk)\n")
			}
			if sec.HasSMB {
				fmt.Printf("      ⚠️  SMB/NetBIOS exposed\n")
			}
			if len(sec.WeakServices) > 0 {
				fmt.Printf("      🚨 Weak services detected:\n")
				for _, service := range sec.WeakServices {
					fmt.Printf("         • %s\n", service)
				}
			}
			if len(sec.VulnerablePorts) > 0 {
				fmt.Printf("      🚨 Potentially vulnerable ports: %v\n", sec.VulnerablePorts)
			}
		}

		fmt.Printf("   ⏰ Last seen: %s\n", dev.LastSeen.Format("15:04:05"))
		fmt.Printf("\n" + strings.Repeat("-", 50) + "\n")
	}

	fmt.Printf("Scan completed in %v\n", time.Since(startTime))
}
