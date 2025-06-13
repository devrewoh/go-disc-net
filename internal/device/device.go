package device

import (
	"net"
	"time"
)

// Device represents a discovered network device with security details
type Device struct {
	IP           net.IP         `json:"ip"`
	MAC          string         `json:"mac"`
	Hostname     string         `json:"hostname"`
	Vendor       string         `json:"vendor"`
	DeviceType   string         `json:"device_type"`
	OS           string         `json:"os"`
	Architecture string         `json:"architecture"`
	OpenPorts    []PortInfo     `json:"open_ports"`
	Services     map[int]string `json:"services"`
	Banners      map[int]string `json:"banners"`
	FirstSeen    time.Time      `json:"first_seen"`
	LastSeen     time.Time      `json:"last_seen"`
	IsOnline     bool           `json:"is_online"`
	SecurityInfo SecurityInfo   `json:"security_info"`
}

// PortInfo contains detailed information about an open port
type PortInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	Version  string `json:"version"`
	Banner   string `json:"banner"`
}

// SecurityInfo contains security-relevant information
type SecurityInfo struct {
	HasSSH           bool     `json:"has_ssh"`
	HasRDP           bool     `json:"has_rdp"`
	HasSMB           bool     `json:"has_smb"`
	HasWebServices   bool     `json:"has_web_services"`
	VulnerablePorts  []int    `json:"vulnerable_ports"`
	WeakServices     []string `json:"weak_services"`
	TLSVersions      []string `json:"tls_versions"`
	SSHVersion       string   `json:"ssh_version"`
	WebServerVersion string   `json:"web_server_version"`
}

// DeviceStore manages our collection of discovered devices
type DeviceStore struct {
	devices map[string]*Device // Key is IP address string
}

// NewDeviceStore creates a new device store
func NewDeviceStore() *DeviceStore {
	return &DeviceStore{
		devices: make(map[string]*Device),
	}
}

// AddOrUpdate adds a new device or updates an existing one
func (ds *DeviceStore) AddOrUpdate(d *Device) {
	ipStr := d.IP.String()

	if existing, exists := ds.devices[ipStr]; exists {
		// Update existing device
		existing.LastSeen = d.LastSeen
		existing.IsOnline = d.IsOnline

		// Update fields that might have changed
		if d.Hostname != "" {
			existing.Hostname = d.Hostname
		}
		if d.MAC != "" {
			existing.MAC = d.MAC
		}
		if d.Vendor != "" {
			existing.Vendor = d.Vendor
		}
		if d.OS != "" {
			existing.OS = d.OS
		}
		if d.Architecture != "" {
			existing.Architecture = d.Architecture
		}
		if len(d.OpenPorts) > 0 {
			existing.OpenPorts = d.OpenPorts
		}
		if len(d.Services) > 0 {
			existing.Services = d.Services
		}
		if len(d.Banners) > 0 {
			existing.Banners = d.Banners
		}
		// Always update security info
		existing.SecurityInfo = d.SecurityInfo
	} else {
		// Add new device
		d.FirstSeen = d.LastSeen
		ds.devices[ipStr] = d
	}
}

// GetAll returns all devices
func (ds *DeviceStore) GetAll() []*Device {
	devices := make([]*Device, 0, len(ds.devices))
	for _, device := range ds.devices {
		devices = append(devices, device)
	}
	return devices
}

// GetOnline returns only online devices
func (ds *DeviceStore) GetOnline() []*Device {
	var online []*Device
	for _, device := range ds.devices {
		if device.IsOnline {
			online = append(online, device)
		}
	}
	return online
}

// MarkOffline marks devices as offline if not seen recently
func (ds *DeviceStore) MarkOffline(timeout time.Duration) {
	cutoff := time.Now().Add(-timeout)
	for _, device := range ds.devices {
		if device.LastSeen.Before(cutoff) {
			device.IsOnline = false
		}
	}
}
