package service

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Cy-S3c/ScandDeck/pkg/config"
	"github.com/Cy-S3c/ScandDeck/pkg/target"
)

// ServiceInfo represents the detected service information for a specific port
type ServiceInfo struct {
	Port        int               `json:"port"`
	Protocol    string            `json:"protocol"`
	ServiceName string            `json:"service_name"`
	Product     string            `json:"product,omitempty"`
	Version     string            `json:"version,omitempty"`
	Banner      string            `json:"banner,omitempty"`
	CPEs        []string          `json:"cpes,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Confidence  float64           `json:"confidence"`
}

// Detector represents a service detection engine
type Detector struct {
	config          *config.ServiceConfig
	probeDB         map[string][]Probe
	fingerprintDB   map[string][]Fingerprint
	concurrencyPool chan struct{}
	timeout         time.Duration
	mu              sync.Mutex
}

// Probe represents a service detection probe
type Probe struct {
	Name         string
	Protocol     string
	Payload      []byte
	MatchPattern *regexp.Regexp
	Fallback     bool
}

// Fingerprint represents a pattern to identify a service
type Fingerprint struct {
	Pattern   *regexp.Regexp
	Service   string
	Product   string
	Version   string
	CPEFormat string
}

// NewDetector creates a new service detection engine
func NewDetector(cfg *config.ServiceConfig) (*Detector, error) {
	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 100 // Default concurrency
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second // Default timeout
	}

	detector := &Detector{
		config:          cfg,
		probeDB:         make(map[string][]Probe),
		fingerprintDB:   make(map[string][]Fingerprint),
		concurrencyPool: make(chan struct{}, concurrency),
		timeout:         timeout,
	}

	if err := detector.loadProbes(); err != nil {
		return nil, fmt.Errorf("failed to load service probes: %w", err)
	}

	if err := detector.loadFingerprints(); err != nil {
		return nil, fmt.Errorf("failed to load service fingerprints: %w", err)
	}

	return detector, nil
}

// loadProbes loads service probes from embedded resources or files
func (d *Detector) loadProbes() error {
	// TODO: Implement loading probes from files or embed them
	// This is a simplified version with a few common probes
	
	// HTTP probe
	httpProbe := Probe{
		Name:     "HTTP",
		Protocol: "tcp",
		Payload:  []byte("GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: ScandDeck/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"),
		MatchPattern: regexp.MustCompile(`(?i)^HTTP/\d\.\d\s+\d+`),
	}
	
	// SSH probe
	sshProbe := Probe{
		Name:     "SSH",
		Protocol: "tcp",
		Payload:  []byte(""),  // SSH servers typically send their banner immediately upon connection
		MatchPattern: regexp.MustCompile(`(?i)^SSH-\d\.\d`),
	}
	
	// FTP probe
	ftpProbe := Probe{
		Name:     "FTP",
		Protocol: "tcp",
		Payload:  []byte(""),  // FTP servers typically send their banner immediately upon connection
		MatchPattern: regexp.MustCompile(`(?i)^220\s+.*(?:ftp|file\s+transfer)`),
	}
	
	// SMTP probe
	smtpProbe := Probe{
		Name:     "SMTP",
		Protocol: "tcp",
		Payload:  []byte(""),  // SMTP servers typically send their banner immediately upon connection
		MatchPattern: regexp.MustCompile(`(?i)^220\s+.*(?:smtp|mail\s+service)`),
	}
	
	// MySQL probe
	mysqlProbe := Probe{
		Name:     "MySQL",
		Protocol: "tcp",
		Payload:  []byte{},  // MySQL servers typically send a greeting packet
		MatchPattern: regexp.MustCompile(`^.\x00\x00\x00\x0a\d+\.\d+\.\d+`),
	}

	// Group probes by protocol
	d.probeDB["tcp"] = []Probe{httpProbe, sshProbe, ftpProbe, smtpProbe, mysqlProbe}
	
	return nil
}

// loadFingerprints loads service fingerprints from embedded resources or files
func (d *Detector) loadFingerprints() error {
	// TODO: Implement loading fingerprints from files or embed them
	// This is a simplified version with a few common fingerprints
	
	// HTTP server fingerprints
	apacheFingerprint := Fingerprint{
		Pattern:   regexp.MustCompile(`(?i)Server:\s+Apache/(\d+[\.\d]+)`),
		Service:   "http",
		Product:   "Apache httpd",
		Version:   "$1",
		CPEFormat: "cpe:2.3:a:apache:http_server:$1:*:*:*:*:*:*:*",
	}
	
	nginxFingerprint := Fingerprint{
		Pattern:   regexp.MustCompile(`(?i)Server:\s+nginx/(\d+[\.\d]+)`),
		Service:   "http",
		Product:   "Nginx",
		Version:   "$1",
		CPEFormat: "cpe:2.3:a:nginx:nginx:$1:*:*:*:*:*:*:*",
	}
	
	// SSH fingerprints
	openSSHFingerprint := Fingerprint{
		Pattern:   regexp.MustCompile(`(?i)SSH-2.0-OpenSSH_(\d+[\.\d\w]+)`),
		Service:   "ssh",
		Product:   "OpenSSH",
		Version:   "$1",
		CPEFormat: "cpe:2.3:a:openbsd:openssh:$1:*:*:*:*:*:*:*",
	}

	// Group fingerprints by service
	d.fingerprintDB["http"] = []Fingerprint{apacheFingerprint, nginxFingerprint}
	d.fingerprintDB["ssh"] = []Fingerprint{openSSHFingerprint}
	
	return nil
}

// DetectServices scans the provided targets and ports for service information
func (d *Detector) DetectServices(ctx context.Context, targets []target.Target, ports []int) (map[string]map[int]ServiceInfo, error) {
	results := make(map[string]map[int]ServiceInfo)
	resultsMu := sync.Mutex{}
	var wg sync.WaitGroup

	for _, t := range targets {
		for _, ip := range t.IPs {
			ipStr := ip.String()
			resultsMu.Lock()
			if _, exists := results[ipStr]; !exists {
				results[ipStr] = make(map[int]ServiceInfo)
			}
			resultsMu.Unlock()

			for _, port := range ports {
				wg.Add(1)
				go func(ip net.IP, port int) {
					defer wg.Done()

					// Acquire semaphore from pool
					d.concurrencyPool <- struct{}{}
					defer func() { <-d.concurrencyPool }()

					// Check if context is cancelled
					if ctx.Err() != nil {
						return
					}

					// Try TCP first
					serviceInfo, err := d.detectService(ctx, ip, port, "tcp")
					if err != nil || serviceInfo.ServiceName == "" {
						// Optionally try UDP if TCP fails
						if d.config.ScanUDP {
							serviceInfo, _ = d.detectService(ctx, ip, port, "udp")
						}
					}

					if serviceInfo.ServiceName != "" {
						resultsMu.Lock()
						results[ip.String()][port] = serviceInfo
						resultsMu.Unlock()
					}
				}(ip, port)
			}
		}
	}

	wg.Wait()
	return results, nil
}

// detectService attempts to identify a service on a specific IP and port
func (d *Detector) detectService(ctx context.Context, ip net.IP, port int, protocol string) (ServiceInfo, error) {
	serviceInfo := ServiceInfo{
		Port:     port,
		Protocol: protocol,
	}

	// Create a sub-context with timeout
	ctxWithTimeout, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	// Determine address based on protocol
	address := fmt.Sprintf("%s:%d", ip.String(), port)

	// Get appropriate probes for this protocol
	probes, ok := d.probeDB[protocol]
	if !ok {
		return serviceInfo, fmt.Errorf("no probes defined for protocol: %s", protocol)
	}

	var dialer net.Dialer
	var conn net.Conn
	var err error

	// Connect to the service
	if protocol == "tcp" {
		conn, err = dialer.DialContext(ctxWithTimeout, "tcp", address)
	} else if protocol == "udp" {
		conn, err = dialer.DialContext(ctxWithTimeout, "udp", address)
	} else {
		return serviceInfo, fmt.Errorf("unsupported protocol: %s", protocol)
	}

	if err != nil {
		return serviceInfo, err
	}
	defer conn.Close()

	// Set read and write deadlines
	conn.SetDeadline(time.Now().Add(d.timeout))

	// Try each probe
	for _, probe := range probes {
		// If probe is for a different protocol, skip
		if probe.Protocol != protocol {
			continue
		}

		// Reset connection deadlines for each probe
		conn.SetDeadline(time.Now().Add(d.timeout))

		// If there's a payload, send it
		if len(probe.Payload) > 0 {
			if _, err := conn.Write(probe.Payload); err != nil {
				continue // Try next probe if write fails
			}
		}

		// Read response
		buffer := make([]byte, 4096)
		bytesRead, err := conn.Read(buffer)
		if err != nil {
			continue // Try next probe if read fails
		}

		response := buffer[:bytesRead]
		serviceInfo.Banner = string(bytes.TrimRight(response, "\x00"))

		// Try to match the response against the probe pattern
		if probe.MatchPattern.Match(response) {
			serviceInfo.ServiceName = probe.Name
			
			// Extract version information
			d.extractVersionInfo(&serviceInfo)
			
			return serviceInfo, nil
		}
	}

	// If we reached here, no probes matched
	// Try to make a best guess based on common port assignments
	serviceInfo.ServiceName = guessServiceByPort(port)
	serviceInfo.Confidence = 0.5 // Lower confidence for port-based guessing

	return serviceInfo, nil
}

// extractVersionInfo attempts to extract version information from a banner
func (d *Detector) extractVersionInfo(info *ServiceInfo) {
	if info.ServiceName == "" || info.Banner == "" {
		return
	}

	// Look up fingerprints for this service
	fingerprints, ok := d.fingerprintDB[strings.ToLower(info.ServiceName)]
	if !ok {
		return
	}

	// Try each fingerprint
	for _, fp := range fingerprints {
		matches := fp.Pattern.FindStringSubmatch(info.Banner)
		if len(matches) > 0 {
			info.Product = fp.Product
			
			// Replace capturing groups in version string
			version := fp.Version
			for i := 1; i < len(matches); i++ {
				placeholder := fmt.Sprintf("$%d", i)
				version = strings.Replace(version, placeholder, matches[i], -1)
			}
			info.Version = version
			
			// Generate CPE if available
			if fp.CPEFormat != "" {
				cpe := fp.CPEFormat
				for i := 1; i < len(matches); i++ {
					placeholder := fmt.Sprintf("$%d", i)
					cpe = strings.Replace(cpe, placeholder, matches[i], -1)
				}
				info.CPEs = append(info.CPEs, cpe)
			}
			
			info.Confidence = 0.9
			return
		}
	}
}

// guessServiceByPort makes an educated guess about service based on common port numbers
func guessServiceByPort(port int) string {
	switch port {
	case 21:
		return "FTP"
	case 22:
		return "SSH"
	case 23:
		return "Telnet"
	case 25:
		return "SMTP"
	case 80, 8080:
		return "HTTP"
	case 443, 8443:
		return "HTTPS"
	case 3306:
		return "MySQL"
	case 5432:
		return "PostgreSQL"
	case 27017:
		return "MongoDB"
	case 6379:
		return "Redis"
	case 53:
		return "DNS"
	case 161:
		return "SNMP"
	default:
		return "Unknown"
	}
}

// EnhancedScan performs a more detailed scan on identified services
// This can include additional probes, deeper inspection, etc.
func (d *Detector) EnhancedScan(ctx context.Context, target string, port int, initialInfo ServiceInfo) (ServiceInfo, error) {
	// This method would implement more sophisticated techniques for specific services
	// For example, gathering HTTP headers, SSL/TLS information, database versions, etc.
	
	// For now, return the initial info - this would be expanded in a real implementation
	return initialInfo, nil
}

// GetServiceRisks evaluates potential security risks based on detected service and version
func (d *Detector) GetServiceRisks(info ServiceInfo) map[string]interface{} {
	risks := make(map[string]interface{})
	
	// Example risk detection logic
	if info.ServiceName == "HTTP" && info.Product == "Apache httpd" {
		// Check for vulnerable Apache versions
		if strings.HasPrefix(info.Version, "2.4.") {
			versionParts := strings.Split(info.Version, ".")
			if len(versionParts) > 2 {
				// Apache 2.4.0 to 2.4.49 vulnerable to path traversal (CVE-2021-41773)
				if versionParts[

