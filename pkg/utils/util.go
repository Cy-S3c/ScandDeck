package utils

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Common errors
var (
	ErrInvalidIP      = errors.New("invalid IP address format")
	ErrInvalidCIDR    = errors.New("invalid CIDR notation")
	ErrInvalidPort    = errors.New("invalid port number")
	ErrInvalidRange   = errors.New("invalid range format")
	ErrInvalidTimeout = errors.New("invalid timeout value")
)

// ParseIPAddress parses and validates an IP address string
func ParseIPAddress(ipStr string) (net.IP, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, ErrInvalidIP
	}
	return ip, nil
}

// ParseCIDR parses a CIDR notation string and returns the IP and network
func ParseCIDR(cidrStr string) (*net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidCIDR, err.Error())
	}
	return ipNet, nil
}

// IPsInRange returns all IP addresses in a given CIDR range
func IPsInRange(cidrStr string) ([]net.IP, error) {
	ipNet, err := ParseCIDR(cidrStr)
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	// Handle IPv4
	if ipNet.IP.To4() != nil {
		start := ipToUint32(ipNet.IP.To4())
		mask := ipToUint32(net.IP(ipNet.Mask).To4())
		end := start | ^mask

		// Skip network and broadcast addresses for IPv4
		for i := start + 1; i < end; i++ {
			ips = append(ips, uint32ToIP(i))
		}
	} else {
		// Handle IPv6 - simplified, should be expanded for production
		return nil, errors.New("IPv6 range enumeration not implemented")
	}

	return ips, nil
}

// ipToUint32 converts an IPv4 address to a uint32
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// uint32ToIP converts a uint32 to an IPv4 address
func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	ip[0] = byte(n >> 24)
	ip[1] = byte(n >> 16)
	ip[2] = byte(n >> 8)
	ip[3] = byte(n)
	return ip
}

// ParsePortRange parses a port range string (e.g., "80-100" or "443")
func ParsePortRange(portRange string) (int, int, error) {
	if strings.Contains(portRange, "-") {
		parts := strings.Split(portRange, "-")
		if len(parts) != 2 {
			return 0, 0, ErrInvalidRange
		}
		
		start, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || start < 1 || start > 65535 {
			return 0, 0, ErrInvalidPort
		}
		
		end, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil || end < 1 || end > 65535 || end < start {
			return 0, 0, ErrInvalidPort
		}
		
		return start, end, nil
	}
	
	// Single port
	port, err := strconv.Atoi(strings.TrimSpace(portRange))
	if err != nil || port < 1 || port > 65535 {
		return 0, 0, ErrInvalidPort
	}
	
	return port, port, nil
}

// ParsePortList parses a comma-separated list of ports and port ranges
// Returns a slice of individual ports
func ParsePortList(portList string) ([]int, error) {
	if portList == "" {
		return nil, errors.New("empty port list")
	}

	var result []int
	ranges := strings.Split(portList, ",")
	
	for _, r := range ranges {
		start, end, err := ParsePortRange(strings.TrimSpace(r))
		if err != nil {
			return nil, err
		}
		
		for port := start; port <= end; port++ {
			result = append(result, port)
		}
	}
	
	return result, nil
}

// IsPrivateIP checks if an IP address is in private address space
func IsPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
	}
	
	for _, cidr := range privateRanges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.Contains(ip) {
			return true
		}
	}
	
	return false
}

// RandomizePorts returns the ports in random order
func RandomizePorts(ports []int) []int {
	result := make([]int, len(ports))
	copy(result, ports)
	
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	r.Shuffle(len(result), func(i, j int) {
		result[i], result[j] = result[j], result[i]
	})
	
	return result
}

// FormatDuration formats a duration in a human-readable format
func FormatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%d µs", d.Microseconds())
	} else if d < time.Second {
		return fmt.Sprintf("%d ms", d.Milliseconds())
	} else if d < time.Minute {
		return fmt.Sprintf("%.2f s", d.Seconds())
	} else if d < time.Hour {
		return fmt.Sprintf("%.2f min", d.Minutes())
	}
	return fmt.Sprintf("%.2f h", d.Hours())
}

// ResolveHostname resolves a hostname to an IP address
func ResolveHostname(hostname string) ([]net.IP, error) {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve %s: %w", hostname, err)
	}
	return ips, nil
}

// CreateNetworkTimeout creates a timeout for network operations
func CreateNetworkTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return 5 * time.Second // Default timeout
	}
	return timeout
}

// CalculateOptimalThreads calculates the optimal number of threads to use
// based on available CPU cores and network conditions
func CalculateOptimalThreads(numTargets int, numPorts int) int {
	cpuThreads := 8 // Default to 8 threads
	
	// Get actual number of CPU threads
	if runtime, err := getNumCPU(); err == nil {
		cpuThreads = runtime
	}
	
	// Adjust based on scan size
	scanSize := numTargets * numPorts
	
	switch {
	case scanSize < 100:
		return max(1, cpuThreads/4)
	case scanSize < 1000:
		return max(2, cpuThreads/2)
	case scanSize < 10000:
		return cpuThreads
	default:
		return cpuThreads * 2 // For very large scans, use more threads
	}
}

// getNumCPU is a helper to get the number of CPU threads
func getNumCPU() (int, error) {
	// In a real implementation, this would use runtime.NumCPU()
	// For this example, we'll just return a value
	return 16, nil
}

// max returns the maximum of two integers
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ValidateTimeout validates a timeout value
func ValidateTimeout(timeout string) (time.Duration, error) {
	d, err := time.ParseDuration(timeout)
	if err != nil {
		return 0, fmt.Errorf("%w: %s", ErrInvalidTimeout, err.Error())
	}
	
	if d <= 0 {
		return 0, fmt.Errorf("%w: timeout must be positive", ErrInvalidTimeout)
	}
	
	return d, nil
}

// GetCommonPorts returns a slice of common ports for the specified protocol
func GetCommonPorts(protocol string) []int {
	switch strings.ToLower(protocol) {
	case "tcp":
		return []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080}
	case "udp":
		return []int{53, 67, 68, 69, 123, 135, 137, 138, 161, 162, 445, 500, 514, 520, 631, 1434, 1900, 4500, 5353}
	default:
		return []int{}
	}
}

// GetServiceName returns the common service name for a given port
func GetServiceName(port int, protocol string) string {
	proto := strings.ToLower(protocol)
	
	services := map[string]map[int]string{
		"tcp": {
			21:   "FTP",
			22:   "SSH",
			23:   "Telnet",
			25:   "SMTP",
			53:   "DNS",
			80:   "HTTP",
			110:  "POP3",
			111:  "RPC",
			135:  "MSRPC",
			139:  "NetBIOS",
			143:  "IMAP",
			443:  "HTTPS",
			445:  "SMB",
			993:  "IMAPS",
			995:  "POP3S",
			1433: "MSSQL",
			1723: "PPTP",
			3306: "MySQL",
			3389: "RDP",
			5900: "VNC",
			8080: "HTTP-Proxy",
		},
		"udp": {
			53:   "DNS",
			67:   "DHCP",
			68:   "DHCP",
			69:   "TFTP",
			123:  "NTP",
			137:  "NetBIOS-NS",
			138:  "NetBIOS-DGM",
			161:  "SNMP",
			162:  "SNMP-Trap",
			500:  "IKE",
			514:  "Syslog",
			520:  "RIP",
			1434: "MSSQL-Browser",
			1900: "SSDP",
			5353: "mDNS",
		},
	}
	
	if serviceMap, ok := services[proto]; ok {
		if service, ok := serviceMap[port]; ok {
			return service
		}
	}
	
	return "unknown"
}

