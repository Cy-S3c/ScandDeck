package target

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

// Target represents a scannable target which can be an IP address, CIDR range, or hostname
type Target struct {
	// Original is the original target string (IP, CIDR, or hostname) as provided by user
	Original string
	// Type identifies the target type (ip, cidr, hostname)
	Type string
	// IPs contains all IP addresses associated with this target (may be a single IP or multiple from CIDR/hostname)
	IPs []net.IP
	// Hostname contains the hostname if this target was originally a hostname
	Hostname string
	// CIDR contains the CIDR network if this target was originally a CIDR range
	CIDR *net.IPNet
}

// TargetManager handles a collection of targets and provides operations on them
type TargetManager struct {
	targets []*Target
	mu      sync.RWMutex
}

// NewTargetManager creates a new TargetManager instance
func NewTargetManager() *TargetManager {
	return &TargetManager{
		targets: make([]*Target, 0),
	}
}

// ParseTarget parses a string target and returns a Target instance
func ParseTarget(target string) (*Target, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("empty target")
	}

	// Check if it's a CIDR range
	if strings.Contains(target, "/") {
		return parseCIDR(target)
	}

	// Check if it's a valid IP address
	if ip := net.ParseIP(target); ip != nil {
		return &Target{
			Original: target,
			Type:     "ip",
			IPs:      []net.IP{ip},
		}, nil
	}

	// Assume it's a hostname and try to resolve it
	return parseHostname(target)
}

// parseCIDR parses a CIDR notation target
func parseCIDR(cidr string) (*Target, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR format: %w", err)
	}

	target := &Target{
		Original: cidr,
		Type:     "cidr",
		CIDR:     ipNet,
		IPs:      expandCIDR(ipNet),
	}

	return target, nil
}

// parseHostname parses a hostname target and resolves to IPs
func parseHostname(hostname string) (*Target, error) {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return nil, fmt.Errorf("hostname resolution failed: %w", err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("hostname did not resolve to any IP address")
	}

	return &Target{
		Original: hostname,
		Type:     "hostname",
		Hostname: hostname,
		IPs:      ips,
	}, nil
}

// expandCIDR expands a CIDR range into individual IP addresses
func expandCIDR(ipNet *net.IPNet) []net.IP {
	var ips []net.IP
	
	// Handle IPv4 CIDR
	if len(ipNet.IP) == 4 {
		mask := ipNet.Mask
		network := ipNet.IP.Mask(mask)
		
		// Calculate the number of IPs in this CIDR
		ones, bits := mask.Size()
		size := 1 << (bits - ones)
		
		// Don't expand large networks automatically to prevent memory issues
		if size > 65536 {
			// Just include network and broadcast addresses as placeholders
			ips = append(ips, cloneIP(network))
			return ips
		}
		
		// Expand the CIDR to individual IPs
		for i := 0; i < size; i++ {
			ip := cloneIP(network)
			
			// Calculate the host portion
			for j := 3; j >= 0; j-- {
				ip[j] = network[j] | byte((i>>(8*(3-j)))&0xff)
			}
			
			ips = append(ips, ip)
		}
	} else if len(ipNet.IP) == 16 {
		// For IPv6, we don't expand automatically due to the large address space
		ips = append(ips, cloneIP(ipNet.IP))
	}
	
	return ips
}

// cloneIP creates a copy of an IP address to avoid modifying the original
func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

// AddTarget adds a target to the manager
func (tm *TargetManager) AddTarget(targetStr string) error {
	target, err := ParseTarget(targetStr)
	if err != nil {
		return err
	}
	
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.targets = append(tm.targets, target)
	return nil
}

// AddTargets adds multiple targets to the manager
func (tm *TargetManager) AddTargets(targetStrs []string) error {
	var lastErr error
	
	for _, t := range targetStrs {
		if err := tm.AddTarget(t); err != nil {
			lastErr = err
		}
	}
	
	return lastErr
}

// GetTargets returns all targets managed by this manager
func (tm *TargetManager) GetTargets() []*Target {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	targets := make([]*Target, len(tm.targets))
	copy(targets, tm.targets)
	return targets
}

// GetIPs returns all IP addresses from all targets
func (tm *TargetManager) GetIPs() []net.IP {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	var allIPs []net.IP
	for _, target := range tm.targets {
		allIPs = append(allIPs, target.IPs...)
	}
	
	return allIPs
}

// String returns a string representation of a target
func (t *Target) String() string {
	switch t.Type {
	case "ip":
		return fmt.Sprintf("IP: %s", t.IPs[0])
	case "cidr":
		return fmt.Sprintf("CIDR: %s (%d IPs)", t.Original, len(t.IPs))
	case "hostname":
		ips := make([]string, len(t.IPs))
		for i, ip := range t.IPs {
			ips[i] = ip.String()
		}
		return fmt.Sprintf("Hostname: %s (%s)", t.Hostname, strings.Join(ips, ", "))
	default:
		return t.Original
	}
}

// Count returns the number of targets
func (tm *TargetManager) Count() int {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return len(tm.targets)
}

// IPCount returns the total number of IP addresses in all targets
func (tm *TargetManager) IPCount() int {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	count := 0
	for _, target := range tm.targets {
		count += len(target.IPs)
	}
	
	return count
}

// FilterIPv4 returns only IPv4 addresses from all targets
func (tm *TargetManager) FilterIPv4() []net.IP {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	var ipv4s []net.IP
	for _, target := range tm.targets {
		for _, ip := range target.IPs {
			if ip.To4() != nil {
				ipv4s = append(ipv4s, ip)
			}
		}
	}
	
	return ipv4s
}

// FilterIPv6 returns only IPv6 addresses from all targets
func (tm *TargetManager) FilterIPv6() []net.IP {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	var ipv6s []net.IP
	for _, target := range tm.targets {
		for _, ip := range target.IPs {
			if ip.To4() == nil {
				ipv6s = append(ipv6s, ip)
			}
		}
	}
	
	return ipv6s
}

// Clear removes all targets from the manager
func (tm *TargetManager) Clear() {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	tm.targets = make([]*Target, 0)
}

// RemoveTarget removes a specific target by its original string
func (tm *TargetManager) RemoveTarget(targetStr string) bool {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	for i, target := range tm.targets {
		if target.Original == targetStr {
			// Remove the target by swapping with the last element and truncating
			tm.targets[i] = tm.targets[len(tm.targets)-1]
			tm.targets = tm.targets[:len(tm.targets)-1]
			return true
		}
	}
	
	return false
}

// ValidateTarget checks if a string represents a valid target (IP, CIDR, or resolvable hostname)
func ValidateTarget(targetStr string) error {
	_, err := ParseTarget(targetStr)
	return err
}

