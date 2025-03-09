package portscan

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/Cy-S3c/ScandDeck/pkg/config"
	"github.com/Cy-S3c/ScandDeck/pkg/target"
	"golang.org/x/net/icmp"
	"golang.org/x/sync/semaphore"
)

// ScanResult represents the result of scanning a single port
type ScanResult struct {
	IP      net.IP
	Port    int
	Open    bool
	Service string
	Banner  string
	Latency time.Duration
	Method  string
}

// PortScanner represents the port scanning engine
type PortScanner struct {
	config      *config.ScanConfig
	results     chan ScanResult
	stats       *ScanStats
	concurrency *semaphore.Weighted
	timeout     time.Duration
	retries     int
	wg          sync.WaitGroup
}

// ScanStats keeps track of scan statistics
type ScanStats struct {
	StartTime        time.Time
	EndTime          time.Time
	TotalTargets     int64
	CompletedTargets int64
	TotalPorts       int64
	OpenPorts        int64
	ClosedPorts      int64
	FilteredPorts    int64
}

// NewPortScanner creates a new port scanner with the provided configuration
func NewPortScanner(cfg *config.ScanConfig) *PortScanner {
	concurrencyLimit := int64(cfg.Concurrency)
	if concurrencyLimit <= 0 {
		concurrencyLimit = 1000 // Default value
	}

	return &PortScanner{
		config:      cfg,
		results:     make(chan ScanResult, concurrencyLimit*2),
		stats:       &ScanStats{StartTime: time.Now()},
		concurrency: semaphore.NewWeighted(concurrencyLimit),
		timeout:     time.Duration(cfg.Timeout) * time.Millisecond,
		retries:     cfg.Retries,
	}
}

// Scan initiates a port scan on the specified targets
func (ps *PortScanner) Scan(ctx context.Context, targets []*target.Target, ports []int) (<-chan ScanResult, error) {
	atomic.StoreInt64(&ps.stats.TotalTargets, int64(len(targets)))
	atomic.StoreInt64(&ps.stats.TotalPorts, int64(len(targets)*len(ports)))

	go func() {
		for _, t := range targets {
			for _, p := range ports {
				select {
				case <-ctx.Done():
					return
				default:
					// Acquire semaphore to control concurrency
					if err := ps.concurrency.Acquire(ctx, 1); err != nil {
						continue
					}

					ps.wg.Add(1)
					go func(target *target.Target, port int) {
						defer ps.wg.Done()
						defer ps.concurrency.Release(1)

						// Choose scan method based on configuration
						var result ScanResult
						switch ps.config.ScanType {
						case "syn":
							result = ps.scanSYN(target.IP, port)
						case "connect":
							result = ps.scanConnect(target.IP, port)
						case "udp":
							result = ps.scanUDP(target.IP, port)
						default:
							// Default to connect scan
							result = ps.scanConnect(target.IP, port)
						}

						// Send result to channel
						ps.results <- result

						// Update statistics
						if result.Open {
							atomic.AddInt64(&ps.stats.OpenPorts, 1)
						} else {
							atomic.AddInt64(&ps.stats.ClosedPorts, 1)
						}
					}(t, p)
				}
			}
			atomic.AddInt64(&ps.stats.CompletedTargets, 1)
		}

		// Wait for all scans to complete
		ps.wg.Wait()
		ps.stats.EndTime = time.Now()
		close(ps.results)
	}()

	return ps.results, nil
}

// scanConnect performs a full TCP connect scan
func (ps *PortScanner) scanConnect(ip net.IP, port int) ScanResult {
	result := ScanResult{
		IP:     ip,
		Port:   port,
		Method: "connect",
	}

	start := time.Now()
	addr := fmt.Sprintf("%s:%d", ip.String(), port)
	conn, err := net.DialTimeout("tcp", addr, ps.timeout)

	if err == nil {
		result.Open = true
		result.Latency = time.Since(start)
		
		// Try to get banner if connection succeeded
		if ps.config.BannerGrab {
			// Set read deadline to avoid hanging
			_ = conn.SetReadDeadline(time.Now().Add(ps.timeout))
			
			// Read initial banner
			banner := make([]byte, 1024)
			n, _ := conn.Read(banner)
			if n > 0 {
				result.Banner = string(banner[:n])
			}
		}
		
		conn.Close()
	}

	return result
}

// scanSYN performs a SYN scan (half-open scan)
func (ps *PortScanner) scanSYN(ip net.IP, port int) ScanResult {
	result := ScanResult{
		IP:     ip,
		Port:   port,
		Method: "syn",
	}

	// This is a simplified implementation for illustration
	// In a real implementation, you would:
	// 1. Create a raw socket
	// 2. Craft a TCP SYN packet
	// 3. Send it to the target
	// 4. Listen for SYN-ACK or RST responses
	// 5. If SYN-ACK is received, send RST to tear down
	
	// Note: Raw socket implementation requires root privileges
	// and is platform-dependent. A full implementation would be more complex.
	
	// For now, fallback to connect scan if not root
	// In a real implementation, check for root/admin privileges
	return ps.scanConnect(ip, port)

	// The following is a pseudocode sketch of raw socket implementation:
	/*
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return ps.scanConnect(ip, port) // Fallback
	}
	defer conn.Close()
	
	// Create and send SYN packet
	// Listen for response with timeout
	// Parse response (SYN-ACK indicates open port)
	// Send RST packet to tear down connection if open
	*/
}

// scanUDP performs a UDP scan
func (ps *PortScanner) scanUDP(ip net.IP, port int) ScanResult {
	result := ScanResult{
		IP:     ip,
		Port:   port,
		Method: "udp",
	}

	// UDP scanning is more complex because:
	// 1. Open ports may not respond at all
	// 2. Closed ports should generate ICMP port unreachable
	// 3. Need to craft appropriate probe packets for the service

	addr := fmt.Sprintf("%s:%d", ip.String(), port)
	conn, err := net.DialTimeout("udp", addr, ps.timeout)
	if err != nil {
		return result
	}
	
	// Send an empty UDP packet
	_, err = conn.Write([]byte{})
	if err != nil {
		conn.Close()
		return result
	}
	
	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(ps.timeout))
	
	// Try to read response
	resp := make([]byte, 1024)
	n, err := conn.Read(resp)
	conn.Close()
	
	if err == nil && n > 0 {
		// If we got a response, port is definitely open
		result.Open = true
		result.Banner = string(resp[:n])
		return result
	}
	
	// If we reach here, we didn't get a response
	// In a real UDP scanner, we would also listen for ICMP port unreachable
	// An absence of ICMP port unreachable *might* indicate an open port
	// For simplicity, we mark it as "potentially open" with very low confidence
	result.Open = true // This is a simplification
	
	return result
}

// GetStats returns the current scan statistics
func (ps *PortScanner) GetStats() ScanStats {
	stats := *ps.stats
	if stats.EndTime.IsZero() {
		stats.EndTime = time.Now() // If scan is still running
	}
	return stats
}

// PortState returns the state of a port as a string
func PortState(result ScanResult) string {
	if result.Open {
		return "open"
	}
	return "closed"
}

// ScanTime returns the total time taken for the scan
func (s ScanStats) ScanTime() time.Duration {
	end := s.EndTime
	if end.IsZero() {
		end = time.Now()
	}
	return end.Sub(s.StartTime)
}

// PortsPerSecond calculates the average ports scanned per second
func (s ScanStats) PortsPerSecond() float64 {
	duration := s.ScanTime().Seconds()
	if duration == 0 {
		return 0
	}
	
	scannedPorts := s.OpenPorts + s.ClosedPorts + s.FilteredPorts
	return float64(scannedPorts) / duration
}

// Progress returns the scan progress as a percentage
func (s ScanStats) Progress() float64 {
	if s.TotalPorts == 0 {
		return 100.0
	}
	scannedPorts := s.OpenPorts + s.ClosedPorts + s.FilteredPorts
	return float64(scannedPorts) / float64(s.TotalPorts) * 100.0
}

// CustomPortScan is a convenience function for running a scan with custom parameters
func CustomPortScan(ctx context.Context, targets []*target.Target, ports []int, cfg *config.ScanConfig) ([]ScanResult, error) {
	scanner := NewPortScanner(cfg)
	resultChan, err := scanner.Scan(ctx, targets, ports)
	if err != nil {
		return nil, err
	}
	
	var results []ScanResult
	for result := range resultChan {
		results = append(results, result)
	}
	
	return results, nil
}

