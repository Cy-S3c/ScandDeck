// Package discovery implements host discovery methods for network scanning
package discovery

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
)

// DiscoveryResult represents the result of a host discovery operation
type DiscoveryResult struct {
	Host    string    // Host IP address
	Up      bool      // Whether the host is up
	Latency time.Duration // Response time if measured
	Method  string    // Discovery method used (ICMP, ARP, TCP SYN, etc.)
}

// DiscoveryOptions contains configuration for discovery operations
type DiscoveryOptions struct {
	Timeout       time.Duration // Timeout for each probe
	Retries       int           // Number of retries for each host
	Concurrency   int           // Maximum number of concurrent operations
	Interface     string        // Network interface to use
	SourceIP      string        // Source IP address to use
	ICMPEnabled   bool          // Whether to use ICMP echo
	ARPEnabled    bool          // Whether to use ARP
	TCPSYNEnabled bool          // Whether to use TCP SYN
	TCPPorts      []int         // TCP ports to use for TCP SYN discovery
}

// DefaultDiscoveryOptions returns the default discovery options
func DefaultDiscoveryOptions() *DiscoveryOptions {
	return &DiscoveryOptions{
		Timeout:       2 * time.Second,
		Retries:       2,
		Concurrency:   100,
		ICMPEnabled:   true,
		ARPEnabled:    true,
		TCPSYNEnabled: true,
		TCPPorts:      []int{80, 443, 22, 445},
	}
}

// Discoverer defines the interface for host discovery methods
type Discoverer interface {
	// Discover performs host discovery on the given targets
	Discover(ctx context.Context, targets []string, options *DiscoveryOptions) ([]DiscoveryResult, error)
}

// Engine implements the Discoverer interface with multiple discovery methods
type Engine struct {
	// Configuration and state can be added here
}

// NewEngine creates a new discovery engine
func NewEngine() *Engine {
	return &Engine{}
}

// Discover performs host discovery using all enabled methods
func (e *Engine) Discover(ctx context.Context, targets []string, options *DiscoveryOptions) ([]DiscoveryResult, error) {
	if options == nil {
		options = DefaultDiscoveryOptions()
	}

	var results []DiscoveryResult
	var mutex sync.Mutex
	var wg errgroup.Group
	sem := semaphore.NewWeighted(int64(options.Concurrency))

	// Helper function to add results
	addResult := func(result DiscoveryResult) {
		mutex.Lock()
		defer mutex.Unlock()
		results = append(results, result)
	}

	// Process each target
	for _, target := range targets {
		target := target // Create a new variable for the goroutine
		
		if err := sem.Acquire(ctx, 1); err != nil {
			return results, fmt.Errorf("failed to acquire semaphore: %w", err)
		}
		
		wg.Go(func() error {
			defer sem.Release(1)
			
			// Try each enabled discovery method until we find the host is up
			var discoveryResult DiscoveryResult
			discoveryResult.Host = target
			
			// ICMP Echo discovery
			if options.ICMPEnabled {
				up, latency, err := e.icmpDiscover(ctx, target, options)
				if err == nil && up {
					discoveryResult.Up = true
					discoveryResult.Latency = latency
					discoveryResult.Method = "ICMP"
					addResult(discoveryResult)
					return nil
				}
			}
			
			// ARP discovery for local network
			if options.ARPEnabled {
				isLocal, err := isLocalNetwork(target)
				if err == nil && isLocal {
					up, latency, err := e.arpDiscover(ctx, target, options)
					if err == nil && up {
						discoveryResult.Up = true
						discoveryResult.Latency = latency
						discoveryResult.Method = "ARP"
						addResult(discoveryResult)
						return nil
					}
				}
			}
			
			// TCP SYN discovery
			if options.TCPSYNEnabled {
				up, latency, err := e.tcpSynDiscover(ctx, target, options)
				if err == nil && up {
					discoveryResult.Up = true
					discoveryResult.Latency = latency
					discoveryResult.Method = "TCP SYN"
					addResult(discoveryResult)
					return nil
				}
			}
			
			// If we've tried all methods and found nothing, host is likely down
			discoveryResult.Up = false
			discoveryResult.Method = "None"
			addResult(discoveryResult)
			
			return nil
		})
	}

	if err := wg.Wait(); err != nil {
		return results, fmt.Errorf("discovery error: %w", err)
	}
	
	return results, nil
}

// icmpDiscover performs ICMP Echo (ping) discovery
func (e *Engine) icmpDiscover(ctx context.Context, target string, options *DiscoveryOptions) (bool, time.Duration, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", options.SourceIP)
	if err != nil {
		return false, 0, fmt.Errorf("failed to listen for ICMP packets: %w", err)
	}
	defer conn.Close()

	ipAddr, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		return false, 0, fmt.Errorf("failed to resolve IP address: %w", err)
	}

	// Create ICMP echo request
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("ScandDeck ICMP Discovery"),
		},
	}

	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		return false, 0, fmt.Errorf("failed to marshal ICMP message: %w", err)
	}

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(options.Timeout))

	// Send the ICMP echo request
	startTime := time.Now()
	if _, err := conn.WriteTo(msgBytes, ipAddr); err != nil {
		return false, 0, fmt.Errorf("failed to send ICMP packet: %w", err)
	}

	// Read the response
	resp := make([]byte, 1500)
	n, _, err := conn.ReadFrom(resp)
	if err != nil {
		return false, 0, fmt.Errorf("failed to read ICMP response: %w", err)
	}

	// Calculate latency
	latency := time.Since(startTime)

	// Parse the response
	parsedMsg, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), resp[:n])
	if err != nil {
		return false, 0, fmt.Errorf("failed to parse ICMP response: %w", err)
	}

	// Check if it's an echo reply
	if parsedMsg.Type == ipv4.ICMPTypeEchoReply {
		return true, latency, nil
	}

	return false, 0, fmt.Errorf("received ICMP message is not an echo reply")
}

// arpDiscover performs ARP discovery for hosts on the local network
func (e *Engine) arpDiscover(ctx context.Context, target string, options *DiscoveryOptions) (bool, time.Duration, error) {
	// Find network interface for ARP scanning
	var iface *net.Interface
	var err error

	if options.Interface != "" {
		iface, err = net.InterfaceByName(options.Interface)
		if err != nil {
			return false, 0, fmt.Errorf("failed to find interface %s: %w", options.Interface, err)
		}
	} else {
		// Find appropriate interface based on target IP
		ifaces, err := net.Interfaces()
		if err != nil {
			return false, 0, fmt.Errorf("failed to list network interfaces: %w", err)
		}

		targetIP := net.ParseIP(target)
		if targetIP == nil {
			return false, 0, fmt.Errorf("invalid target IP: %s", target)
		}

		for _, i := range ifaces {
			addrs, err := i.Addrs()
			if err != nil {
				continue
			}

			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && ipnet.Contains(targetIP) {
					iface = &i
					break
				}
			}
			if iface != nil {
				break
			}
		}
	}

	if iface == nil {
		return false, 0, fmt.Errorf("could not find appropriate interface for ARP scanning")
	}

	// Open packet capture handle
	handle, err := pcap.OpenLive(iface.Name, 1600, true, options.Timeout)
	if err != nil {
		return false, 0, fmt.Errorf("failed to open pcap handle: %w", err)
	}
	defer handle.Close()

	// Set BPF filter to only capture ARP responses
	err = handle.SetBPFFilter("arp and arp[6:2] = 2") // ARP reply
	if err != nil {
		return false, 0, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	// Get interface details
	sourceIP, sourceMAC, err := getInterfaceDetails(iface)
	if err != nil {
		return false, 0, fmt.Errorf("failed to get interface details: %w", err)
	}

	// Parse target IP
	targetIP := net.ParseIP(target).To4()
	if targetIP == nil {
		return false, 0, fmt.Errorf("invalid IPv4 target: %s", target)
	}

	// Create ARP request
	eth := layers.Ethernet{
		SrcMAC:       sourceMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // Broadcast
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   sourceMAC,
		SourceProtAddress: sourceIP.To4(),
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    targetIP,
	}

	// Serialize packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	err = gopacket.SerializeLayers(buf, opts, &eth, &arp)
	if err != nil {
		return false, 0, fmt.Errorf("failed to serialize ARP packet: %w", err)
	}

	// Send ARP request
	startTime := time.Now()
	err = handle.WritePacketData(buf.Bytes())
	if err != nil {
		return false, 0, fmt.Errorf("failed to send ARP packet: %w", err)
	}

	// Set a timeout for receiving the response
	timeoutChan := time.After(options.Timeout)
	
	// Create packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true
	
	// Read packets from the capture handle
	for {
		select {
		case <-ctx.Done():
			return false, 0, ctx.Err()
			
		case <-timeoutChan:
			return false, 0, fmt.Errorf("ARP timeout for %s", target)
			
		case packet, ok := <-packetSource.Packets():
			if !ok {
				return false, 0, fmt.Errorf("packet source closed")
			}
			
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			
			arpPacket, ok := arpLayer.(*layers.ARP)
			if !ok || arpPacket.Operation != layers.ARPReply {
				continue
			}
			
			// Check if this is the reply we're looking for
			if net.IP(arpPacket.SourceProtAddress).Equal(targetIP) {
				latency := time.Since(startTime)
				return true, latency, nil
			}
		}
	}
}

// tcpSynDiscover performs TCP SYN scanning for host discovery
func (e *Engine) tcpSynDiscover(ctx context.Context, target string, options *DiscoveryOptions) (bool, time.Duration, error) {
	if len(options.TCPPorts) == 0 {
		return false, 0, fmt.Errorf("no TCP ports specified for SYN discovery")
	}

	// Find appropriate interface
	var iface *net.Interface
	var err error

	if options.Interface != "" {
		iface, err = net.InterfaceByName(options.Interface)
		if err != nil {
			return false, 0, fmt.Errorf("failed to find interface %s: %w", options.Interface, err)
		}
	}

	// Parse target IP
	targetIP := net.ParseIP(target).To4()
	if targetIP == nil {
		return false, 0, fmt.Errorf("invalid IPv4 target: %s", target)
	}

	// Open packet capture handle
	handle, err := pcap.OpenLive(iface.Name, 1600, true, options.Timeout)
	if err != nil {
		return false, 0, fmt.Errorf("failed to open pcap handle: %w", err)
	}
	defer handle.Close()

	// Set BPF filter to only capture relevant TCP packets
	// Filter for SYN-ACK or RS

