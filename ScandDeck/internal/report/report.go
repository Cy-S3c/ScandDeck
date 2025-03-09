package report

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// ScanResult represents the overall result of a scan operation
type ScanResult struct {
	StartTime    time.Time      `json:"start_time" xml:"start_time"`
	EndTime      time.Time      `json:"end_time" xml:"end_time"`
	Duration     time.Duration  `json:"duration" xml:"duration"`
	TargetSpec   string         `json:"target_spec" xml:"target_spec"`
	Hosts        []*HostResult  `json:"hosts" xml:"hosts>host"`
	TotalHosts   int            `json:"total_hosts" xml:"total_hosts"`
	UpHosts      int            `json:"up_hosts" xml:"up_hosts"`
	DownHosts    int            `json:"down_hosts" xml:"down_hosts"`
	ScanOptions  *ScanOptions   `json:"scan_options" xml:"scan_options"`
	Summary      *ScanSummary   `json:"summary" xml:"summary"`
}

// ScanOptions represents the options used for the scan
type ScanOptions struct {
	PortRanges     []string `json:"port_ranges" xml:"port_ranges>range"`
	ScanSpeed      string   `json:"scan_speed" xml:"scan_speed"`
	Timeout        int      `json:"timeout" xml:"timeout"`
	ScanType       string   `json:"scan_type" xml:"scan_type"`
	ServiceScan    bool     `json:"service_scan" xml:"service_scan"`
	DiscoveryMode  string   `json:"discovery_mode" xml:"discovery_mode"`
	MaxConcurrency int      `json:"max_concurrency" xml:"max_concurrency"`
}

// ScanSummary provides overall statistics about the scan
type ScanSummary struct {
	TotalPorts      int            `json:"total_ports" xml:"total_ports"`
	OpenPorts       int            `json:"open_ports" xml:"open_ports"`
	ClosedPorts     int            `json:"closed_ports" xml:"closed_ports"`
	FilteredPorts   int            `json:"filtered_ports" xml:"filtered_ports"`
	ServicesFound   int            `json:"services_found" xml:"services_found"`
	PacketsSent     int            `json:"packets_sent" xml:"packets_sent"`
	PacketsReceived int            `json:"packets_received" xml:"packets_received"`
	ErrorCount      int            `json:"error_count" xml:"error_count"`
	Errors          []string       `json:"errors,omitempty" xml:"errors>error,omitempty"`
	ServiceStats    map[string]int `json:"service_stats,omitempty" xml:"service_stats>service,omitempty"`
}

// HostResult represents the scan result for a single host
type HostResult struct {
	IP        string        `json:"ip" xml:"ip"`
	Hostname  string        `json:"hostname,omitempty" xml:"hostname,omitempty"`
	Status    string        `json:"status" xml:"status"` // "up" or "down"
	Ports     []*PortResult `json:"ports,omitempty" xml:"ports>port,omitempty"`
	OpenPorts int           `json:"open_ports" xml:"open_ports"`
	RTT       time.Duration `json:"rtt,omitempty" xml:"rtt,omitempty"` // Round trip time
	LastSeen  time.Time     `json:"last_seen" xml:"last_seen"`
	MAC       string        `json:"mac,omitempty" xml:"mac,omitempty"`
	Vendor    string        `json:"vendor,omitempty" xml:"vendor,omitempty"`
}

// PortResult represents the scan result for a single port
type PortResult struct {
	Port      int            `json:"port" xml:"port"`
	Protocol  string         `json:"protocol" xml:"protocol"` // "tcp" or "udp"
	Status    string         `json:"status" xml:"status"`     // "open", "closed", or "filtered"
	Service   *ServiceResult `json:"service,omitempty" xml:"service,omitempty"`
	Reason    string         `json:"reason,omitempty" xml:"reason,omitempty"` // Reason for the state determination
	ScanTime  time.Duration  `json:"scan_time,omitempty" xml:"scan_time,omitempty"`
	Latency   time.Duration  `json:"latency,omitempty" xml:"latency,omitempty"`
}

// ServiceResult represents information about a detected service
type ServiceResult struct {
	Name        string            `json:"name" xml:"name"`
	Product     string            `json:"product,omitempty" xml:"product,omitempty"`
	Version     string            `json:"version,omitempty" xml:"version,omitempty"`
	ExtraInfo   string            `json:"extra_info,omitempty" xml:"extra_info,omitempty"`
	Fingerprint string            `json:"fingerprint,omitempty" xml:"fingerprint,omitempty"`
	Confidence  float64           `json:"confidence" xml:"confidence"`
	Method      string            `json:"method" xml:"method"` // How the service was detected
	Banner      string            `json:"banner,omitempty" xml:"banner,omitempty"`
	CPEs        []string          `json:"cpes,omitempty" xml:"cpes>cpe,omitempty"` // Common Platform Enumeration
	Metadata    map[string]string `json:"metadata,omitempty" xml:"metadata,omitempty"`
}

// Reporter interface defines methods for different output formatters
type Reporter interface {
	Generate(result *ScanResult) ([]byte, error)
}

// OutputWriter interface for different output destinations
type OutputWriter interface {
	Write(data []byte) error
	Close() error
}

// JSONReporter implements Reporter for JSON output
type JSONReporter struct {
	Pretty bool
}

// Generate generates a JSON representation of scan results
func (r *JSONReporter) Generate(result *ScanResult) ([]byte, error) {
	if r.Pretty {
		return json.MarshalIndent(result, "", "  ")
	}
	return json.Marshal(result)
}

// XMLReporter implements Reporter for XML output
type XMLReporter struct {
	Pretty bool
}

// Generate generates an XML representation of scan results
func (r *XMLReporter) Generate(result *ScanResult) ([]byte, error) {
	if r.Pretty {
		return xml.MarshalIndent(result, "", "  ")
	}
	return xml.Marshal(result)
}

// TextReporter implements Reporter for human-readable text output
type TextReporter struct {
	Verbose bool
}

// Generate generates a human-readable text representation of scan results
func (r *TextReporter) Generate(result *ScanResult) ([]byte, error) {
	var sb strings.Builder

	// Header
	sb.WriteString("═════════════════════════════════════════════\n")
	sb.WriteString("           SCANDECK SCAN REPORT              \n")
	sb.WriteString("═════════════════════════════════════════════\n\n")

	// Scan information
	sb.WriteString(fmt.Sprintf("Target:    %s\n", result.TargetSpec))
	sb.WriteString(fmt.Sprintf("Started:   %s\n", result.StartTime.Format(time.RFC1123)))
	sb.WriteString(fmt.Sprintf("Finished:  %s\n", result.EndTime.Format(time.RFC1123)))
	sb.WriteString(fmt.Sprintf("Duration:  %s\n\n", result.Duration))

	// Scan summary
	sb.WriteString(fmt.Sprintf("Hosts: %d total, %d up, %d down\n", result.TotalHosts, result.UpHosts, result.DownHosts))
	if result.Summary != nil {
		sb.WriteString(fmt.Sprintf("Ports: %d total, %d open, %d closed, %d filtered\n", 
			result.Summary.TotalPorts, 
			result.Summary.OpenPorts, 
			result.Summary.ClosedPorts, 
			result.Summary.FilteredPorts))
		sb.WriteString(fmt.Sprintf("Services: %d identified\n\n", result.Summary.ServicesFound))
	}

	// Host details
	sb.WriteString("HOST DETAILS\n")
	sb.WriteString("═════════════════════════════════════════════\n")
	
	for _, host := range result.Hosts {
		if host.Status == "down" && !r.Verbose {
			continue
		}

		hostname := host.IP
		if host.Hostname != "" {
			hostname = fmt.Sprintf("%s (%s)", host.Hostname, host.IP)
		}
		
		sb.WriteString(fmt.Sprintf("\nHOST: %s\n", hostname))
		sb.WriteString(fmt.Sprintf("STATUS: %s\n", strings.ToUpper(host.Status)))
		
		if host.MAC != "" {
			vendor := ""
			if host.Vendor != "" {
				vendor = fmt.Sprintf(" (%s)", host.Vendor)
			}
			sb.WriteString(fmt.Sprintf("MAC: %s%s\n", host.MAC, vendor))
		}
		
		if host.Status == "up" && len(host.Ports) > 0 {
			sb.WriteString("\nPORT      STATE    SERVICE     VERSION\n")
			sb.WriteString("-------------------------------------------\n")
			
			for _, port := range host.Ports {
				if !r.Verbose && port.Status != "open" {
					continue
				}
				
				service := "unknown"
				version := ""
				
				if port.Service != nil {
					service = port.Service.Name
					if port.Service.Product != "" {
						version = port.Service.Product
						if port.Service.Version != "" {
							version += " " + port.Service.Version
						}
					}
				}
				
				sb.WriteString(fmt.Sprintf("%-9s %-8s %-11s %s\n", 
					fmt.Sprintf("%d/%s", port.Port, port.Protocol),
					port.Status,
					service,
					version))
					
				// Banner information for verbose mode
				if r.Verbose && port.Service != nil && port.Service.Banner != "" {
					sb.WriteString(fmt.Sprintf("  |_ Banner: %s\n", formatBanner(port.Service.Banner)))
				}
			}
		} else if host.Status == "up" {
			sb.WriteString("No open ports found\n")
		}
		
		sb.WriteString("\n")
	}

	// Footer with additional information for verbose mode
	if r.Verbose && result.Summary != nil {
		sb.WriteString("═════════════════════════════════════════════\n")
		sb.WriteString("ADDITIONAL INFORMATION\n\n")
		
		if len(result.Summary.ServiceStats) > 0 {
			sb.WriteString("Service Statistics:\n")
			for service, count := range result.Summary.ServiceStats {
				sb.WriteString(fmt.Sprintf("  %-20s %d\n", service+":", count))
			}
			sb.WriteString("\n")
		}
		
		sb.WriteString(fmt.Sprintf("Network Traffic: %d packets sent, %d packets received\n", 
			result.Summary.PacketsSent, 
			result.Summary.PacketsReceived))
			
		if result.Summary.ErrorCount > 0 {
			sb.WriteString(fmt.Sprintf("\nErrors (%d):\n", result.Summary.ErrorCount))
			for _, err := range result.Summary.Errors {
				sb.WriteString(fmt.Sprintf("  - %s\n", err))
			}
		}
	}

	return []byte(sb.String()), nil
}

// Helper function to format banner information
func formatBanner(banner string) string {
	// Replace control characters and limit length
	banner = strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return ' '
		}
		return r
	}, banner)
	
	// Truncate if too long
	if len(banner) > 80 {
		return banner[:77] + "..."
	}
	return banner
}

// FileWriter implements OutputWriter for file output
type FileWriter struct {
	file *os.File
}

// NewFileWriter creates a new FileWriter
func NewFileWriter(filename string) (*FileWriter, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	return &FileWriter{file: file}, nil
}

// Write writes data to the file
func (w *FileWriter) Write(data []byte) error {
	_, err := w.file.Write(data)
	return err
}

// Close closes the file
func (w *FileWriter) Close() error {
	return w.file.Close()
}

// StdoutWriter implements OutputWriter for stdout
type StdoutWriter struct{}

// NewStdoutWriter creates a new StdoutWriter
func NewStdoutWriter() *StdoutWriter {
	return &StdoutWriter{}
}

// Write writes data to stdout
func (w *StdoutWriter) Write(data []byte) error {
	_, err := os.Stdout.Write(data)
	return err
}

// Close is a no-op for StdoutWriter
func (w *StdoutWriter) Close() error {
	return nil
}

// ReportManager handles generation and output of reports
type ReportManager struct {
	reporter Reporter
	writer   OutputWriter
}

// NewReportManager creates a new ReportManager with the specified reporter and writer
func NewReportManager(reporter Reporter, writer OutputWriter) *ReportManager {
	return &ReportManager{
		reporter: reporter,
		writer:   writer,
	}
}

// GenerateAndWrite generates a report and writes it to the configured output
func (m *ReportManager) GenerateAndWrite(result *ScanResult) error {
	data, err := m.reporter.Generate(result)
	if err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	if err := m.writer.Write(data); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	return nil
}

// Close closes the writer
func (m *ReportManager) Close() error {
	return m.writer.Close()
}

// NewReporter creates a new Reporter based on the specified format
func NewReporter(format string, pretty bool) (Reporter, error) {
	switch strings.ToLower(format) {
	case "json":
		return &JSONReporter{Pretty: pretty}, nil
	case "xml":
		return &XMLReporter{Pretty: pretty}, nil
	case "text":
		return &TextReporter{Verbose: pretty}, nil
	default:
		return nil, fmt.Errorf("unsupported report format: %s", format)
	}
}

// NewWriter creates a new OutputWriter based on the specified output
func NewWriter(output string) (Output

