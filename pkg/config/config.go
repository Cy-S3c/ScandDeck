package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the main configuration structure for ScandDeck
type Config struct {
	// General settings
	General GeneralConfig `json:"general" yaml:"general"`
	
	// Scan settings
	Scan ScanConfig `json:"scan" yaml:"scan"`
	
	// Output settings
	Output OutputConfig `json:"output" yaml:"output"`
	
	// Performance settings
	Performance PerformanceConfig `json:"performance" yaml:"performance"`
}

// GeneralConfig contains general application settings
type GeneralConfig struct {
	Verbose    bool   `json:"verbose" yaml:"verbose"`
	Debug      bool   `json:"debug" yaml:"debug"`
	LogFile    string `json:"log_file" yaml:"log_file"`
	ConfigPath string `json:"config_path" yaml:"config_path"`
}

// ScanConfig contains settings related to the scanning behavior
type ScanConfig struct {
	Targets     []string `json:"targets" yaml:"targets"`
	PortRanges  []string `json:"port_ranges" yaml:"port_ranges"`
	Timeout     int      `json:"timeout" yaml:"timeout"`             // In seconds
	Retries     int      `json:"retries" yaml:"retries"`
	ScanType    string   `json:"scan_type" yaml:"scan_type"`         // syn, connect, etc.
	ServiceScan bool     `json:"service_scan" yaml:"service_scan"`   // Whether to perform service detection
	AggressiveMode bool   `json:"aggressive_mode" yaml:"aggressive_mode"`
	ExcludeHosts []string `json:"exclude_hosts" yaml:"exclude_hosts"`
}

// OutputConfig contains settings related to result output
type OutputConfig struct {
	Format      string `json:"format" yaml:"format"`           // json, xml, yaml, etc.
	OutputFile  string `json:"output_file" yaml:"output_file"` // Path to output file
	Quiet       bool   `json:"quiet" yaml:"quiet"`             // No stdout output
	ShowClosed  bool   `json:"show_closed" yaml:"show_closed"` // Show closed ports in output
	ReportTemplate string `json:"report_template" yaml:"report_template"` // Custom report template
}

// PerformanceConfig contains settings related to scan performance
type PerformanceConfig struct {
	Concurrency     int  `json:"concurrency" yaml:"concurrency"`           // Number of concurrent scanning goroutines
	PacketsPerSecond int  `json:"packets_per_second" yaml:"packets_per_second"` // Rate limiting
	EnableAutoTuning bool `json:"enable_auto_tuning" yaml:"enable_auto_tuning"` // Auto-adjust performance settings
	WorkerPoolSize   int  `json:"worker_pool_size" yaml:"worker_pool_size"`     // Size of worker pools
	BatchSize        int  `json:"batch_size" yaml:"batch_size"`                 // Batch size for processing
}

// DefaultConfig returns a config with default values
func DefaultConfig() *Config {
	return &Config{
		General: GeneralConfig{
			Verbose:    false,
			Debug:      false,
			LogFile:    "",
			ConfigPath: "",
		},
		Scan: ScanConfig{
			Targets:       []string{},
			PortRanges:    []string{"1-1024"},
			Timeout:       5,
			Retries:       2,
			ScanType:      "syn",
			ServiceScan:   true,
			AggressiveMode: false,
			ExcludeHosts:  []string{},
		},
		Output: OutputConfig{
			Format:     "json",
			OutputFile: "",
			Quiet:      false,
			ShowClosed: false,
			ReportTemplate: "",
		},
		Performance: PerformanceConfig{
			Concurrency:     100,
			PacketsPerSecond: 5000,
			EnableAutoTuning: true,
			WorkerPoolSize:   10,
			BatchSize:        1000,
		},
	}
}

// LoadFromFile loads configuration from a JSON or YAML file
func (c *Config) LoadFromFile(filePath string) error {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	ext := filepath.Ext(filePath)
	switch ext {
	case ".json":
		if err := json.Unmarshal(data, c); err != nil {
			return fmt.Errorf("failed to parse JSON config: %w", err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, c); err != nil {
			return fmt.Errorf("failed to parse YAML config: %w", err)
		}
	default:
		return fmt.Errorf("unsupported config file format: %s", ext)
	}

	return nil
}

// SaveToFile saves the current configuration to a file in JSON or YAML format
func (c *Config) SaveToFile(filePath string) error {
	var data []byte
	var err error

	ext := filepath.Ext(filePath)
	switch ext {
	case ".json":
		data, err = json.MarshalIndent(c, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal config to JSON: %w", err)
		}
	case ".yaml", ".yml":
		data, err = yaml.Marshal(c)
		if err != nil {
			return fmt.Errorf("failed to marshal config to YAML: %w", err)
		}
	default:
		return fmt.Errorf("unsupported config file format: %s", ext)
	}

	if err := ioutil.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config to file: %w", err)
	}

	return nil
}

// MergeCommandLine merges command-line parameters into the configuration
// The params map contains parameter names and values from command line
func (c *Config) MergeCommandLine(params map[string]interface{}) {
	// Example implementation - this would need to be customized based on actual CLI parameters
	if verbose, ok := params["verbose"].(bool); ok {
		c.General.Verbose = verbose
	}
	
	if debug, ok := params["debug"].(bool); ok {
		c.General.Debug = debug
	}
	
	if logFile, ok := params["log-file"].(string); ok && logFile != "" {
		c.General.LogFile = logFile
	}
	
	if targets, ok := params["targets"].([]string); ok && len(targets) > 0 {
		c.Scan.Targets = targets
	}
	
	if portRanges, ok := params["port-ranges"].([]string); ok && len(portRanges) > 0 {
		c.Scan.PortRanges = portRanges
	}
	
	// and so on for other parameters...
}

// Validate validates the configuration values
func (c *Config) Validate() error {
	// Validate there's at least one target
	if len(c.Scan.Targets) == 0 {
		return fmt.Errorf("no scan targets specified")
	}
	
	// Validate port ranges
	if len(c.Scan.PortRanges) == 0 {
		return fmt.Errorf("no port ranges specified")
	}
	
	// Validate timeout values
	if c.Scan.Timeout <= 0 {
		return fmt.Errorf("invalid timeout value: must be greater than 0")
	}
	
	// Validate performance settings
	if c.Performance.Concurrency <= 0 {
		return fmt.Errorf("invalid concurrency value: must be greater than 0")
	}
	
	if c.Performance.PacketsPerSecond <= 0 {
		return fmt.Errorf("invalid packets per second value: must be greater than 0")
	}
	
	return nil
}

// GenerateExampleConfig creates an example configuration file
func GenerateExampleConfig(filePath string) error {
	config := DefaultConfig()
	
	// Add some example values
	config.Scan.Targets = []string{"192.168.1.0/24", "10.0.0.1-10.0.0.100"}
	config.Scan.PortRanges = []string{"1-1000", "8080", "9000-9100"}
	
	return config.SaveToFile(filePath)
}

