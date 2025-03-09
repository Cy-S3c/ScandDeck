# ScandDeck

![ScandDeck Logo](docs/images/logo.png) *(Coming Soon)*

[![Go Report Card](https://goreportcard.com/badge/github.com/v0rt3x/ScandDeck)](https://goreportcard.com/report/github.com/v0rt3x/ScandDeck)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0--alpha-orange)](https://github.com/v0rt3x/ScandDeck/releases)

**ScandDeck** is a next-generation network scanning framework built for speed, efficiency, and insight. It goes beyond traditional scanners by providing a comprehensive, structured approach to network discovery and analysis.

## 🌟 Features

### Current Features (Phase 1)
- **Lightning-Fast Scanning**: Engineered from the ground up in Go for maximum performance
- **Intelligent Host Discovery**: Rapidly identify live hosts within network ranges using multiple techniques
- **High-Speed Port Scanning**: Scan all 65,535 ports faster than traditional tools
- **Service & Version Detection**: Accurately identify services and their versions
- **Structured Output**: Well-organized, parsable results for better analysis and integration
- **Parallel Execution**: Optimized multi-core processing for maximum efficiency
- **Minimal Footprint**: Efficient resource usage even during intensive scans

### Coming Soon
- **Vulnerability Correlation**: Automatic matching of detected services with known CVEs
- **Custom Scripting Engine**: Define custom scan behaviors for specific targets
- **Distributed Scanning**: Coordinate scanning across multiple agents
- **Web Interface**: Intuitive dashboard for scan management and visualization
- **Extensive Plugin System**: Easily extend functionality with custom modules

## 🏛️ Architecture

ScandDeck follows a modular architecture designed for performance, extensibility, and maintainability:

```
ScandDeck/
├── cmd/                  # Command-line applications
│   └── scandeck/         # Main application entry point
├── internal/             # Private application code
│   ├── discovery/        # Host discovery implementations
│   ├── portscan/         # Port scanning engine
│   ├── service/          # Service detection logic
│   ├── report/           # Results formatting and output
│   └── util/             # Internal utilities
├── pkg/                  # Public libraries
│   ├── scanner/          # Core scanning primitives
│   ├── target/           # Target management
│   ├── result/           # Result data structures
│   └── config/           # Configuration handling
└── docs/                 # Documentation
```

### Core Components

1. **Scanning Engine**: High-performance, concurrent scanning implementation
2. **Discovery Module**: Multiple strategies for host discovery
3. **Port Scanner**: Advanced port detection with adaptive timing
4. **Service Analyzer**: Sophisticated service fingerprinting
5. **Result Processor**: Structured data collection and organization
6. **API Layer**: Interfaces for extending and integrating with the framework

## 🚀 Installation

### Prerequisites
- Go 1.18 or later
- libpcap development files
- Root/Administrator privileges (for raw socket operations)

### From Source
```bash
# Clone the repository
git clone https://github.com/v0rt3x/ScandDeck.git
cd ScandDeck

# Install dependencies
go mod download

# Build the binary
go build -o scandeck ./cmd/scandeck

# Optional: Install system-wide
sudo mv scandeck /usr/local/bin/
```

### Using Go Install
```bash
go install github.com/v0rt3x/ScandDeck/cmd/scandeck@latest
```

### Docker (Coming Soon)
```bash
docker pull v0rt3x/scandeck:latest
docker run --net=host v0rt3x/scandeck scan -t 192.168.1.0/24
```

## 📊 Usage Examples

### Basic Network Scan
```bash
# Scan a single host
scandeck scan -t 10.0.0.1

# Scan a network range
scandeck scan -t 192.168.1.0/24

# Scan multiple targets
scandeck scan -t 10.0.0.1,10.0.0.2,10.0.0.5-10
```

### Port-Specific Scanning
```bash
# Scan specific ports
scandeck scan -t 10.0.0.0/24 -p 22,80,443,3389

# Scan port ranges
scandeck scan -t 10.0.0.1 -p 1-1000

# Scan top ports
scandeck scan -t 10.0.0.1 --top-ports 100
```

### Advanced Options
```bash
# Adjust scan intensity (1-5, where 5 is most aggressive)
scandeck scan -t 192.168.1.0/24 --intensity 4

# Output formats
scandeck scan -t 10.0.0.1 --output-format json --output scan-results.json

# Service detection
scandeck scan -t 10.0.0.1 --service-detection deep

# Run specific modules only
scandeck scan -t 10.0.0.1 --modules discovery,portscan --skip service-detection
```

### Scan Profiles
```bash
# Use predefined scan profiles
scandeck scan -t 10.0.0.1 --profile quick
scandeck scan -t 10.0.0.1 --profile thorough
scandeck scan -t 10.0.0.1 --profile stealth
```

## 🔍 Sample Output

```json
{
  "scan_id": "b8f3e0a9-4f7e-4a0b-8d1c-53a9e4a3f6e2",
  "timestamp": "2023-04-12T15:23:47Z",
  "scan_duration": 12.45,
  "targets": {
    "10.0.0.1": {
      "status": "up",
      "discovery_method": "tcp_syn",
      "latency_ms": 3.2,
      "ports": {
        "22": {
          "state": "open",
          "service": "ssh",
          "version": "OpenSSH 8.2p1 Ubuntu 4ubuntu0.5",
          "confidence": 0.98
        },
        "80": {
          "state": "open",
          "service": "http",
          "version": "nginx 1.18.0",
          "confidence": 0.95,
          "banner": "nginx/1.18.0 (Ubuntu)"
        }
      },
      "os_detection": {
        "name": "Ubuntu",
        "version": "20.04",
        "confidence": 0.85
      }
    }
  }
}
```

## 🛣️ Development Roadmap

### Phase 1 (Current): Core Scanning Capabilities
- [x] Project structure and architecture
- [ ] High-performance host discovery
- [ ] Concurrent port scanning engine
- [ ] Basic service detection
- [ ] Command-line interface
- [ ] Structured output formats

### Phase 2: Enhanced Service Analysis
- [ ] Advanced service fingerprinting
- [ ] Banner grabbing improvements
- [ ] OS detection
- [ ] Application protocol implementation
- [ ] Configuration analysis

### Phase 3: Intelligence & Correlation
- [ ] Vulnerability database integration
- [ ] Exploit suggestion
- [ ] Risk scoring
- [ ] Extended service profiling
- [ ] Behavior-based detection

### Phase 4: Usability & Integration
- [ ] Web dashboard
- [ ] Report generation
- [ ] API for third-party integration
- [ ] Distributed scanning
- [ ] Continuous monitoring

## 🤝 Contributing

Contributions are welcome! Please see our [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to submit pull requests, report issues, or request features.

## 📜 License

ScandDeck is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- [Project Website](https://github.com/v0rt3x/ScandDeck)
- [Documentation](https://github.com/v0rt3x/ScandDeck/wiki)
- [Issue Tracker](https://github.com/v0rt3x/ScandDeck/issues)

