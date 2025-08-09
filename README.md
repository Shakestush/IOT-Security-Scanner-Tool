
# IoT Security Scanner 🛡️

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Kali%20Linux-purple.svg)](https://kali.org)
[![Security](https://img.shields.io/badge/security-penetration%20testing-red.svg)](https://github.com/yourusername/iot-security-scanner)

A comprehensive Python-based security assessment tool designed to identify, analyze, and report vulnerabilities in IoT devices across network environments. Built specifically for security professionals and penetration testers using Kali Linux.

## 📋 Table of Contents

- [Features](#-features)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Usage](#-usage)
- [Examples](#-examples)
- [Output](#-output)
- [Configuration](#-configuration)
- [Contributing](#-contributing)
- [Legal Disclaimer](#-legal-disclaimer)
- [License](#-license)

## 🚀 Features

### Core Capabilities
- **🔍 Network Discovery**: Automatic device discovery using ARP scanning.
- **🔌 Port Scanning**: Multi-threaded port scanning with intelligent service detection
- **🎯 IoT Device Identification**: Smart identification of IoT device types and manufacturers
- **🔐 Vulnerability Assessment**: Comprehensive security analysis including:
  - Default credential detection
  - Unencrypted service identification
  - Open port analysis
  - Service-specific vulnerability checks
- **📊 Professional Reporting**: Detailed reports in JSON format and color-coded console output
- **⚡ High Performance**: Multi-threaded scanning with configurable performance settings

### Supported IoT Device Types
- **📹 IP Cameras**: Axis, Hikvision, Dahua, Foscam, D-Link
- **🌐 Network Equipment**: Routers, switches, access points
- **🏠 Smart Home Devices**: Nest, Ring, Philips Hue, SmartThings
- **🏭 Industrial IoT**: SCADA systems, PLCs, industrial sensors
- **🖨️ Network Printers**: HP, Canon, Epson, Brother
- **📺 Smart TVs**: Samsung, LG, Sony, Roku

## ⚡ Quick Start

### One-Command Installation (Kali Linux)
```bash
curl -sSL https://raw.githubusercontent.com/yourusername/iot-security-scanner/main/deploy.sh | bash
```

### Quick Scan
```bash
cd ~/iot-security-scanner
python3 iot_scanner.py -n 192.168.1.0/24
```

## 🛠️ Installation

### Automated Installation (Recommended)

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/iot-security-scanner.git
   cd iot-security-scanner
   ```

2. **Run the deployment script**:
   ```bash
   chmod +x deploy.sh
   ./deploy.sh
   ```

### Manual Installation

<details>
<summary>Click to expand manual installation steps</summary>

1. **Install system dependencies**:
   ```bash
   sudo apt update
   sudo apt install -y python3 python3-pip python3-dev python3-venv nmap masscan \
                       git curl wget build-essential libpcap-dev libssl-dev libffi-dev
   ```

2. **Create virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Python packages**:
   ```bash
   pip install -r requirements.txt
   ```

</details>

### Requirements

- **Operating System**: Kali Linux (recommended), Ubuntu 20.04+, Debian 10+
- **Python**: 3.7 or higher
- **Memory**: Minimum 2GB RAM
- **Network**: Administrative privileges for network scanning
- **Dependencies**: Listed in `requirements.txt`

## 📖 Usage

### Command Line Options

```bash
python3 iot_scanner.py [OPTIONS]

Options:
  -n, --network TEXT     Network range to scan (e.g., 192.168.1.0/24) [REQUIRED]
  -o, --output TEXT      Output file for JSON report (optional)
  -v, --verbose          Enable verbose output
  -h, --help             Show help message
```

### Basic Usage Examples

**Simple network scan**:
```bash
python3 iot_scanner.py -n 192.168.1.0/24
```

**Scan with JSON report output**:
```bash
python3 iot_scanner.py -n 10.0.0.0/24 -o security_assessment.json
```

**Verbose scanning for detailed information**:
```bash
python3 iot_scanner.py -n 172.16.0.0/16 -v -o detailed_report.json
```

### Using Utility Scripts

If you used the automated installation, additional helper scripts are available:

```bash
# Run scanner with helper script
./run_scanner.sh -n 192.168.1.0/24 -o report.json

# Discover network ranges
./network_discovery.sh

# Update dependencies
./update_scanner.sh
```

## 🔍 Examples

### Example 1: Home Network Assessment
```bash
# Scan typical home network
python3 iot_scanner.py -n 192.168.1.0/24 -o home_security_report.json

# Results will show smart TVs, cameras, routers, and other IoT devices
```

### Example 2: Corporate Network IoT Discovery
```bash
# Scan corporate network range
python3 iot_scanner.py -n 10.0.0.0/8 -v -o corporate_iot_assessment.json

# Comprehensive scan of large network with verbose output
```

### Example 3: Targeted IoT Subnet
```bash
# Focus on specific IoT subnet
python3 iot_scanner.py -n 192.168.100.0/24 -o iot_devices_report.json
```

## 📊 Output

### Console Output
The scanner provides real-time, color-coded console output:

```
╔══════════════════════════════════════════════════════════╗
║             IoT SECURITY ASSESSMENT REPORT              ║
╚══════════════════════════════════════════════════════════╝
Scan Time: 2025-01-15T10:30:00.123456
Total Devices Scanned: 12

RISK SUMMARY:
High Risk Vulnerabilities: 3
Medium Risk Vulnerabilities: 7
Low Risk Vulnerabilities: 2

DETAILED FINDINGS:
[Device 1]
IP Address: 192.168.1.100
MAC Address: 00:12:34:56:78:90
Vendor: Hikvision
Device Type: IP Camera
Open Ports: [80, 554, 8000]
Vulnerabilities:
  • [HIGH] Default Credentials
    Port: 80
    Details: Default credentials found: [('admin', 'admin')]
  • [MEDIUM] Unencrypted Services
    Port: 554
    Details: RTSP service running without encryption
```

### JSON Report Format
```json
{
  "scan_time": "2025-01-15T10:30:00.123456",
  "total_devices": 12,
  "summary": {
    "high_risk": 3,
    "medium_risk": 7,
    "low_risk": 2
  },
  "devices": [
    {
      "ip": "192.168.1.100",
      "mac": "00:12:34:56:78:90",
      "vendor": "Hikvision",
      "device_type": "IP Camera",
      "confidence": 85,
      "open_ports": [80, 554, 8000],
      "services": {
        "80": "HTTP/1.1 Server: lighttpd",
        "554": "RTSP/1.0 Server: Hikvision"
      },
      "vulnerabilities": [
        {
          "type": "Default Credentials",
          "severity": "HIGH",
          "port": 80,
          "details": "Default credentials found: [('admin', 'admin')]",
          "cve": "N/A"
        }
      ]
    }
  ]
}
```

## ⚙️ Configuration

### Custom Configuration File

Create a `config.json` file to customize scanner behavior:

```json
{
  "scan_settings": {
    "timeout": 3,
    "max_threads": 100,
    "default_ports": [21, 22, 23, 53, 80, 443, 554, 1883, 5683, 8080, 8443, 9999],
    "extended_ports": true,
    "service_detection": true,
    "vulnerability_checks": true
  },
  "output_settings": {
    "format": "json",
    "include_timestamps": true,
    "verbose": false
  },
  "network_settings": {
    "interface": "auto",
    "source_port": "random"
  }
}
```

### Performance Tuning

For large networks, adjust these parameters:

```python
# In iot_scanner.py
self.common_iot_ports = [21, 22, 23, 53, 80, 443, 554, 1883, 5683, 8080, 8443, 9999]

# Thread pool size (default: 50)
with ThreadPoolExecutor(max_workers=100) as executor:
```

## 🔧 Troubleshooting

### Common Issues

<details>
<summary>Permission Errors</summary>

```bash
# Run with sudo for network scanning capabilities
sudo python3 iot_scanner.py -n 192.168.1.0/24
```

</details>

<details>
<summary>Import Errors</summary>

```bash
# Ensure virtual environment is activated
source venv/bin/activate
pip install -r requirements.txt
```

</details>

<details>
<summary>Network Interface Issues</summary>

```bash
# Check available interfaces
ip link show

# Bring interface up if needed
sudo ip link set eth0 up
```

</details>

### Performance Optimization

```bash
# Increase file descriptor limits
ulimit -n 65536

# Optimize network buffers
sudo sysctl -w net.core.rmem_max=134217728
```

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/new-vulnerability-check`
3. **Make your changes** and add tests if applicable
4. **Commit your changes**: `git commit -am 'Add new vulnerability check'`
5. **Push to the branch**: `git push origin feature/new-vulnerability-check`
6. **Create a Pull Request**

### Development Guidelines

- Follow PEP 8 coding standards
- Add docstrings to all functions
- Include unit tests for new features
- Update documentation as needed

### Adding New Vulnerability Checks

```python
def custom_vulnerability_check(self, device):
    """Template for adding custom vulnerability checks"""
    vulnerabilities = []
    
    # Your vulnerability logic here
    
    return vulnerabilities
```

## 📝 Roadmap

- [ ] **Web Interface**: Browser-based dashboard for scan management
- [ ] **Database Integration**: Store and track scan results over time
- [ ] **Advanced Reporting**: PDF reports with executive summaries
- [ ] **API Integration**: Connect with external threat intelligence feeds
- [ ] **Custom Plugins**: Plugin architecture for extending functionality
- [ ] **Distributed Scanning**: Support for scanning from multiple locations
- [ ] **Real-time Monitoring**: Continuous monitoring capabilities
- [ ] **Machine Learning**: AI-powered device classification and anomaly detection

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [Usage Examples](docs/examples.md)
- [API Reference](docs/api.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Contributing Guide](CONTRIBUTING.md)

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/iot-security-scanner/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/iot-security-scanner/discussions)
- **Security Issues**: Please report security vulnerabilities privately to [security@yoursite.com](mailto:security@yoursite.com)

## ⚖️ Legal Disclaimer

**IMPORTANT**: This tool is designed for legitimate security testing and research purposes only.

### Responsible Use Guidelines

- ✅ **DO**: Use on networks you own or have explicit permission to test
- ✅ **DO**: Follow responsible disclosure practices for vulnerabilities found
- ✅ **DO**: Comply with all applicable laws and regulations
- ❌ **DON'T**: Use for unauthorized network scanning or malicious purposes
- ❌ **DON'T**: Access systems without proper authorization
- ❌ **DON'T**: Use for any illegal activities

### Legal Compliance

Users are responsible for ensuring compliance with:
- Local and international laws
- Corporate policies and procedures
- Ethical hacking guidelines
- Data protection regulations (GDPR, CCPA, etc.)

The developers of this tool are not responsible for any misuse or illegal activities performed with this software.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 IoT Security Scanner Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

## 🙏 Acknowledgments

- **Security Research Community** for vulnerability databases and testing methodologies
- **Open Source Projects**: Scapy, Nmap, and other network security tools
- **Contributors** who help improve and maintain this project
- **Kali Linux Team** for providing the excellent penetration testing platform

## 📊 Project Statistics

![GitHub Stars](https://img.shields.io/github/stars/yourusername/iot-security-scanner?style=social)
![GitHub Forks](https://img.shields.io/github/forks/yourusername/iot-security-scanner?style=social)
![GitHub Issues](https://img.shields.io/github/issues/yourusername/iot-security-scanner)
![GitHub Last Commit](https://img.shields.io/github/last-commit/yourusername/iot-security-scanner)

---

<div align="center">

**Made with ❤️ by security professionals, for security professionals**

[⭐ Star this project](https://github.com/yourusername/iot-security-scanner/stargazers) | [🐛 Report Bug](https://github.com/yourusername/iot-security-scanner/issues) | [💡 Request Feature](https://github.com/yourusername/iot-security-scanner/issues)

</div>
