#!/usr/bin/env python3
"""
IoT Security Scanner Tool
A comprehensive security assessment tool for IoT devices
Author: Manasseh Mutugi
"""

import socket
import threading
import subprocess
import json
import argparse
import sys
import time
import requests
from datetime import datetime
import nmap
import scapy.all as scapy
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
import ssl
import warnings

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

class IoTSecurityScanner:
    def __init__(self):
        self.devices = []
        self.vulnerabilities = []
        self.common_iot_ports = [21, 22, 23, 53, 80, 443, 554, 1883, 5683, 8080, 8443, 9999]
        self.iot_signatures = {
            'cameras': ['axis', 'hikvision', 'dahua', 'foscam', 'dlink', 'netcam'],
            'routers': ['linksys', 'netgear', 'tplink', 'dlink', 'asus', 'belkin'],
            'smart_home': ['philips', 'nest', 'ring', 'ecobee', 'wemo', 'smartthings'],
            'industrial': ['schneider', 'siemens', 'rockwell', 'omron', 'modbus']
        }
        self.default_credentials = [
            ('admin', 'admin'), ('admin', 'password'), ('admin', '12345'),
            ('root', 'root'), ('root', 'admin'), ('user', 'user'),
            ('admin', ''), ('', 'admin'), ('', ''),
            ('guest', 'guest'), ('admin', 'admin123')
        ]
        
    def print_banner(self):
        """Display tool banner"""
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════╗
║                  IoT Security Scanner                    ║
║              Comprehensive IoT Assessment Tool           ║
╚══════════════════════════════════════════════════════════╝
{Colors.END}
        """
        print(banner)
    
    def discover_devices(self, network_range):
        """Discover devices on the network using ARP scanning"""
        print(f"{Colors.BLUE}[INFO]{Colors.END} Discovering devices on {network_range}...")
        
        try:
            # Create ARP request
            arp_request = scapy.ARP(pdst=network_range)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send request and receive response
            answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            
            devices = []
            for element in answered_list:
                device = {
                    'ip': element[1].psrc,
                    'mac': element[1].hwsrc,
                    'vendor': self.get_vendor(element[1].hwsrc)
                }
                devices.append(device)
            
            print(f"{Colors.GREEN}[SUCCESS]{Colors.END} Found {len(devices)} devices")
            return devices
            
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.END} ARP scan failed: {str(e)}")
            return []
    
    def get_vendor(self, mac_address):
        """Get vendor information from MAC address"""
        try:
            # Simple vendor lookup based on OUI
            oui = mac_address[:8].upper().replace(':', '')
            vendor_db = {
                '00:50:56': 'VMware',
                '08:00:27': 'VirtualBox',
                '00:0C:29': 'VMware',
                '00:1B:21': 'Intel',
                '00:E0:4C': 'Realtek'
            }
            return vendor_db.get(mac_address[:8].upper(), 'Unknown')
        except:
            return 'Unknown'
    
    def port_scan(self, target_ip, ports):
        """Perform port scan on target IP"""
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    return port
                sock.close()
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(scan_port, port) for port in ports]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        return sorted(open_ports)
    
    def service_detection(self, ip, port):
        """Detect service running on specific port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            
            # Send HTTP request for web services
            if port in [80, 8080, 8443]:
                request = b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n"
                sock.send(request)
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                return self.parse_http_response(response)
            
            # For other services, try to grab banner
            else:
                sock.send(b"\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                return banner.strip()
                
        except Exception as e:
            return f"Unknown service"
        finally:
            try:
                sock.close()
            except:
                pass
    
    def parse_http_response(self, response):
        """Parse HTTP response to extract server information"""
        lines = response.split('\n')
        server_info = "HTTP Service"
        
        for line in lines:
            if 'server:' in line.lower():
                server_info = line.split(':', 1)[1].strip()
                break
            elif 'apache' in line.lower():
                server_info = "Apache"
                break
            elif 'nginx' in line.lower():
                server_info = "Nginx"
                break
            elif 'iis' in line.lower():
                server_info = "IIS"
                break
        
        return server_info
    
    def check_default_credentials(self, ip, port):
        """Check for default credentials"""
        vulnerable_creds = []
        
        if port == 22:  # SSH
            for username, password in self.default_credentials[:5]:  # Limit SSH attempts
                if self.test_ssh_login(ip, username, password):
                    vulnerable_creds.append((username, password))
        
        elif port in [80, 8080]:  # HTTP
            for username, password in self.default_credentials:
                if self.test_http_login(ip, port, username, password):
                    vulnerable_creds.append((username, password))
        
        return vulnerable_creds
    
    def test_ssh_login(self, ip, username, password):
        """Test SSH login with credentials"""
        try:
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password, timeout=3)
            ssh.close()
            return True
        except:
            return False
    
    def test_http_login(self, ip, port, username, password):
        """Test HTTP basic authentication"""
        try:
            url = f"http://{ip}:{port}"
            response = requests.get(url, auth=(username, password), timeout=3, verify=False)
            return response.status_code == 200
        except:
            return False
    
    def identify_iot_device(self, ip, open_ports, services):
        """Identify if device is IoT and its type"""
        device_type = "Unknown"
        confidence = 0
        
        # Check for common IoT ports
        iot_port_matches = len([p for p in open_ports if p in self.common_iot_ports])
        if iot_port_matches > 0:
            confidence += iot_port_matches * 20
        
        # Check service banners for IoT signatures
        service_text = " ".join(services.values()).lower()
        for category, signatures in self.iot_signatures.items():
            for sig in signatures:
                if sig in service_text:
                    device_type = category
                    confidence += 30
                    break
        
        # Specific port patterns
        if 554 in open_ports:  # RTSP - likely camera
            device_type = "IP Camera"
            confidence += 40
        elif 1883 in open_ports:  # MQTT - IoT messaging
            device_type = "IoT Device (MQTT)"
            confidence += 35
        elif 5683 in open_ports:  # CoAP - IoT protocol
            device_type = "IoT Device (CoAP)"
            confidence += 35
        
        return device_type if confidence > 30 else "Standard Device", confidence
    
    def vulnerability_assessment(self, device):
        """Assess device for common vulnerabilities"""
        vulnerabilities = []
        
        # Check for default credentials
        for port in device['open_ports']:
            default_creds = self.check_default_credentials(device['ip'], port)
            if default_creds:
                vulnerabilities.append({
                    'type': 'Default Credentials',
                    'severity': 'HIGH',
                    'port': port,
                    'details': f"Default credentials found: {default_creds}",
                    'cve': 'N/A'
                })
        
        # Check for unencrypted services
        unencrypted_ports = [p for p in device['open_ports'] if p in [21, 23, 80, 1883]]
        if unencrypted_ports:
            vulnerabilities.append({
                'type': 'Unencrypted Services',
                'severity': 'MEDIUM',
                'port': unencrypted_ports,
                'details': 'Services running without encryption',
                'cve': 'N/A'
            })
        
        # Check for excessive open ports
        if len(device['open_ports']) > 10:
            vulnerabilities.append({
                'type': 'Excessive Open Ports',
                'severity': 'LOW',
                'port': 'Multiple',
                'details': f"{len(device['open_ports'])} open ports detected",
                'cve': 'N/A'
            })
        
        return vulnerabilities
    
    def generate_report(self, devices, output_file=None):
        """Generate comprehensive security report"""
        report = {
            'scan_time': datetime.now().isoformat(),
            'total_devices': len(devices),
            'devices': devices,
            'summary': {
                'high_risk': 0,
                'medium_risk': 0,
                'low_risk': 0
            }
        }
        
        # Calculate risk summary
        for device in devices:
            for vuln in device.get('vulnerabilities', []):
                if vuln['severity'] == 'HIGH':
                    report['summary']['high_risk'] += 1
                elif vuln['severity'] == 'MEDIUM':
                    report['summary']['medium_risk'] += 1
                else:
                    report['summary']['low_risk'] += 1
        
        # Print report to console
        self.print_report(report)
        
        # Save to file if specified
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n{Colors.GREEN}[SUCCESS]{Colors.END} Report saved to {output_file}")
        
        return report
    
    def print_report(self, report):
        """Print formatted report to console"""
        print(f"\n{Colors.BOLD}{'='*60}")
        print(f"             IoT SECURITY ASSESSMENT REPORT")
        print(f"{'='*60}{Colors.END}")
        print(f"Scan Time: {report['scan_time']}")
        print(f"Total Devices Scanned: {report['total_devices']}")
        print(f"\n{Colors.BOLD}RISK SUMMARY:{Colors.END}")
        print(f"{Colors.RED}High Risk Vulnerabilities: {report['summary']['high_risk']}{Colors.END}")
        print(f"{Colors.YELLOW}Medium Risk Vulnerabilities: {report['summary']['medium_risk']}{Colors.END}")
        print(f"{Colors.BLUE}Low Risk Vulnerabilities: {report['summary']['low_risk']}{Colors.END}")
        
        print(f"\n{Colors.BOLD}DETAILED FINDINGS:{Colors.END}")
        for i, device in enumerate(report['devices'], 1):
            print(f"\n{Colors.CYAN}[Device {i}]{Colors.END}")
            print(f"IP Address: {device['ip']}")
            print(f"MAC Address: {device['mac']}")
            print(f"Vendor: {device['vendor']}")
            print(f"Device Type: {device.get('device_type', 'Unknown')}")
            print(f"Open Ports: {device.get('open_ports', [])}")
            
            if device.get('vulnerabilities'):
                print(f"{Colors.BOLD}Vulnerabilities:{Colors.END}")
                for vuln in device['vulnerabilities']:
                    severity_color = Colors.RED if vuln['severity'] == 'HIGH' else Colors.YELLOW if vuln['severity'] == 'MEDIUM' else Colors.BLUE
                    print(f"  • {severity_color}[{vuln['severity']}]{Colors.END} {vuln['type']}")
                    print(f"    Port: {vuln['port']}")
                    print(f"    Details: {vuln['details']}")
            else:
                print(f"{Colors.GREEN}No vulnerabilities detected{Colors.END}")
    
    def scan_network(self, network_range, output_file=None):
        """Main scanning function"""
        print(f"{Colors.BOLD}Starting IoT Security Assessment...{Colors.END}")
        
        # Step 1: Device Discovery
        devices = self.discover_devices(network_range)
        
        if not devices:
            print(f"{Colors.RED}[ERROR]{Colors.END} No devices found. Check network range.")
            return
        
        # Step 2: Port Scanning and Service Detection
        for i, device in enumerate(devices, 1):
            print(f"\n{Colors.BLUE}[INFO]{Colors.END} Scanning device {i}/{len(devices)}: {device['ip']}")
            
            # Port scan
            open_ports = self.port_scan(device['ip'], self.common_iot_ports + [port for port in range(1, 1001) if port not in self.common_iot_ports])
            device['open_ports'] = open_ports
            
            if open_ports:
                print(f"  Open ports: {open_ports}")
                
                # Service detection
                services = {}
                for port in open_ports[:10]:  # Limit service detection to first 10 ports
                    service = self.service_detection(device['ip'], port)
                    services[port] = service
                
                device['services'] = services
                
                # Device identification
                device_type, confidence = self.identify_iot_device(device['ip'], open_ports, services)
                device['device_type'] = device_type
                device['confidence'] = confidence
                
                # Vulnerability assessment
                vulnerabilities = self.vulnerability_assessment(device)
                device['vulnerabilities'] = vulnerabilities
                
                if vulnerabilities:
                    print(f"  {Colors.RED}Vulnerabilities found: {len(vulnerabilities)}{Colors.END}")
                else:
                    print(f"  {Colors.GREEN}No vulnerabilities detected{Colors.END}")
            else:
                print(f"  No open ports found")
        
        # Step 3: Generate Report
        self.generate_report(devices, output_file)

def main():
    parser = argparse.ArgumentParser(description='IoT Security Scanner - Comprehensive IoT Device Assessment')
    parser.add_argument('-n', '--network', required=True, help='Network range to scan (e.g., 192.168.1.0/24)')
    parser.add_argument('-o', '--output', help='Output file for JSON report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    scanner = IoTSecurityScanner()
    scanner.print_banner()
    
    try:
        scanner.scan_network(args.network, args.output)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[INFO]{Colors.END} Scan interrupted by user")
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.END} {str(e)}")

if __name__ == "__main__":
    main()
