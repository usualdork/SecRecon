# Port Scanner Documentation

## Overview
The Port Scanner is a Nmap-based scanner with web technology detection capabilities. It helps security professionals identify open ports, running services, and web technologies on target systems, providing valuable information for security assessments and penetration testing.

## Features
- **Service Discovery**: Identifies services running on open ports
- **Open Port Identification**: Detects open ports on target systems
- **Web Technology Fingerprinting**: Identifies web servers, frameworks, and technologies
- **Comprehensive Scan Reports**: Generates detailed reports with actionable findings
- **Multi-target Scanning**: Efficiently scans multiple targets in sequence

## Installation

The Port Scanner is included in the SecRecon framework. The tool requires Nmap to be installed on your system:

### Linux
```bash
sudo apt-get install nmap
```

### macOS
```bash
brew install nmap
```

### Windows
Download and install Nmap from: https://nmap.org/download.html

## Usage

### Basic Usage

```bash
python portlisting.py targetsport.txt
```

### Command Line Options

```
usage: portlisting.py [-h] [-o OUTPUT] [-t TIMEOUT] [-w WORKERS] [--nmap-path NMAP_PATH] [--aggressive] targets_file

Scan ports and detect web technologies

positional arguments:
  targets_file          File containing list of targets to scan (one per line)

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output Excel file (default: port_scan_results_YYYYMMDD_HHMMSS.xlsx)
  -t TIMEOUT, --timeout TIMEOUT
                        Scan timeout in seconds (default: 300)
  -w WORKERS, --workers WORKERS
                        Number of concurrent scans (default: 3)
  --nmap-path NMAP_PATH
                        Path to nmap executable
  --aggressive          Use more aggressive scanning techniques
```

## Input Format

Create a text file with targets to scan, one per line:

```
example.com
192.168.1.1
10.0.0.0/24
secondexample.com:80,443,8080
```

## Output

The tool generates an Excel report with the following information:

- **Target**: The scanned target (hostname or IP address)
- **Port**: The port number
- **Protocol**: The protocol (TCP/UDP)
- **State**: Port state (open, filtered, closed)
- **Service**: Identified service (e.g., http, ssh, ftp)
- **Version**: Service version information
- **Web Technology**: Detected web technologies (if applicable)
- **Notes**: Additional observations and security recommendations

## Scan Types

The Port Scanner performs several types of scans:

1. **Basic Port Scan**: Identifies open ports and services
2. **Service Version Detection**: Determines service versions running on open ports
3. **Web Technology Detection**: Identifies web technologies on HTTP/HTTPS ports
4. **OS Detection**: Attempts to identify the operating system (when run with elevated privileges)

## Best Practices

1. **Legal Compliance**: Only scan targets you have permission to test
2. **Scan Throttling**: Use the default worker count to avoid overwhelming target systems
3. **Timeout Adjustment**: Increase timeout for comprehensive scans of large networks
4. **Regular Scanning**: Perform periodic scans to identify new services and ports
5. **Validation**: Manually verify critical findings to eliminate false positives

## Troubleshooting

- **Nmap Not Found**: Specify the path to the Nmap executable with `--nmap-path`
- **Slow Scanning**: Adjust the timeout value with `-t` option
- **Permission Issues**: Run with appropriate privileges for complete scanning
- **False Positives**: Use the `--aggressive` option for more thorough scanning

## Integration with Other Tools

The Port Scanner works seamlessly with other SecRecon tools:

- Use **Subdomain Analyzer** to discover subdomains before port scanning
- Combine with **DAST Scanner** for comprehensive web application testing
- Use findings to guide **Credential Scanner** for targeted credential testing
