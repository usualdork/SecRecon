# HTTP vs HTTPS Analyzer Documentation

## Overview
The HTTP vs HTTPS Analyzer is a specialized tool designed to systematically evaluate HTTP and HTTPS implementation differences across web domains. It helps security professionals identify potential security vulnerabilities related to insecure protocol usage, improper redirects, and certificate issues. The tool provides comprehensive insights into how websites handle both HTTP and HTTPS protocols.

## Features
- **Protocol Accessibility Analysis**: Determines if domains are accessible via HTTP, HTTPS, or both
- **Redirect Validation**: Identifies and validates HTTP to HTTPS redirects
- **Certificate Verification**: Checks SSL/TLS certificate validity and configuration
- **DNS Resolution Verification**: Confirms proper DNS resolution for target domains
- **Endpoint Response Characteristics**: Analyzes response codes, headers, and content
- **Comprehensive Reporting**: Generates detailed CSV reports and console summaries
- **Batch Processing**: Efficiently processes multiple domains from input files

## Installation

The HTTP vs HTTPS Analyzer is included in the SecRecon framework. The tool requires Python 3.6+ and the following dependencies:

```bash
pip install requests urllib3
```

## Usage

### Basic Usage

```bash
python httpvshttps.py -f domains.txt
```

Where `domains.txt` contains a list of domains to analyze (one per line).

### Analyzing a Single Domain

```bash
python httpvshttps.py -d example.com
```

### Command Line Options

```
usage: httpvshttps.py [-h] (-f FILE | -d DOMAIN) [-o OUTPUT] [-t TIMEOUT] [-s]

HTTP Protocol Accessibility Analyzer: Systematically evaluate HTTP vs HTTPS availability

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Input file containing domains (one per line)
  -d DOMAIN, --domain DOMAIN
                        Single domain to analyze
  -o OUTPUT, --output OUTPUT
                        Output CSV file for results
  -t TIMEOUT, --timeout TIMEOUT
                        Request timeout in seconds (default: 5)
  -s, --ssl             Verify SSL certificates
```

## Output Format

### Console Output
The tool provides a detailed summary in the console, including:
- Total domains analyzed
- DNS resolution statistics
- HTTP protocol status breakdown
- HTTPS protocol status breakdown
- List of domains with direct HTTP access (potential security concern)

### CSV Report
When using the `-o` option, the tool generates a CSV file with the following fields:
- domain: The analyzed domain name
- dns_resolution_status: Whether DNS resolution succeeded
- ip_address: Resolved IP address
- http_direct_access: Whether HTTP content is directly accessible
- http_response_code: HTTP response status code
- http_redirect_to_https: Whether HTTP redirects to HTTPS
- https_accessible: Whether HTTPS is accessible
- https_response_code: HTTPS response status code

## Implementation Details

### HTTP Protocol Analysis
The tool performs a comprehensive analysis of HTTP protocol implementation by:
1. Checking DNS resolution for the target domain
2. Testing HTTP accessibility with redirect behavior analysis
3. Identifying if HTTP content is directly accessible (potential security issue)
4. Detecting if proper HTTP to HTTPS redirects are implemented

### HTTPS Protocol Analysis
The HTTPS analysis includes:
1. Testing HTTPS accessibility
2. Validating SSL/TLS certificate configuration
3. Analyzing HTTPS response characteristics

### Security Implications
The tool helps identify several security concerns:
- Domains serving content directly over HTTP (unencrypted)
- Missing or improper HTTP to HTTPS redirects
- SSL/TLS certificate issues
- Inconsistent protocol implementation

## Best Practices
Based on the analysis results, security professionals should recommend:
1. Implementing proper HTTP to HTTPS redirects
2. Ensuring valid SSL/TLS certificates
3. Configuring HSTS (HTTP Strict Transport Security)
4. Disabling direct HTTP content access
