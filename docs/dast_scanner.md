# DAST Scanner Documentation

## Overview
The DAST Scanner (Dynamic Application Security Testing) is a comprehensive tool designed to perform in-depth scanning of web applications, identify vulnerable components, and generate professional reports. It helps security professionals assess the security posture of web applications through dynamic testing.

## Features
- **URL Batch Processing**: Scan multiple websites from a text file
- **Comprehensive Scanning**: Performs various security checks including:
  - SSL/TLS configuration
  - Security headers
  - Sensitive file exposure
  - HTTP method testing
  - Component vulnerability analysis
- **Advanced Scanning with OWASP ZAP**: Integration with ZAP for thorough vulnerability assessment
- **Component Analysis**: Identifies and checks frontend libraries/frameworks for known vulnerabilities
- **Professional Reporting**: Generates beautifully formatted Excel reports with:
  - Color-coded risk levels
  - Filterable tables
  - Summary statistics
  - Detailed vulnerability findings

## Installation

The DAST Scanner is included in the SecRecon framework. For advanced scanning features, you may need to install and configure OWASP ZAP:

```bash
python setup_zap.py
```

## Usage

### Basic Usage

```bash
python dast_scanner.py -i urls.txt -o security_report.xlsx
```

### Advanced Usage with ZAP Integration

```bash
python dast_scanner.py -i urls.txt --zap-proxy http://localhost:8080 --zap-api-key <your-api-key> --ignore-ssl
```

### Command Line Options

```
usage: dast_scanner.py [-h] -i INPUT_FILE [-o OUTPUT] [--zap-proxy ZAP_PROXY] [--zap-api-key ZAP_API_KEY] [--require-zap] [--ignore-ssl]

Dynamic Application Security Testing (DAST) Scanner

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT_FILE, --input-file INPUT_FILE
                        Input file with URLs to scan (required)
  -o OUTPUT, --output OUTPUT
                        Output Excel file (default: security_scan_YYYYMMDD_HHMMSS.xlsx)
  --zap-proxy ZAP_PROXY
                        OWASP ZAP proxy address (e.g., http://localhost:8080)
  --zap-api-key ZAP_API_KEY
                        OWASP ZAP API key
  --require-zap         Exit if ZAP connection fails
  --ignore-ssl          Ignore SSL certificate errors
```

## Input Format

Create a text file with URLs to scan, one per line:

```
example.com
https://another-example.com
http://test-site.org
```

## Security Checks

The DAST Scanner performs the following security checks:

1. **SSL/TLS Configuration**:
   - Protocol versions (TLS 1.2, TLS 1.3)
   - Cipher suites
   - Certificate validity

2. **Security Headers**:
   - Content-Security-Policy
   - X-XSS-Protection
   - X-Frame-Options
   - X-Content-Type-Options
   - Strict-Transport-Security
   - Referrer-Policy

3. **Sensitive File Exposure**:
   - Configuration files
   - Backup files
   - Directory listings
   - Development files

4. **HTTP Method Testing**:
   - OPTIONS method
   - TRACE method
   - PUT/DELETE methods

5. **Component Analysis**:
   - Frontend libraries
   - JavaScript frameworks
   - Known vulnerabilities in components

## Output

The tool generates a professionally formatted Excel report with:

1. **Security Findings** sheet:
   - URL scanned
   - Vulnerability type
   - Risk level (High, Medium, Low, Info)
   - Description and path
   - Recommended solution
   - References for more information

2. **Summary** sheet:
   - Breakdown of findings by risk level and vulnerability type
   - Statistics on total issues found

## Best Practices

1. **Legal Compliance**: Only scan websites you have permission to test
2. **ZAP Integration**: Use OWASP ZAP for more comprehensive scanning
3. **Regular Scanning**: Perform periodic scans to identify new vulnerabilities
4. **Validation**: Manually verify critical findings to eliminate false positives
5. **Remediation Tracking**: Use the reports to track remediation progress

## Troubleshooting

- **ZAP Connection Issues**: Verify ZAP is running and API key is correct
- **SSL Errors**: Use the `--ignore-ssl` option for sites with certificate issues
- **Timeout Errors**: Increase timeout settings in the configuration
- **False Positives**: Manually verify findings before remediation

## Integration with Other Tools

The DAST Scanner works seamlessly with other SecRecon tools:

- Use **OWASP Scanner** for more targeted vulnerability assessment
- Combine with **Credential Scanner** to identify exposed sensitive information
- Use **Subdomain Analyzer** to discover subdomains before scanning
