# DAST Scanner

A comprehensive Dynamic Application Security Testing (DAST) tool designed to perform in-depth scanning of web applications, identify vulnerable components, and generate professional reports.

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

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/dast-scanner.git
   cd dast-scanner
   ```

2. Create a virtual environment (recommended):
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

4. (Optional) For advanced scanning features, install and configure OWASP ZAP:
   - Download from: https://www.zaproxy.org/download/
   - Run ZAP and note your API key (in Tools > Options > API)

## Usage

### Basic Usage

Create a text file with URLs to scan (one per line):

```
example.com
https://another-example.com
http://test-site.org
```

Run the scanner:

```
python dast_scanner.py -i urls.txt -o security_report.xlsx
```

### Advanced Usage

```
python dast_scanner.py -i urls.txt --zap-proxy http://localhost:8080 --zap-api-key <your-api-key> --ignore-ssl
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-i, --input-file` | Input file with URLs to scan (required) |
| `-o, --output` | Output Excel file (default: security_scan_YYYYMMDD_HHMMSS.xlsx) |
| `--zap-proxy` | OWASP ZAP proxy address (e.g., http://localhost:8080) |
| `--zap-api-key` | OWASP ZAP API key |
| `--require-zap` | Exit if ZAP connection fails |
| `--ignore-ssl` | Ignore SSL certificate errors |

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

## Example

![Example Report](report_example.png)

## Requirements

- Python 3.7+
- See requirements.txt for Python dependencies
- (Optional) OWASP ZAP for advanced vulnerability scanning

## Extending the Tool

You can extend the vulnerability checks by modifying:

- `basic_security_checks()`: Add custom security tests
- `analyze_components()`: Add detection for more library types
- Add new methods for additional security tests

## License

MIT

## Disclaimer

This tool is for educational and security assessment purposes only. Always obtain proper authorization before scanning any website. The authors are not responsible for misuse or damage caused by this tool. 