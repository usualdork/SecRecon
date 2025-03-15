# Credential Scanner Documentation

## Overview
The Credential Scanner is a powerful tool for scanning websites for leaked credentials, API keys, and other sensitive information. It helps security professionals identify exposed data that could lead to security breaches.

## Features
- **Comprehensive Pattern Matching**: Detects various types of exposed data:
  - API keys (AWS, Google, Firebase, etc.)
  - Tokens (JWT, OAuth, etc.)
  - Passwords and private keys
  - Credit card numbers and personal information
- **Multi-threaded Scanning**: Efficiently scans multiple domains in parallel
- **Depth Control**: Configurable crawling depth for thorough analysis
- **Professional Reporting**: Generates detailed Excel reports with color-coded risk levels

## Installation

The Credential Scanner is included in the SecRecon framework. After installing the framework, no additional installation is required.

## Usage

### Basic Usage

```bash
python credential_scanner.py sample_domains.txt -o results.xlsx
```

### Command Line Options

```
usage: credential_scanner.py [-h] [-o OUTPUT] [-d DEPTH] [-t THREADS] [-T TIMEOUT] [--delay DELAY] domains_file

Scan domains for leaked credentials and sensitive information

positional arguments:
  domains_file          File containing list of domains to scan (one per line)

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output Excel file (default: credential_scan_results_YYYYMMDD_HHMMSS.xlsx)
  -d DEPTH, --depth DEPTH
                        Maximum crawling depth (default: 3)
  -t THREADS, --threads THREADS
                        Number of concurrent threads (default: 10)
  -T TIMEOUT, --timeout TIMEOUT
                        Request timeout in seconds (default: 10)
  --delay DELAY         Delay between requests in seconds (default: 1)
```

## Input Format

Create a text file with domains to scan, one per line:

```
example.com
secondexample.com
thirdexample.com
```

## Output

The tool generates an Excel report with the following information:

- **Domain**: The scanned domain
- **URL**: The specific URL where sensitive information was found
- **Type**: The type of sensitive information (API key, password, etc.)
- **Value**: The detected sensitive value (partially masked for security)
- **Risk Level**: High, Medium, or Low based on the sensitivity of the information
- **Context**: The surrounding context where the information was found
- **Timestamp**: When the scan was performed

## Best Practices

1. **Legal Compliance**: Only scan domains you have permission to test
2. **Responsible Disclosure**: If you find sensitive information, report it to the domain owner
3. **Scan Throttling**: Use the `--delay` option to avoid overwhelming target servers
4. **Depth Control**: Start with a lower depth value and increase if needed
5. **Regular Scanning**: Perform periodic scans to identify new exposures

## Example Workflow

1. Create a list of domains to scan: `domains.txt`
2. Run the scanner: `python credential_scanner.py domains.txt -d 2 -t 5`
3. Review the generated Excel report
4. Prioritize findings based on risk level
5. Take remediation actions for identified exposures

## Troubleshooting

- **Connection Errors**: Increase the timeout value with `-T` option
- **Slow Scanning**: Adjust the number of threads with `-t` option
- **False Positives**: Review the context of findings to confirm validity
- **Memory Issues**: Reduce the depth or split the domain list into smaller batches

## Integration with Other Tools

The Credential Scanner works seamlessly with other SecRecon tools:

- Use **DAST Scanner** for more comprehensive web application testing
- Combine with **Leaked API Scanner** for focused API security analysis
- Use findings to guide **Port Scanner** for targeted service enumeration
