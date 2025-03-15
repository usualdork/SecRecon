# Leaked API Scanner Documentation

## Overview
The Leaked API Scanner is an advanced URL credential scanner focused on API security. It helps security professionals identify exposed API credentials, authentication tokens, and other sensitive information in web applications.

## Features
- **Comprehensive Pattern Matching**: Detects various types of exposed API data:
  - API keys and tokens
  - Authentication credentials
  - Cryptographic keys
  - Service-specific identifiers
- **Multi-threaded Scanning**: Efficiently scans multiple URLs in parallel
- **Validation Checks**: Performs validation of detected credentials
- **Professional Reporting**: Generates detailed reports with actionable findings

## Installation

The Leaked API Scanner is included in the SecRecon framework. After installing the framework, no additional installation is required.

## Usage

### Basic Usage

```bash
python leakedAPI.py targetsport.txt
```

### Command Line Options

```
usage: leakedAPI.py [-h] [-o OUTPUT] [-t THREADS] [-T TIMEOUT] [--delay DELAY] [--verify-ssl] targets_file

Scan for leaked API credentials in web applications

positional arguments:
  targets_file          File containing list of targets to scan (one per line)

optional arguments:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output file (default: leaked_api_results_YYYYMMDD_HHMMSS.csv)
  -t THREADS, --threads THREADS
                        Number of concurrent threads (default: 10)
  -T TIMEOUT, --timeout TIMEOUT
                        Request timeout in seconds (default: 10)
  --delay DELAY         Delay between requests in seconds (default: 1)
  --verify-ssl          Verify SSL certificates (default: False)
```

## Input Format

Create a text file with targets to scan, one per line:

```
example.com
api.secondexample.com
thirdexample.com/api
```

## Output

The tool generates a CSV report with the following information:

- **Target**: The scanned target URL
- **Credential Type**: The type of credential found (API Key, Auth Token, etc.)
- **Pattern**: The pattern that matched the credential
- **Value**: The detected credential value (partially masked for security)
- **Context**: The surrounding context where the credential was found
- **Risk Level**: High, Medium, or Low based on the sensitivity of the credential
- **Timestamp**: When the scan was performed

## Credential Types

The scanner detects the following types of credentials:

1. **API Keys**: Various service-specific API keys
2. **Authentication Tokens**: OAuth, JWT, and other auth tokens
3. **Passwords**: Plain text and encoded passwords
4. **Cryptographic Keys**: Private keys, certificates, and encryption keys
5. **Service-Specific Credentials**: AWS, Google, Firebase, Stripe, etc.

## Best Practices

1. **Legal Compliance**: Only scan targets you have permission to test
2. **Responsible Disclosure**: If you find sensitive information, report it to the target owner
3. **Scan Throttling**: Use the `--delay` option to avoid overwhelming target servers
4. **Regular Scanning**: Perform periodic scans to identify new exposures
5. **Validation**: Manually verify critical findings to confirm validity

## Troubleshooting

- **Connection Errors**: Increase the timeout value with `-T` option
- **Slow Scanning**: Adjust the number of threads with `-t` option
- **SSL Errors**: Use the `--verify-ssl` option for strict certificate checking
- **False Positives**: Review the context of findings to confirm validity

## Integration with Other Tools

The Leaked API Scanner works seamlessly with other SecRecon tools:

- Use **Credential Scanner** for more general credential scanning
- Combine with **DAST Scanner** for comprehensive web application testing
- Use **Subdomain Analyzer** to discover API endpoints before scanning
