# OWASP Scanner Documentation

## Overview
The OWASP Scanner is a comprehensive tool for scanning web applications against the OWASP Top 10 vulnerabilities. It helps security professionals identify common security issues in web applications based on the industry-standard OWASP Top 10 list.

## Features
- **OWASP Top 10 Coverage**: Scans for all vulnerabilities in the OWASP Top 10 list
- **Intelligent Problem Domain Handling**: Automatically skips problematic domains
- **Batch Processing**: Efficiently scans multiple domains in sequence
- **Advanced Timeout Controls**: Prevents hanging on unresponsive sites
- **Detailed Vulnerability Reports**: Provides actionable information about findings

## Installation

The OWASP Scanner is included in the SecRecon framework. After installing the framework, you may need to set up additional dependencies:

```bash
./run_scan.sh --setup
```

## Usage

### Basic Usage

```bash
./skip_problematic_domains.sh filtered_domains.txt
```

### Batch Processing

```bash
./run_automated_scan.sh filtered_domains.txt
```

### Comprehensive Scanning

```bash
./run_comprehensive_scan.sh filtered_domains.txt
```

## Input Format

Create a text file with domains to scan, one per line:

```
example.com
secondexample.com
thirdexample.com
```

## Scripts and Utilities

The OWASP Scanner includes several utility scripts:

1. **skip_problematic_domains.sh**: Skips domains that are known to cause issues
2. **run_automated_scan.sh**: Runs automated scans with default settings
3. **run_comprehensive_scan.sh**: Performs in-depth scanning with extended checks
4. **run_scan.sh**: Core scanning script with customizable options
5. **merge_reports.py**: Combines multiple scan reports into a single report
6. **url_fetcher.py**: Utility for fetching and validating URLs

## OWASP Top 10 Coverage

The scanner checks for the following OWASP Top 10 vulnerabilities:

1. **Injection**: SQL, NoSQL, OS, and LDAP injection flaws
2. **Broken Authentication**: Authentication and session management flaws
3. **Sensitive Data Exposure**: Unprotected sensitive data
4. **XML External Entities (XXE)**: Processing of untrusted XML input
5. **Broken Access Control**: Improper access restrictions
6. **Security Misconfiguration**: Insecure default configurations
7. **Cross-Site Scripting (XSS)**: Untrusted data sent to browsers
8. **Insecure Deserialization**: Untrusted data deserialization
9. **Using Components with Known Vulnerabilities**: Outdated or vulnerable components
10. **Insufficient Logging & Monitoring**: Lack of proper security monitoring

## Output

The scanner generates reports in multiple formats:

- **JSON**: Machine-readable format for integration with other tools
- **HTML**: Human-readable reports with interactive elements
- **Excel**: Detailed spreadsheets with vulnerability information

Each report includes:

- **Vulnerability Type**: The category of vulnerability found
- **Risk Level**: Severity rating (Critical, High, Medium, Low, Info)
- **Description**: Detailed explanation of the vulnerability
- **Evidence**: Proof of the vulnerability's existence
- **Solution**: Recommended remediation steps
- **References**: Links to additional information

## Best Practices

1. **Legal Compliance**: Only scan domains you have permission to test
2. **Filtering Domains**: Use the `filtered_domains.txt` approach to avoid problematic sites
3. **Report Merging**: For large scans, use the merge_reports.py utility
4. **Regular Scanning**: Perform periodic scans to identify new vulnerabilities
5. **Validation**: Manually verify critical findings to eliminate false positives

## Troubleshooting

- **Hanging Scans**: Use the skip_problematic_domains.sh script
- **Memory Issues**: Reduce the batch size in automated scans
- **Timeout Errors**: Adjust timeout settings in the configuration
- **False Positives**: Use the comprehensive scan mode for more accurate results

## Integration with Other Tools

The OWASP Scanner works seamlessly with other SecRecon tools:

- Use **DAST Scanner** for more comprehensive web application testing
- Combine with **Credential Scanner** to identify exposed sensitive information
- Use findings to guide **Port Scanner** for targeted service enumeration
