# Subdomain Analyzer Documentation

## Overview
The Subdomain Analyzer is a powerful tool for validating and enumerating subdomains. It helps security professionals identify active subdomains, analyze their operational status, and generate comprehensive reports for security assessments.

## Features
- **Parallel Connection Establishment**: Efficiently validates multiple subdomains simultaneously
- **Operational Status Analysis**: Determines if subdomains are active and accessible
- **Response Validation**: Analyzes HTTP response characteristics including status codes, headers, and content
- **DNS Resolution Verification**: Confirms proper DNS resolution for target subdomains
- **Title Extraction**: Automatically extracts page titles from HTML responses
- **Server Identification**: Identifies web server technologies from response headers
- **IP Address Resolution**: Maps subdomains to their corresponding IP addresses
- **Redirect Tracking**: Follows and documents HTTP redirects to final destinations
- **Comprehensive Reporting**: Generates detailed CSV and Excel reports with color-coded status indicators
- **Statistical Analysis**: Provides summary statistics on validation results
- **Subdomain Generation**: Can generate common subdomains for a base domain

## Installation

The Subdomain Analyzer is included in the SecRecon framework. The tool requires Python 3.6+ and the following dependencies:

```bash
pip install requests urllib3
```

For Excel report generation (optional):

```bash
pip install openpyxl
```

## Usage

### Basic Usage

```bash
python enumeration.py -f url.txt
```

Where `url.txt` contains a list of subdomains to analyze (one per line).

### Analyzing a Single URL

```bash
python enumeration.py -u example.com
```

### Generating Common Subdomains

```bash
python enumeration.py -d example.com
```

This will automatically generate and test common subdomains for the specified base domain.

### Command Line Options

```
usage: enumeration.py [-h] (-f FILE | -u URL | -d DOMAIN) [-o OUTPUT] [-t TIMEOUT]
                      [-w WORKERS] [-s] [-r] [-p]

URL Validation Protocol: Systematically assess subdomain operational status

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Input file containing URLs (one per line)
  -u URL, --url URL     Single URL to validate
  -d DOMAIN, --domain DOMAIN
                        Base domain for subdomain generation
  -o OUTPUT, --output OUTPUT
                        Output file (.csv or .xlsx format)
  -t TIMEOUT, --timeout TIMEOUT
                        Request timeout in seconds (default: 8)
  -w WORKERS, --workers WORKERS
                        Number of concurrent workers (default: 25)
  -s, --ssl             Verify SSL certificates (default: False)
  -r, --no-redirect     Do not follow redirects (default: False)
  -p, --single-protocol Check only one protocol (HTTPS) instead of both HTTP and HTTPS
                        (default: False)
```

## Output Formats

### Console Output

The tool provides real-time progress updates and a comprehensive summary of results in the console, including:

- Total URLs processed and execution time
- Active vs. inactive URL counts and percentages
- Protocol distribution (HTTP vs. HTTPS)
- Response code distribution
- Error type distribution
- Average response time
- Samples of active and inactive URLs

### CSV Output

When specifying an output file with a `.csv` extension, the tool generates a detailed CSV report with the following fields:

- URL
- Domain
- Protocol
- Status (active/inactive)
- Response Code
- Response Time (ms)
- Content Length
- Page Title
- Server
- IP Address
- Redirect URL
- Error

### Excel Output

When specifying an output file with a `.xlsx` extension, the tool generates a formatted Excel workbook with:

- Color-coded status indicators (green for active, red for inactive)
- Conditional formatting for response codes
- Auto-filtering capabilities
- A summary sheet with statistical analysis
- Charts visualizing the results

## Integration

The Subdomain Analyzer can be integrated into larger security assessment workflows:

- Use the output as input for other tools in the SecRecon framework
- Incorporate into automated security scanning pipelines
- Use the URLValidator class in custom Python scripts

## Best Practices

- **Adjust Timeout Settings**: Increase the timeout value for slower networks or when scanning large numbers of subdomains
- **Optimize Worker Count**: Adjust the number of concurrent workers based on available system resources
- **Use Excel Output**: For better visualization and analysis of large datasets
- **Combine with Other Tools**: Use the results as input for port scanners or vulnerability assessment tools
- **Regular Updates**: Periodically scan subdomains to identify changes in infrastructure

## Example Workflow

1. Generate a list of potential subdomains using OSINT techniques
2. Validate subdomains with the Subdomain Analyzer
3. Export results to Excel for analysis
4. Target active subdomains with other security assessment tools
5. Document findings in security assessment reports

## Troubleshooting

- **SSL Errors**: Use the `-s` flag to enable SSL certificate verification
- **Timeout Issues**: Increase the timeout value with the `-t` flag
- **Rate Limiting**: Reduce the number of concurrent workers with the `-w` flag
- **Excel Export Errors**: Install the openpyxl library or use CSV export instead
