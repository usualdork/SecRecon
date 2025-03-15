import requests
import urllib3
import argparse
import sys
import socket
from urllib.parse import urlparse, urljoin
import csv
import time
from datetime import datetime

class HTTPProtocolAnalyzer:
    """
    Implementation of systematic HTTP protocol accessibility analysis methodology
    with differentiated classification of endpoint response characteristics.
    """
    
    def __init__(self, timeout=5, verify_ssl=False):
        """
        Initialize analysis parameters for HTTP protocol verification.
        
        Parameters:
            timeout (int): Connection establishment timeout threshold in seconds
            verify_ssl (bool): SSL certificate validation parameter
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = self._initialize_session()
        
        # Disable SSL warnings if verification is disabled
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def _initialize_session(self):
        """
        Establish optimized HTTP session with standardized request parameters.
        
        Returns:
            requests.Session: Configured session object
        """
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        })
        return session
    
    def analyze_url(self, url):
        """
        Execute comprehensive HTTP protocol analysis for specified URL.
        
        Parameters:
            url (str): URL to analyze (with or without protocol specification)
            
        Returns:
            dict: Structured analysis result object
        """
        # Normalize URL format
        if not url.startswith(('http://', 'https://')):
            base_url = url
            http_url = f"http://{url}"
            https_url = f"https://{url}"
        else:
            parsed = urlparse(url)
            base_url = parsed.netloc
            http_url = f"http://{parsed.netloc}{parsed.path}"
            https_url = f"https://{parsed.netloc}{parsed.path}"
        
        # Initialize result object
        result = {
            'domain': base_url,
            'http_url': http_url,
            'https_url': https_url,
            'dns_resolution': self._check_dns_resolution(base_url),
            'http_status': self._check_http_accessibility(http_url),
            'https_status': self._check_https_accessibility(https_url)
        }
        
        return result
    
    def _check_dns_resolution(self, domain):
        """
        Verify DNS resolution for specified domain.
        
        Parameters:
            domain (str): Domain to resolve
            
        Returns:
            dict: DNS resolution status information
        """
        # Extract domain from URL if necessary
        if '/' in domain:
            domain = urlparse(domain).netloc
        
        try:
            ip_address = socket.gethostbyname(domain)
            return {
                'status': 'resolved',
                'ip_address': ip_address
            }
        except socket.gaierror:
            return {
                'status': 'failed',
                'ip_address': None
            }
    
    def _check_http_accessibility(self, url):
        """
        Analyze HTTP protocol accessibility with redirect behavior analysis.
        
        Parameters:
            url (str): HTTP URL to analyze
            
        Returns:
            dict: HTTP protocol accessibility status
        """
        # Ensure URL uses HTTP protocol
        if not url.startswith('http://'):
            url = f"http://{url}"
        
        try:
            # Initial request with redirects disabled
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False
            )
            
            result = {
                'status': 'accessible',
                'response_code': response.status_code,
                'content_length': len(response.content),
                'server': response.headers.get('Server', 'Unknown')
            }
            
            # Check for redirect response
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                if location:
                    # Handle relative redirects
                    if location.startswith('/'):
                        location = urljoin(url, location)
                    
                    result['redirect_url'] = location
                    result['redirect_type'] = 'https' if location.startswith('https://') else 'other'
                    
                    if location.startswith('https://'):
                        result['protocol_status'] = 'redirects_to_https'
                    else:
                        result['protocol_status'] = 'redirects_elsewhere'
                else:
                    result['protocol_status'] = 'ambiguous_redirect'
            elif 200 <= response.status_code < 300:
                # Direct HTTP content serving
                result['protocol_status'] = 'direct_http'
            else:
                # Other response code
                result['protocol_status'] = 'non_success_response'
            
            return result
            
        except requests.exceptions.SSLError:
            return {
                'status': 'error',
                'error_type': 'ssl_error',
                'protocol_status': 'connection_failed'
            }
        except requests.exceptions.ConnectionError:
            return {
                'status': 'error',
                'error_type': 'connection_error',
                'protocol_status': 'connection_failed'
            }
        except requests.exceptions.Timeout:
            return {
                'status': 'error',
                'error_type': 'timeout',
                'protocol_status': 'connection_failed'
            }
        except requests.exceptions.RequestException as e:
            return {
                'status': 'error',
                'error_type': str(e),
                'protocol_status': 'connection_failed'
            }
    
    def _check_https_accessibility(self, url):
        """
        Analyze HTTPS protocol accessibility.
        
        Parameters:
            url (str): HTTPS URL to analyze
            
        Returns:
            dict: HTTPS protocol accessibility status
        """
        # Ensure URL uses HTTPS protocol
        if not url.startswith('https://'):
            url = f"https://{url}"
        
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl
            )
            
            return {
                'status': 'accessible',
                'response_code': response.status_code,
                'content_length': len(response.content),
                'server': response.headers.get('Server', 'Unknown')
            }
            
        except requests.exceptions.SSLError:
            return {
                'status': 'error',
                'error_type': 'ssl_error'
            }
        except requests.exceptions.ConnectionError:
            return {
                'status': 'error',
                'error_type': 'connection_error'
            }
        except requests.exceptions.Timeout:
            return {
                'status': 'error',
                'error_type': 'timeout'
            }
        except requests.exceptions.RequestException as e:
            return {
                'status': 'error',
                'error_type': str(e)
            }
    
    def analyze_urls_from_file(self, file_path):
        """
        Process and analyze URL collection from file input source.
        
        Parameters:
            file_path (str): Path to file containing URL entries
            
        Returns:
            list: Collection of URL analysis result objects
        """
        try:
            with open(file_path, 'r') as file:
                urls = [line.strip() for line in file if line.strip()]
            
            results = []
            for i, url in enumerate(urls):
                sys.stdout.write(f"\r[+] Analyzing {i+1}/{len(urls)}: {url}")
                sys.stdout.flush()
                results.append(self.analyze_url(url))
            
            print("\n[+] Analysis completed")
            return results
        except FileNotFoundError:
            print(f"[-] Error: Input file not found - {file_path}")
            sys.exit(1)
    
    def export_results_to_csv(self, results, output_file):
        """
        Export analysis results to structured CSV format.
        
        Parameters:
            results (list): Collection of analysis result objects
            output_file (str): Output file path specification
        """
        fieldnames = [
            'domain', 'dns_resolution_status', 'ip_address',
            'http_direct_access', 'http_response_code', 'http_redirect_to_https',
            'https_accessible', 'https_response_code'
        ]
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                row = {
                    'domain': result['domain'],
                    'dns_resolution_status': result['dns_resolution']['status'],
                    'ip_address': result['dns_resolution']['ip_address'],
                    'http_direct_access': result['http_status'].get('protocol_status') == 'direct_http',
                    'http_response_code': result['http_status'].get('response_code'),
                    'http_redirect_to_https': result['http_status'].get('protocol_status') == 'redirects_to_https',
                    'https_accessible': result['https_status']['status'] == 'accessible',
                    'https_response_code': result['https_status'].get('response_code')
                }
                writer.writerow(row)
        
        print(f"[+] Results exported to {output_file}")
    
    def display_results_summary(self, results):
        """
        Generate formatted console output of analysis results.
        
        Parameters:
            results (list): Collection of analysis result objects
        """
        # Count HTTP protocol status
        http_direct = sum(1 for r in results if r['http_status'].get('protocol_status') == 'direct_http')
        http_redirects_https = sum(1 for r in results if r['http_status'].get('protocol_status') == 'redirects_to_https')
        http_redirects_other = sum(1 for r in results if r['http_status'].get('protocol_status') == 'redirects_elsewhere')
        http_error = sum(1 for r in results if r['http_status'].get('status') == 'error')
        
        # Count HTTPS status
        https_accessible = sum(1 for r in results if r['https_status']['status'] == 'accessible')
        https_error = sum(1 for r in results if r['https_status']['status'] == 'error')
        
        print("\n" + "=" * 70)
        print("HTTP PROTOCOL ACCESSIBILITY ANALYSIS")
        print("=" * 70)
        print(f"Total domains analyzed: {len(results)}")
        print(f"DNS resolution successful: {sum(1 for r in results if r['dns_resolution']['status'] == 'resolved')}")
        
        print("\nHTTP Protocol Status:")
        print(f"  Direct HTTP content: {http_direct} ({http_direct/len(results)*100:.1f}%)")
        print(f"  Redirects to HTTPS: {http_redirects_https} ({http_redirects_https/len(results)*100:.1f}%)")
        print(f"  Redirects elsewhere: {http_redirects_other} ({http_redirects_other/len(results)*100:.1f}%)")
        print(f"  Connection errors: {http_error} ({http_error/len(results)*100:.1f}%)")
        
        print("\nHTTPS Protocol Status:")
        print(f"  Accessible: {https_accessible} ({https_accessible/len(results)*100:.1f}%)")
        print(f"  Connection errors: {https_error} ({https_error/len(results)*100:.1f}%)")
        
        print("\n" + "=" * 70)
        print("DOMAINS WITH DIRECT HTTP ACCESS")
        print("=" * 70)
        
        # List domains with direct HTTP
        direct_http_domains = [r for r in results if r['http_status'].get('protocol_status') == 'direct_http']
        if direct_http_domains:
            for r in direct_http_domains:
                print(f"{r['domain']} - HTTP: {r['http_status'].get('response_code')} - "
                      f"HTTPS: {r['https_status'].get('response_code', 'N/A')}")
        else:
            print("No domains with direct HTTP access found.")

def main():
    """
    Primary execution function implementing command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="HTTP Protocol Accessibility Analyzer: Systematically evaluate HTTP vs HTTPS availability",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # Input specification
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-f', '--file', help='Input file containing domains (one per line)')
    input_group.add_argument('-d', '--domain', help='Single domain to analyze')
    
    # Output specification
    parser.add_argument('-o', '--output', help='Output CSV file for results')
    
    # Execution parameters
    parser.add_argument('-t', '--timeout', type=int, default=5, help='Request timeout in seconds')
    parser.add_argument('-s', '--ssl', action='store_true', help='Verify SSL certificates')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = HTTPProtocolAnalyzer(
        timeout=args.timeout,
        verify_ssl=args.ssl
    )
    
    # Process URLs based on input type
    if args.file:
        print(f"[+] Reading domains from file: {args.file}")
        results = analyzer.analyze_urls_from_file(args.file)
    elif args.domain:
        print(f"[+] Analyzing domain: {args.domain}")
        results = [analyzer.analyze_url(args.domain)]
    
    # Display results summary
    analyzer.display_results_summary(results)
    
    # Export results if output file specified
    if args.output:
        analyzer.export_results_to_csv(results, args.output)


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("  HTTP PROTOCOL ACCESSIBILITY ANALYSIS IMPLEMENTATION")
    print("=" * 70)
    
    start_time = time.time()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[+] Execution initiated: {timestamp}\n")
    
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Execution terminated by user")
    except Exception as e:
        print(f"\n[-] Execution error: {str(e)}")
    
    elapsed_time = time.time() - start_time
    print(f"\n[+] Total execution time: {elapsed_time:.2f} seconds")