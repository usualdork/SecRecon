#!/usr/bin/env python3
# URL Fetcher for OWASP Scanner
# This script fetches URLs from various sources and prepares them for batch scanning

import argparse
import os
import csv
import json
import re
import logging
import requests
import sys
import subprocess
from urllib.parse import urlparse
from datetime import datetime
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(f"url_fetcher_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    ]
)
logger = logging.getLogger('url_fetcher')

def fetch_from_file(file_path, file_format='txt'):
    """Fetch URLs from a file (supports txt, csv, json formats)."""
    if not os.path.exists(file_path):
        logger.error(f"File not found: {file_path}")
        return []
        
    urls = []
    try:
        if file_format.lower() == 'txt':
            with open(file_path, 'r') as f:
                urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
                
        elif file_format.lower() == 'csv':
            with open(file_path, 'r') as f:
                reader = csv.reader(f)
                header = next(reader, None)
                if header:
                    # Try to find URL column
                    url_col = None
                    for i, col in enumerate(header):
                        if col.lower() in ['url', 'link', 'domain', 'website', 'target']:
                            url_col = i
                            break
                    
                    if url_col is not None:
                        urls = [row[url_col].strip() for row in reader if len(row) > url_col and row[url_col].strip()]
                    else:
                        # Use first column as URL if no clear URL column found
                        urls = [row[0].strip() for row in reader if row and row[0].strip()]
                
        elif file_format.lower() == 'json':
            with open(file_path, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    # Extract URLs from list of objects or strings
                    for item in data:
                        if isinstance(item, str):
                            urls.append(item.strip())
                        elif isinstance(item, dict) and any(k in item for k in ['url', 'link', 'domain', 'website', 'target']):
                            for k in ['url', 'link', 'domain', 'website', 'target']:
                                if k in item and item[k]:
                                    urls.append(str(item[k]).strip())
                                    break
                elif isinstance(data, dict) and 'urls' in data:
                    # Extract from {"urls": [...]} format
                    urls = [url.strip() for url in data['urls'] if url.strip()]
        
        logger.info(f"Extracted {len(urls)} URLs from {file_path}")
        return urls
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {e}")
        return []

def fetch_from_api(api_url, api_key=None, method='GET', auth_type='header', headers=None, payload=None, url_path=''):
    """Fetch URLs from an API endpoint."""
    if not api_url:
        logger.error("API URL is required")
        return []
        
    try:
        # Prepare request
        request_headers = headers or {}
        if api_key and auth_type == 'header':
            request_headers['Authorization'] = f"Bearer {api_key}"
            
        request_params = {}
        if api_key and auth_type == 'param':
            request_params['api_key'] = api_key
            
        # Make request
        if method.upper() == 'GET':
            response = requests.get(api_url, headers=request_headers, params=request_params, timeout=30)
        elif method.upper() == 'POST':
            response = requests.post(api_url, headers=request_headers, params=request_params, json=payload, timeout=30)
        else:
            logger.error(f"Unsupported HTTP method: {method}")
            return []
            
        # Process response
        if response.status_code == 200:
            data = response.json()
            urls = []
            
            # Extract URL from response
            if url_path:
                # Access nested path like 'data.items.url'
                parts = url_path.split('.')
                current = data
                for part in parts[:-1]:
                    if isinstance(current, dict) and part in current:
                        current = current[part]
                    elif isinstance(current, list) and part == '*':
                        break
                    else:
                        logger.error(f"Invalid path: {url_path}")
                        return []
                
                last_part = parts[-1]
                if isinstance(current, list):
                    for item in current:
                        if isinstance(item, dict) and last_part in item:
                            urls.append(str(item[last_part]).strip())
                elif isinstance(current, dict) and last_part in current:
                    if isinstance(current[last_part], list):
                        urls = [str(url).strip() for url in current[last_part]]
                    else:
                        urls = [str(current[last_part]).strip()]
            else:
                # Try common patterns if no path specified
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, str):
                            urls.append(item.strip())
                        elif isinstance(item, dict):
                            for key in ['url', 'link', 'domain', 'target']:
                                if key in item and item[key]:
                                    urls.append(str(item[key]).strip())
                                    break
                elif isinstance(data, dict):
                    for key in ['urls', 'domains', 'targets', 'data', 'items', 'results']:
                        if key in data and isinstance(data[key], list):
                            if all(isinstance(item, str) for item in data[key]):
                                urls.extend([url.strip() for url in data[key]])
                                break
                            elif all(isinstance(item, dict) for item in data[key]):
                                for item in data[key]:
                                    for k in ['url', 'link', 'domain', 'target']:
                                        if k in item and item[k]:
                                            urls.append(str(item[k]).strip())
                                            break
                                break
            
            logger.info(f"Extracted {len(urls)} URLs from API")
            return urls
        else:
            logger.error(f"API request failed with status code {response.status_code}: {response.text}")
            return []
    except Exception as e:
        logger.error(f"Error fetching from API: {e}")
        return []

def fetch_from_web(web_url, selector=None):
    """Fetch URLs from a webpage using a CSS selector."""
    if not web_url:
        logger.error("Web URL is required")
        return []
        
    try:
        # Try to import BeautifulSoup
        try:
            from bs4 import BeautifulSoup
        except ImportError:
            logger.error("BeautifulSoup not installed. Installing...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'beautifulsoup4'])
            from bs4 import BeautifulSoup
        
        # Fetch page
        response = requests.get(web_url, timeout=30)
        if response.status_code != 200:
            logger.error(f"Failed to fetch webpage: {response.status_code}")
            return []
            
        # Parse page
        soup = BeautifulSoup(response.text, 'html.parser')
        urls = []
        
        if selector:
            # Use provided selector
            elements = soup.select(selector)
            for element in elements:
                if element.name == 'a' and element.get('href'):
                    urls.append(element['href'])
                else:
                    # For non-anchor elements, look for URLs in text
                    text = element.get_text()
                    found_urls = re.findall(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', text)
                    urls.extend(found_urls)
        else:
            # Extract all links
            for a in soup.find_all('a', href=True):
                href = a['href']
                if href.startswith('http') or href.startswith('www'):
                    urls.append(href)
        
        # Clean and normalize URLs
        normalized_urls = []
        for url in urls:
            if url.startswith('www.'):
                url = 'http://' + url
            normalized_urls.append(url)
            
        logger.info(f"Extracted {len(normalized_urls)} URLs from web page")
        return normalized_urls
    except Exception as e:
        logger.error(f"Error fetching from web: {e}")
        return []

def normalize_urls(urls):
    """Ensure all URLs have proper format and remove duplicates."""
    normalized = []
    seen = set()
    
    for url in urls:
        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            
        # Remove trailing slashes for consistency
        if url.endswith('/'):
            url = url[:-1]
            
        # Skip duplicates
        if url.lower() in seen:
            continue
            
        normalized.append(url)
        seen.add(url.lower())
    
    return normalized

def group_by_domain(urls, max_per_domain=None):
    """Group URLs by domain to optimize scanning."""
    domain_groups = {}
    
    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc
        
        if domain not in domain_groups:
            domain_groups[domain] = []
            
        domain_groups[domain].append(url)
    
    # Apply max per domain limit if specified
    if max_per_domain:
        for domain in domain_groups:
            if len(domain_groups[domain]) > max_per_domain:
                logger.warning(f"Limiting domain {domain} to {max_per_domain} URLs")
                domain_groups[domain] = domain_groups[domain][:max_per_domain]
    
    return domain_groups

def create_batch_files(urls, output_dir, batch_size=5, by_domain=False, max_per_domain=None):
    """Split URLs into batch files for scanning."""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if by_domain:
        # Create batches by domain
        domain_groups = group_by_domain(urls, max_per_domain)
        
        batch_files = []
        batch_num = 1
        current_batch = []
        current_domains = []
        
        # Group domains into batches
        for domain, domain_urls in domain_groups.items():
            if len(current_batch) + len(domain_urls) > batch_size and current_batch:
                # Save current batch
                batch_file = os.path.join(output_dir, f"batch_{timestamp}_{batch_num}.txt")
                with open(batch_file, 'w') as f:
                    f.write('\n'.join(current_batch))
                batch_files.append(batch_file)
                logger.info(f"Created batch {batch_num} with {len(current_batch)} URLs from domains: {', '.join(current_domains)}")
                
                # Start new batch
                batch_num += 1
                current_batch = domain_urls
                current_domains = [domain]
            else:
                # Add to current batch
                current_batch.extend(domain_urls)
                current_domains.append(domain)
        
        # Save last batch if not empty
        if current_batch:
            batch_file = os.path.join(output_dir, f"batch_{timestamp}_{batch_num}.txt")
            with open(batch_file, 'w') as f:
                f.write('\n'.join(current_batch))
            batch_files.append(batch_file)
            logger.info(f"Created batch {batch_num} with {len(current_batch)} URLs from domains: {', '.join(current_domains)}")
    else:
        # Split into equal size batches
        batch_files = []
        for i in range(0, len(urls), batch_size):
            batch_num = i // batch_size + 1
            batch = urls[i:i+batch_size]
            batch_file = os.path.join(output_dir, f"batch_{timestamp}_{batch_num}.txt")
            
            with open(batch_file, 'w') as f:
                f.write('\n'.join(batch))
                
            batch_files.append(batch_file)
            logger.info(f"Created batch {batch_num} with {len(batch)} URLs")
    
    # Create all URLs file
    all_urls_file = os.path.join(output_dir, f"all_urls_{timestamp}.txt")
    with open(all_urls_file, 'w') as f:
        f.write('\n'.join(urls))
    logger.info(f"Created combined file with all {len(urls)} URLs: {all_urls_file}")
    
    return batch_files

def launch_scans(batch_files, scan_script="./run_scan.sh", output_dir=None, workers=1, timeout=30, api_key=None):
    """Launch OWASP scans for each batch file."""
    if not os.path.exists(scan_script):
        logger.error(f"Scan script not found: {scan_script}")
        return False
    
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    success_count = 0
    for i, batch_file in enumerate(batch_files):
        batch_num = i + 1
        batch_name = os.path.basename(batch_file).replace('.txt', '')
        
        output_file = f"{batch_name}_results.xlsx"
        if output_dir:
            output_file = os.path.join(output_dir, output_file)
        
        logger.info(f"Launching scan for batch {batch_num}/{len(batch_files)}: {batch_file}")
        
        cmd = [scan_script, 
               "-f", batch_file,
               "-o", output_file,
               "-w", str(workers),
               "-t", str(timeout)]
               
        if api_key:
            cmd.extend(["-k", api_key])
        
        try:
            logger.info(f"Executing: {' '.join(cmd)}")
            result = subprocess.run(cmd, check=True)
            if result.returncode == 0:
                logger.info(f"Successfully completed scan for batch {batch_num}")
                success_count += 1
            else:
                logger.error(f"Scan for batch {batch_num} failed with return code {result.returncode}")
                
            # Add delay between scans to allow resources to free up
            if i < len(batch_files) - 1:
                logger.info("Waiting 30 seconds before starting next batch...")
                time.sleep(30)
                
        except subprocess.CalledProcessError as e:
            logger.error(f"Error executing scan for batch {batch_num}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during scan for batch {batch_num}: {e}")
    
    if success_count == len(batch_files):
        logger.info(f"All {len(batch_files)} batch scans completed successfully")
        return True
    else:
        logger.warning(f"{success_count}/{len(batch_files)} batch scans completed successfully")
        return False

def main():
    parser = argparse.ArgumentParser(description='URL Fetcher and Batch Manager for OWASP Scanner')
    
    # Source options
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument('--file', help='Path to file containing URLs (txt, csv, json)')
    source_group.add_argument('--api', help='API endpoint to fetch URLs from')
    source_group.add_argument('--web', help='Web page URL to extract links from')
    
    # Source-specific options
    parser.add_argument('--file-format', choices=['txt', 'csv', 'json'], default='txt', 
                      help='Format of input file (default: txt)')
    parser.add_argument('--api-key', help='API key for authentication')
    parser.add_argument('--api-method', choices=['GET', 'POST'], default='GET',
                      help='HTTP method for API request (default: GET)')
    parser.add_argument('--api-auth-type', choices=['header', 'param'], default='header',
                      help='How to send API key: in header or as URL parameter (default: header)')
    parser.add_argument('--api-path', help='JSON path to extract URLs from response (e.g., "data.items.url")')
    parser.add_argument('--web-selector', help='CSS selector to find URL elements on the page')
    
    # Output options
    parser.add_argument('--output-dir', default='batches',
                      help='Directory to save batch files (default: batches)')
    parser.add_argument('--scan-output-dir', default='reports',
                      help='Directory to save scan reports (default: reports)')
    
    # Batch options
    parser.add_argument('--batch-size', type=int, default=5,
                      help='Number of URLs per batch (default: 5)')
    parser.add_argument('--by-domain', action='store_true',
                      help='Group URLs by domain within batches')
    parser.add_argument('--max-per-domain', type=int,
                      help='Maximum number of URLs to process per domain')
    
    # Scan options
    parser.add_argument('--run-scans', action='store_true',
                      help='Automatically run scans for each batch')
    parser.add_argument('--scan-script', default='./run_scan.sh',
                      help='Path to scan script (default: ./run_scan.sh)')
    parser.add_argument('--workers', type=int, default=1,
                      help='Number of concurrent workers for each scan (default: 1)')
    parser.add_argument('--timeout', type=int, default=30,
                      help='Scan timeout in minutes per URL (default: 30)')
    parser.add_argument('--scan-api-key', 
                      help='API key for ZAP (default: api-key-for-owasp from run_scan.sh)')
    
    args = parser.parse_args()
    
    # Fetch URLs from specified source
    urls = []
    if args.file:
        urls = fetch_from_file(args.file, args.file_format)
    elif args.api:
        urls = fetch_from_api(args.api, args.api_key, args.api_method, 
                             args.api_auth_type, None, None, args.api_path)
    elif args.web:
        urls = fetch_from_web(args.web, args.web_selector)
    
    if not urls:
        logger.error("No URLs found from the specified source")
        return 1
    
    # Normalize URLs
    urls = normalize_urls(urls)
    logger.info(f"Found {len(urls)} unique URLs after normalization")
    
    # Create batch files
    batch_files = create_batch_files(
        urls, 
        args.output_dir, 
        args.batch_size, 
        args.by_domain, 
        args.max_per_domain
    )
    
    # Run scans if requested
    if args.run_scans:
        logger.info(f"Launching scans for {len(batch_files)} batches")
        launch_scans(
            batch_files, 
            args.scan_script, 
            args.scan_output_dir,
            args.workers,
            args.timeout,
            args.scan_api_key
        )
    else:
        logger.info(f"Created {len(batch_files)} batch files. Run scans manually or use --run-scans")
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 