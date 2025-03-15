#!/usr/bin/env python3

import os
import shutil
import sys
from colorama import Fore, Style, init

# Initialize colorama
init()

# Define paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(BASE_DIR, "tools")
WORKSPACE_DIR = os.path.dirname(BASE_DIR)  # Parent directory where original tools are located

# Map of source files to destination directories
TOOL_MAPPING = {
    # Credential Scanner
    "credential_scanner.py": "tools/credential_scanner/",
    "sample_domains.txt": "tools/credential_scanner/",
    
    # DAST Scanner
    "DAST/dast_scanner.py": "tools/dast_scanner/",
    "DAST/setup_zap.py": "tools/dast_scanner/",
    "DAST/sample_urls.txt": "tools/dast_scanner/",
    "DAST/README.md": "tools/dast_scanner/README.md",
    
    # OWASP Scanner
    "owasp/owasp_scanner.py": "tools/owasp_scanner/",
    "owasp/url_fetcher.py": "tools/owasp_scanner/",
    "owasp/merge_reports.py": "tools/owasp_scanner/",
    "owasp/skip_problematic_domains.sh": "tools/owasp_scanner/",
    "owasp/run_scan.sh": "tools/owasp_scanner/",
    "owasp/run_automated_scan.sh": "tools/owasp_scanner/",
    "owasp/run_comprehensive_scan.sh": "tools/owasp_scanner/",
    "owasp/filtered_domains.txt": "tools/owasp_scanner/",
    
    # Leaked API Scanner
    "holi/leakedAPI/leakedAPI.py": "tools/leaked_api/",
    "holi/leakedAPI/targetsport.txt": "tools/leaked_api/",
    
    # HTTP Analyzer
    "holi/httpvshttps.py": "tools/http_analyzer/",
    "holi/okto.txt": "tools/http_analyzer/",
    
    # Subdomain Analyzer
    "holi/enumeration.py": "tools/subdomain_analyzer/",
    "holi/url.txt": "tools/subdomain_analyzer/",
    
    # Port Scanner
    "holi/portlisting.py": "tools/port_scanner/",
    "holi/targetsport.txt": "tools/port_scanner/"
}

def print_banner():
    """Prints the tool copy banner."""
    banner = f"""
{Fore.CYAN}
 _____            _____                      
|   __|___ ___   |   __|___ ___ ___ ___ ___ 
|__   | -_|  _|  |  |  | -_|  _| . |   |   |
|_____|___|___|  |_____|___|___|___|_|_|_|_|
                                             
{Fore.GREEN}Copying Security Tools{Style.RESET_ALL}

This script will copy the security tools from their original locations to the SecRecon framework.
"""
    print(banner)

def ensure_directories():
    """Ensure all necessary directories exist."""
    for _, dest_dir in TOOL_MAPPING.items():
        full_dest_dir = os.path.join(BASE_DIR, dest_dir)
        
        # If it's a file path not a directory
        if dest_dir.endswith(".md") or dest_dir.endswith(".txt"):
            directory = os.path.dirname(full_dest_dir)
        else:
            directory = full_dest_dir
            
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            print(f"{Fore.GREEN}Created directory: {directory}{Style.RESET_ALL}")

def copy_tools():
    """Copy the tools from source to destination."""
    print(f"\n{Fore.CYAN}Copying tools...{Style.RESET_ALL}")
    
    success_count = 0
    fail_count = 0
    
    for src_path, dest_dir in TOOL_MAPPING.items():
        full_src_path = os.path.join(WORKSPACE_DIR, src_path)
        full_dest_dir = os.path.join(BASE_DIR, dest_dir)
        
        try:
            if os.path.exists(full_src_path):
                # If destination is a specific file
                if dest_dir.endswith(".md") or dest_dir.endswith(".txt"):
                    shutil.copy2(full_src_path, full_dest_dir)
                else:
                    # Otherwise, copy to the tool directory
                    dest_file = os.path.join(full_dest_dir, os.path.basename(full_src_path))
                    shutil.copy2(full_src_path, dest_file)
                
                # Make shell scripts executable
                if src_path.endswith(".sh"):
                    if dest_dir.endswith(".sh"):
                        os.chmod(full_dest_dir, 0o755)
                    else:
                        dest_file = os.path.join(full_dest_dir, os.path.basename(full_src_path))
                        os.chmod(dest_file, 0o755)
                
                print(f"{Fore.GREEN}✓ Copied: {src_path} to {dest_dir}{Style.RESET_ALL}")
                success_count += 1
            else:
                print(f"{Fore.YELLOW}Warning: Source file not found: {full_src_path}{Style.RESET_ALL}")
                fail_count += 1
        except Exception as e:
            print(f"{Fore.RED}Error copying {src_path}: {str(e)}{Style.RESET_ALL}")
            fail_count += 1
    
    print(f"\n{Fore.GREEN}Successfully copied {success_count} files{Style.RESET_ALL}")
    if fail_count > 0:
        print(f"{Fore.YELLOW}Failed to copy {fail_count} files{Style.RESET_ALL}")
    
    return success_count > 0

def create_readme_files():
    """Create README files for each tool directory."""
    readme_content = {
        "credential_scanner": """# Credential Scanner

A powerful tool for scanning domains for leaked credentials, API keys, and other sensitive information.

## Usage

```
python credential_scanner.py sample_domains.txt -o results.xlsx
```

For more options, run:
```
python credential_scanner.py -h
```
""",
        "dast_scanner": """# DAST Scanner

A comprehensive Dynamic Application Security Testing (DAST) tool for web applications.

## Usage

```
python dast_scanner.py -i sample_urls.txt -o security_report.xlsx
```

For more options, run:
```
python dast_scanner.py -h
```
""",
        "owasp_scanner": """# OWASP Scanner

A comprehensive tool for scanning web applications against the OWASP Top 10 vulnerabilities.

## Usage

```
./skip_problematic_domains.sh filtered_domains.txt
```

For batch processing:
```
./run_automated_scan.sh filtered_domains.txt
```
""",
        "leaked_api": """# Leaked API Scanner

A powerful tool for detecting leaked API keys and credentials in web applications.

## Usage

```
python leakedAPI.py targetsport.txt
```

For more options, run:
```
python leakedAPI.py -h
```
""",
        "http_analyzer": """# HTTP vs HTTPS Analyzer

A tool for analyzing HTTP and HTTPS implementation differences.

## Usage

```
python httpvshttps.py okto.txt
```

For more options, run:
```
python httpvshttps.py -h
```
""",
        "subdomain_analyzer": """# Subdomain Analyzer

A tool for validating and enumerating subdomains.

## Usage

```
python enumeration.py url.txt
```

For more options, run:
```
python enumeration.py -h
```
""",
        "port_scanner": """# Port Scanner

A Nmap-based scanner with web technology detection.

## Usage

```
python portlisting.py targetsport.txt
```

For more options, run:
```
python portlisting.py -h
```
"""
    }
    
    for tool_name, content in readme_content.items():
        readme_path = os.path.join(TOOLS_DIR, tool_name, "README.md")
        if not os.path.exists(readme_path):
            try:
                with open(readme_path, 'w') as f:
                    f.write(content)
                print(f"{Fore.GREEN}✓ Created README for {tool_name}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Error creating README for {tool_name}: {str(e)}{Style.RESET_ALL}")

def main():
    print_banner()
    
    # Ensure all directories exist
    ensure_directories()
    
    # Copy tools
    if copy_tools():
        print(f"\n{Fore.GREEN}Successfully copied tools to the SecRecon framework!{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.RED}Failed to copy some tools. Please check the errors above.{Style.RESET_ALL}")
    
    # Create README files
    create_readme_files()
    
    print(f"\n{Fore.CYAN}Next steps:{Style.RESET_ALL}")
    print(f"1. Run the SecRecon menu: {Fore.YELLOW}python secrecon.py{Style.RESET_ALL}")
    print(f"2. Push to GitHub with: {Fore.YELLOW}git init && git add . && git commit -m 'Initial commit' && git remote add origin https://github.com/yourusername/SecRecon.git && git push -u origin main{Style.RESET_ALL}")

if __name__ == "__main__":
    main() 