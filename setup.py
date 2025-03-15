#!/usr/bin/env python3

import os
import sys
import shutil
import subprocess
import platform
from colorama import Fore, Style, init

# Initialize colorama
init()

# Define paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
DOCS_DIR = os.path.join(BASE_DIR, "docs")

# Map of source files to destination directories
TOOL_MAPPING = {
    # Credential Scanner
    "credential_scanner.py": "tools/credential_scanner/",
    "sample_domains.txt": "tools/credential_scanner/",
    
    # DAST Scanner
    "DAST/dast_scanner.py": "tools/dast_scanner/",
    "DAST/setup_zap.py": "tools/dast_scanner/",
    "DAST/sample_urls.txt": "tools/dast_scanner/",
    "DAST/README.md": "docs/dast_scanner.md",
    
    # OWASP Scanner
    "owasp/owasp_scanner.py": "tools/owasp_scanner/",
    "owasp/url_fetcher.py": "tools/owasp_scanner/",
    "owasp/merge_reports.py": "tools/owasp_scanner/",
    "owasp/skip_problematic_domains.sh": "tools/owasp_scanner/",
    "owasp/run_scan.sh": "tools/owasp_scanner/",
    "owasp/run_automated_scan.sh": "tools/owasp_scanner/",
    "owasp/run_comprehensive_scan.sh": "tools/owasp_scanner/",
    "owasp/owasp_scanner_production/README.md": "docs/owasp_scanner.md",
    
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
    """Prints the SecRecon setup banner."""
    banner = f"""
{Fore.CYAN}
 _____            _____                       _____      _             
|   __|___ ___   |   __|___ ___ ___ ___ ___  |   __|___ | |_ _ _ ___   
|__   | -_|  _|  |  |  | -_|  _| . |   |   | |__   | -_||  _| | | . |  
|_____|___|___|  |_____|___|___|___|_|_|_|_| |_____|___||_| |___|  _|  
                                                                  |_|   
{Fore.GREEN}Security Reconnaissance Framework - Setup{Style.RESET_ALL}
{Fore.YELLOW}Version 1.0{Style.RESET_ALL}

Setting up the SecRecon framework...
"""
    print(banner)

def check_requirements():
    """Check if the system meets the requirements."""
    print(f"{Fore.CYAN}Checking system requirements...{Style.RESET_ALL}")
    
    # Check Python version
    python_version = platform.python_version()
    python_version_tuple = tuple(map(int, python_version.split('.')))
    if python_version_tuple < (3, 7):
        print(f"{Fore.RED}Error: Python 3.7+ is required. You have {python_version}{Style.RESET_ALL}")
        return False
    
    print(f"{Fore.GREEN}✓ Python version: {python_version}{Style.RESET_ALL}")
    
    # Check if pip is available
    try:
        subprocess.run([sys.executable, "-m", "pip", "--version"], check=True, capture_output=True)
        print(f"{Fore.GREEN}✓ Pip is installed{Style.RESET_ALL}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{Fore.RED}Error: Pip is not installed or not in PATH{Style.RESET_ALL}")
        return False
    
    # Check for Nmap (required for Port Scanner)
    nmap_available = False
    try:
        subprocess.run(["nmap", "--version"], check=True, capture_output=True)
        nmap_available = True
        print(f"{Fore.GREEN}✓ Nmap is installed{Style.RESET_ALL}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print(f"{Fore.YELLOW}Warning: Nmap is not installed or not in PATH. Port Scanner functionality will be limited.{Style.RESET_ALL}")
    
    # Check for ZAP (optional)
    zap_available = False
    zap_paths = [
        "/Applications/ZAP.app/Contents/Java/zap.sh",  # macOS
        "/usr/share/zaproxy/zap.sh",  # Linux
        "C:\\Program Files\\OWASP\\Zed Attack Proxy\\zap.bat"  # Windows
    ]
    
    for path in zap_paths:
        if os.path.exists(path):
            zap_available = True
            break
    
    if zap_available:
        print(f"{Fore.GREEN}✓ OWASP ZAP is installed{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}Warning: OWASP ZAP not found. OWASP Scanner functionality will be limited.{Style.RESET_ALL}")
    
    return True

def install_dependencies():
    """Install Python dependencies."""
    print(f"\n{Fore.CYAN}Installing Python dependencies...{Style.RESET_ALL}")
    
    requirements_file = os.path.join(BASE_DIR, "requirements.txt")
    if not os.path.exists(requirements_file):
        print(f"{Fore.RED}Error: requirements.txt not found{Style.RESET_ALL}")
        return False
    
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "-r", requirements_file], check=True)
        print(f"{Fore.GREEN}✓ Dependencies installed successfully{Style.RESET_ALL}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Error installing dependencies: {e}{Style.RESET_ALL}")
        return False

def create_directories():
    """Create the necessary directories."""
    print(f"\n{Fore.CYAN}Creating directories...{Style.RESET_ALL}")
    
    # Create tools directories
    for _, dest_dir in TOOL_MAPPING.items():
        full_dest_dir = os.path.join(BASE_DIR, dest_dir)
        os.makedirs(os.path.dirname(full_dest_dir), exist_ok=True)
    
    # Create reports directory
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    # Create docs directory
    os.makedirs(DOCS_DIR, exist_ok=True)
    
    print(f"{Fore.GREEN}✓ Directories created{Style.RESET_ALL}")
    return True

def copy_tools():
    """Copy the tools from source to destination."""
    print(f"\n{Fore.CYAN}Copying tools...{Style.RESET_ALL}")
    
    success_count = 0
    fail_count = 0
    
    for src_path, dest_dir in TOOL_MAPPING.items():
        full_src_path = os.path.join(os.path.dirname(BASE_DIR), src_path)
        full_dest_dir = os.path.join(BASE_DIR, dest_dir)
        
        # Make sure the destination directory exists
        os.makedirs(os.path.dirname(full_dest_dir), exist_ok=True)
        
        try:
            if os.path.exists(full_src_path):
                # If destination is a markdown file for documentation
                if dest_dir.startswith("docs/") and dest_dir.endswith(".md"):
                    shutil.copy2(full_src_path, full_dest_dir)
                else:
                    # Otherwise, copy to the tool directory
                    dest_file = os.path.join(full_dest_dir, os.path.basename(full_src_path))
                    shutil.copy2(full_src_path, dest_file)
                
                if src_path.endswith(".sh"):
                    # Make shell scripts executable
                    dest_file = os.path.join(full_dest_dir, os.path.basename(full_src_path))
                    os.chmod(dest_file, 0o755)
                
                print(f"{Fore.GREEN}✓ Copied: {src_path}{Style.RESET_ALL}")
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

def create_tool_readmes():
    """Create README files for tools that don't have them."""
    print(f"\n{Fore.CYAN}Creating tool-specific documentation...{Style.RESET_ALL}")
    
    # Define basic documentation for tools that might not have READMEs
    tool_docs = {
        "leaked_api": """# Leaked API Scanner

A powerful tool for detecting leaked API keys and credentials in web applications.

## Features

- Advanced pattern matching for API key detection
- Validation of credentials against actual services
- Comprehensive scanning of URL parameters and response bodies
- Generate professional reports with findings

## Usage

```bash
python leakedAPI.py -i targets.txt -o report.xlsx
```

## Options

- `-i, --input`: Input file with URLs to scan
- `-o, --output`: Output report file
- `-t, --threads`: Number of concurrent threads (default: 5)
- `--timeout`: Request timeout in seconds (default: 10)
""",
        "http_analyzer": """# HTTP vs HTTPS Analyzer

A tool for analyzing HTTP and HTTPS implementation differences.

## Features

- Protocol accessibility analysis
- Endpoint response validation
- Redirect checking
- Certificate verification
- Security header analysis

## Usage

```bash
python httpvshttps.py -i domains.txt -o report.xlsx
```

## Options

- `-i, --input`: Input file with domains to analyze
- `-o, --output`: Output report file
- `--timeout`: Request timeout in seconds (default: 5)
""",
        "subdomain_analyzer": """# Subdomain Analyzer

A tool for validating and enumerating subdomains.

## Features

- Parallel connection establishment
- Operational status analysis
- Response validation
- HTTP/HTTPS support checks
- Detailed reporting

## Usage

```bash
python enumeration.py -i domains.txt -o report.xlsx
```

## Options

- `-i, --input`: Input file with domains to analyze
- `-o, --output`: Output report file
- `-t, --threads`: Number of concurrent threads (default: 25)
- `--timeout`: Request timeout in seconds (default: 8)
""",
        "port_scanner": """# Port Scanner

A Nmap-based scanner with web technology detection.

## Features

- Service discovery
- Open port identification
- Web technology fingerprinting
- Comprehensive scan reports

## Usage

```bash
python portlisting.py -i targets.txt -o report.xlsx
```

## Options

- `-i, --input`: Input file with targets to scan
- `-o, --output`: Output report file
- `-p, --ports`: Ports to scan (default: common web ports)
- `--timeout`: Scan timeout in seconds (default: 300)
"""
    }
    
    # Create docs for tools that don't have them
    for tool_name, doc_content in tool_docs.items():
        doc_path = os.path.join(DOCS_DIR, f"{tool_name}.md")
        if not os.path.exists(doc_path):
            try:
                with open(doc_path, 'w') as doc_file:
                    doc_file.write(doc_content)
                print(f"{Fore.GREEN}✓ Created documentation: {doc_path}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}Error creating documentation for {tool_name}: {str(e)}{Style.RESET_ALL}")
    
    # Copy credential scanner README
    try:
        root_readme = os.path.join(os.path.dirname(BASE_DIR), "README.md")
        cred_scanner_doc = os.path.join(DOCS_DIR, "credential_scanner.md")
        if os.path.exists(root_readme) and not os.path.exists(cred_scanner_doc):
            shutil.copy2(root_readme, cred_scanner_doc)
            print(f"{Fore.GREEN}✓ Created documentation: {cred_scanner_doc}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error creating credential scanner documentation: {str(e)}{Style.RESET_ALL}")
    
    return True

def main():
    """Main setup function."""
    print_banner()
    
    # Check requirements
    if not check_requirements():
        print(f"{Fore.RED}Setup failed: System requirements not met.{Style.RESET_ALL}")
        return False
    
    # Create directories
    if not create_directories():
        print(f"{Fore.RED}Setup failed: Could not create directories.{Style.RESET_ALL}")
        return False
    
    # Install dependencies
    if not install_dependencies():
        print(f"{Fore.YELLOW}Warning: Some dependencies could not be installed.{Style.RESET_ALL}")
    
    # Copy tools
    if not copy_tools():
        print(f"{Fore.RED}Setup failed: Could not copy tools.{Style.RESET_ALL}")
        return False
    
    # Create tool-specific READMEs
    create_tool_readmes()
    
    print(f"\n{Fore.GREEN}SecRecon setup completed successfully!{Style.RESET_ALL}")
    print(f"\n{Fore.CYAN}To start using SecRecon, run:{Style.RESET_ALL}")
    print(f"  {Fore.YELLOW}python secrecon.py{Style.RESET_ALL}")
    
    return True

if __name__ == "__main__":
    main() 