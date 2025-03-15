#!/usr/bin/env python3
"""
ZAP Setup Helper - Assists with setting up OWASP ZAP for DAST Scanner

This helper script checks if ZAP is available and configured correctly.
It can also help generate API keys and configure ZAP for the DAST scanner.
"""

import argparse
import os
import platform
import subprocess
import sys
import time
import re
import requests

def check_zap_installation():
    """Check if ZAP is installed and available"""
    print("Checking for OWASP ZAP installation...")
    
    # Different paths based on platform
    system = platform.system().lower()
    if system == 'windows':
        # Check common Windows paths
        common_paths = [
            os.path.join(os.environ.get('PROGRAMFILES', 'C:\\Program Files'), 'OWASP', 'Zed Attack Proxy'),
            os.path.join(os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)'), 'OWASP', 'Zed Attack Proxy')
        ]
        for path in common_paths:
            zap_bat = os.path.join(path, 'zap.bat')
            if os.path.exists(zap_bat):
                print(f"✅ ZAP installation found at: {path}")
                return True
    elif system in ['darwin', 'linux']:
        # Try to run ZAP from command line
        try:
            result = subprocess.run(['which', 'zap.sh'], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"✅ ZAP installation found at: {result.stdout.strip()}")
                return True
        except:
            pass
        
        # Check common Unix paths
        common_paths = [
            '/usr/share/zaproxy',
            '/opt/zaproxy',
            '/Applications/OWASP ZAP.app/Contents/Java',  # macOS
            os.path.expanduser('~/ZAP')
        ]
        for path in common_paths:
            zap_sh = os.path.join(path, 'zap.sh')
            if os.path.exists(zap_sh):
                print(f"✅ ZAP installation found at: {path}")
                return True
    
    print("❌ OWASP ZAP installation not found.")
    print("\nPlease install ZAP from: https://www.zaproxy.org/download/")
    return False

def check_zap_running():
    """Check if ZAP is currently running"""
    print("\nChecking if ZAP is currently running...")
    
    # Try to connect to ZAP API
    try:
        response = requests.get('http://localhost:8080/', timeout=2)
        if response.status_code == 200:
            print("✅ ZAP is running on http://localhost:8080")
            return True
    except:
        pass
    
    # Check common alternative ports
    common_ports = [8081, 8090, 8443]
    for port in common_ports:
        try:
            response = requests.get(f'http://localhost:{port}/', timeout=1)
            if response.status_code == 200:
                print(f"✅ ZAP is running on http://localhost:{port}")
                return True
        except:
            continue
    
    print("❌ ZAP does not appear to be running.")
    print("\nPlease start ZAP and try again.")
    return False

def find_api_key():
    """Try to find the ZAP API key"""
    print("\nLooking for ZAP API key...")
    
    # Different config paths based on platform
    system = platform.system().lower()
    if system == 'windows':
        config_path = os.path.join(os.environ.get('USERPROFILE', ''), '.ZAP', 'config.xml')
    else:  # Linux and macOS
        config_path = os.path.expanduser('~/.ZAP/config.xml')
    
    # Check if config exists
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                content = f.read()
                # Look for API key in config
                api_key_match = re.search(r'<apikey>(.*?)</apikey>', content)
                if api_key_match:
                    api_key = api_key_match.group(1)
                    if api_key:
                        print(f"✅ Found API key in config: {api_key}")
                        return api_key
        except:
            pass
    
    print("❌ Could not find ZAP API key automatically.")
    print("\nYou can find your API key in ZAP:")
    print("1. Open ZAP")
    print("2. Go to Tools > Options > API")
    print("3. The API Key is displayed in the dialog")
    
    # Prompt user to enter API key
    api_key = input("\nEnter your ZAP API key (or press Enter to generate one): ").strip()
    return api_key if api_key else None

def test_api_connection(api_key, zap_proxy='http://localhost:8080'):
    """Test connection to ZAP API with the provided key"""
    if not api_key:
        return False
        
    print(f"\nTesting ZAP API connection to {zap_proxy} with provided key...")
    
    try:
        # Test API connection with a simple API call
        response = requests.get(f'{zap_proxy}/JSON/core/view/version/?apikey={api_key}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if 'version' in data:
                print(f"✅ Successfully connected to ZAP API. ZAP version: {data['version']}")
                return True
    except Exception as e:
        print(f"❌ Error connecting to ZAP API: {e}")
    
    print("❌ Could not connect to ZAP API with the provided key.")
    return False

def generate_config_file(api_key, zap_proxy):
    """Generate a config file for DAST Scanner"""
    if not api_key:
        return
        
    print("\nGenerating DAST scanner configuration file...")
    
    config_file = 'dast_config.txt'
    with open(config_file, 'w') as f:
        f.write(f"ZAP_PROXY={zap_proxy}\n")
        f.write(f"ZAP_API_KEY={api_key}\n")
    
    print(f"✅ Configuration saved to {config_file}")
    print("\nYou can now run the DAST scanner with:")
    print(f"python dast_scanner.py -i sample_urls.txt -o security_report.xlsx")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='ZAP Setup Helper for DAST Scanner')
    parser.add_argument('--zap-proxy', default='http://localhost:8080', help='ZAP proxy address (default: http://localhost:8080)')
    args = parser.parse_args()
    
    print("=" * 60)
    print("ZAP Setup Helper for DAST Scanner")
    print("=" * 60)
    
    # Check ZAP installation
    check_zap_installation()
    
    # Check if ZAP is running
    if check_zap_running():
        # Find API key
        api_key = find_api_key()
        
        # Test API connection
        if api_key and test_api_connection(api_key, args.zap_proxy):
            # Generate config file
            generate_config_file(api_key, args.zap_proxy)
    
    print("\nSetup complete! If there were any issues, please refer to the README.md file.")
    print("=" * 60)

if __name__ == "__main__":
    main() 