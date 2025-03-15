#!/usr/bin/env python3

import os
import sys
import subprocess
import argparse
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored terminal output
init()

def print_banner():
    """Prints the SecRecon banner."""
    banner = f"""
{Fore.CYAN}
 _____            _____                      
|   __|___ ___   |   __|___ ___ ___ ___ ___ 
|__   | -_|  _|  |  |  | -_|  _| . |   |   |
|_____|___|___|  |_____|___|___|___|_|_|_|_|
                                             
{Fore.GREEN}Security Reconnaissance Framework{Style.RESET_ALL}
{Fore.YELLOW}Version 1.0{Style.RESET_ALL}

A comprehensive framework for security reconnaissance and vulnerability scanning.
"""
    print(banner)

def print_menu():
    """Prints the main menu options."""
    menu = f"""
{Fore.CYAN}Available Tools:{Style.RESET_ALL}

{Fore.GREEN}1.{Style.RESET_ALL} Credential Scanner   - Scan websites for exposed credentials and sensitive information
{Fore.GREEN}2.{Style.RESET_ALL} DAST Scanner        - Dynamic Application Security Testing for web applications
{Fore.GREEN}3.{Style.RESET_ALL} OWASP Scanner       - Check for OWASP Top 10 vulnerabilities
{Fore.GREEN}4.{Style.RESET_ALL} Leaked API Scanner  - Detect leaked API keys and tokens
{Fore.GREEN}5.{Style.RESET_ALL} HTTP vs HTTPS       - Analyze HTTP/HTTPS implementation differences
{Fore.GREEN}6.{Style.RESET_ALL} Subdomain Analyzer  - Validate and enumerate subdomains
{Fore.GREEN}7.{Style.RESET_ALL} Port Scanner        - Scan ports and detect web technologies

{Fore.YELLOW}0.{Style.RESET_ALL} Exit

"""
    print(menu)

def get_tool_info(tool_number):
    """Maps the tool number to the tool info including path and required arguments."""
    tool_info = {
        1: {
            "path": "tools/credential_scanner/credential_scanner.py",
            "args_prompt": {
                "domains_file": f"Enter path to domains file {Fore.YELLOW}(e.g., domains.txt containing target URLs){Style.RESET_ALL}: ",
                "-o": f"Enter output filename {Fore.YELLOW}(e.g., results.xlsx){Style.RESET_ALL} [optional]: ",
                "-d": f"Enter max crawl depth {Fore.YELLOW}(e.g., 3){Style.RESET_ALL} [optional]: ",
                "-t": f"Enter number of threads {Fore.YELLOW}(e.g., 10){Style.RESET_ALL} [optional]: "
            },
            "required_args": ["domains_file"]
        },
        2: {
            "path": "tools/dast_scanner/dast_scanner.py",
            "args_prompt": {
                "-i": f"Enter path to input file {Fore.YELLOW}(e.g., urls.txt containing target URLs){Style.RESET_ALL}: ",
                "-o": f"Enter output filename {Fore.YELLOW}(e.g., dast_report.xlsx){Style.RESET_ALL} [optional]: "
            },
            "required_args": ["-i"]
        },
        3: {
            "path": "tools/owasp_scanner/skip_problematic_domains.sh",
            "args_prompt": {
                "domains_file": f"Enter path to domains file {Fore.YELLOW}(e.g., domains.txt containing URLs to scan){Style.RESET_ALL}: "
            },
            "required_args": ["domains_file"]
        },
        4: {
            "path": "tools/leaked_api/leakedAPI.py",
            "args_prompt": {
                "targets_file": f"Enter path to targets file {Fore.YELLOW}(e.g., targets.txt containing URLs to scan){Style.RESET_ALL}: "
            },
            "required_args": ["targets_file"]
        },
        5: {
            "path": "tools/http_analyzer/httpvshttps.py",
            "args_prompt": {
                "domains_file": f"Enter path to domains file {Fore.YELLOW}(e.g., domains.txt containing target domains){Style.RESET_ALL}: "
            },
            "required_args": ["domains_file"]
        },
        6: {
            "path": "tools/subdomain_analyzer/enumeration.py",
            "args_prompt": {
                "url_file": f"Enter path to URL file {Fore.YELLOW}(e.g., domains.txt containing target domains){Style.RESET_ALL}: "
            },
            "required_args": ["url_file"]
        },
        7: {
            "path": "tools/port_scanner/portlisting.py",
            "args_prompt": {
                "targets_file": f"Enter path to targets file {Fore.YELLOW}(e.g., targets.txt containing IPs or domains){Style.RESET_ALL}: "
            },
            "required_args": ["targets_file"]
        }
    }
    return tool_info.get(tool_number)

def run_tool(tool_number):
    """Runs the selected tool with appropriate arguments."""
    tool_info = get_tool_info(tool_number)
    if not tool_info:
        print(f"{Fore.RED}Invalid selection. Please try again.{Style.RESET_ALL}")
        return
    
    tool_path = tool_info["path"]
    
    # Get the absolute path to the tool
    abs_tool_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), tool_path)
    
    # Check if the tool exists
    if not os.path.exists(abs_tool_path):
        print(f"{Fore.RED}Error: Tool not found at {abs_tool_path}{Style.RESET_ALL}")
        return

    # Check if the tool is executable (for shell scripts)
    if tool_path.endswith('.sh') and not os.access(abs_tool_path, os.X_OK):
        print(f"{Fore.YELLOW}Making {os.path.basename(tool_path)} executable...{Style.RESET_ALL}")
        os.chmod(abs_tool_path, 0o755)  # Set execute permission
    
    # Collect arguments for the tool
    cmd_args = []
    
    # Get required tool arguments
    print(f"\n{Fore.CYAN}Enter arguments for {os.path.basename(tool_path)}:{Style.RESET_ALL}")
    
    # Ask for arguments
    missing_required = False
    for arg_name, prompt in tool_info["args_prompt"].items():
        arg_value = input(prompt)
        
        # Check if required argument is provided
        if not arg_value and arg_name in tool_info["required_args"]:
            print(f"{Fore.RED}Error: {arg_name} is required.{Style.RESET_ALL}")
            missing_required = True
            continue
            
        if arg_value:
            # If the argument is a flag (starts with -), add it separately
            if arg_name.startswith("-"):
                cmd_args.append(arg_name)
                cmd_args.append(arg_value)
            else:
                cmd_args.append(arg_value)
    
    # If any required arguments are missing, don't run the tool
    if missing_required:
        print(f"{Fore.RED}Cannot run the tool because required arguments are missing.{Style.RESET_ALL}")
        return
    
    # Add any additional arguments the user might want to provide
    add_more = input(f"\n{Fore.CYAN}Add additional arguments? (y/N): {Style.RESET_ALL}").lower() == "y"
    if add_more:
        additional_args = input(f"{Fore.CYAN}Enter additional arguments (space-separated): {Style.RESET_ALL}")
        if additional_args:
            cmd_args.extend(additional_args.split())
    
    # Print the command that will be executed
    if tool_path.endswith('.py'):
        cmd = [sys.executable, abs_tool_path] + cmd_args
    elif tool_path.endswith('.sh'):
        cmd = [abs_tool_path] + cmd_args
    
    print(f"\n{Fore.CYAN}Running: {' '.join(cmd)}{Style.RESET_ALL}")
    
    # Run the tool
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Error: Tool execution failed with code {e.returncode}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")

def main():
    """Main entry point for the SecRecon framework."""
    parser = argparse.ArgumentParser(description="SecRecon - Security Reconnaissance Framework")
    parser.add_argument("--tool", type=int, choices=range(1, 8),
                        help="Directly run a specific tool (1-7)")
    args = parser.parse_args()
    
    # If a specific tool is requested, run it directly
    if args.tool:
        run_tool(args.tool)
        return
    
    # Otherwise, show the interactive menu
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print_banner()
        print_menu()
        
        try:
            choice = int(input(f"{Fore.GREEN}Enter your choice [0-7]: {Style.RESET_ALL}"))
            
            if choice == 0:
                print(f"{Fore.YELLOW}Exiting SecRecon. Goodbye!{Style.RESET_ALL}")
                break
            
            if 1 <= choice <= 7:
                run_tool(choice)
                input(f"\n{Fore.CYAN}Press Enter to return to the menu...{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Invalid choice. Please enter a number between 0 and 7.{Style.RESET_ALL}")
                input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")
        except ValueError:
            print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")
            input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")

if __name__ == "__main__":
    main() 