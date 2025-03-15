# SecRecon: Security Reconnaissance Framework

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0-blue.svg" alt="Version 1.0">
  <img src="https://img.shields.io/badge/python-3.7+-green.svg" alt="Python 3.7+">
  <img src="https://img.shields.io/badge/license-MIT-yellow.svg" alt="License MIT">
</p>

SecRecon is a comprehensive security reconnaissance framework that combines seven powerful security testing tools into one integrated platform. Whether you're conducting penetration tests, vulnerability assessments, or security audits, SecRecon provides the tools you need for thorough reconnaissance and security analysis.

<p align="center">
  <img width="652" alt="Screenshot 2025-03-15 at 5 24 13 PM" src="https://github.com/user-attachments/assets/0ba42156-ccdd-48f0-abc1-5b6243042d00" />
</p>

## 🔥 Features

- **Unified Interface**: Access all tools through an intuitive menu-driven interface
- **Comprehensive Coverage**: From credential scanning to port analysis
- **Professional Reporting**: Generate detailed Excel reports with actionable findings
- **Flexible Deployment**: Run individual tools or use the entire framework
- **Cross-Platform**: Works on Linux, macOS, and Windows

## 🛠️ Tools Included

### 1. Credential Scanner
Scans websites for leaked credentials, API keys, and other sensitive information. Detects various types of exposed data:
- API keys (AWS, Google, Firebase, etc.)
- Tokens (JWT, OAuth, etc.)
- Passwords and private keys
- Credit card numbers and personal information

### 2. DAST Scanner
Dynamic Application Security Testing for web applications:
- SSL/TLS configuration analysis
- Security header checks
- Sensitive file exposure detection
- HTTP method testing
- Component vulnerability analysis

### 3. OWASP Scanner
Comprehensive scanning for OWASP Top 10 vulnerabilities:
- Intelligent problem domain handling
- Batch processing for efficient scanning
- Advanced timeout controls
- Detailed vulnerability reports

### 4. Leaked API Scanner
Advanced URL credential scanner focused on API security:
- Detects exposed API credentials
- Validates authentication tokens
- Identifies cryptographic keys
- Comprehensive pattern matching

### 5. HTTP vs HTTPS Analyzer
Analyzes HTTP and HTTPS implementation differences:
- Protocol accessibility analysis
- Endpoint response characteristics
- Redirect validation
- Certificate verification

### 6. Subdomain Analyzer
Validates and enumerates subdomains:
- Parallel connection establishment
- Operational status analysis
- Response validation
- Detailed reporting

### 7. Port Scanner
Nmap-based scanner with web technology detection:
- Service discovery
- Open port identification
- Web technology fingerprinting
- Comprehensive scan reports

## 📋 Requirements

- Python 3.7+
- OWASP ZAP (for OWASP Scanner)
- Various Python packages (specified in requirements.txt)
- Nmap (for Port Scanner)

## 🚀 Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/SecRecon.git
   cd SecRecon
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Set up tool-specific requirements:
   ```
   python setup.py
   ```

## 🎮 Usage

### Interactive Menu

Run the framework with the interactive menu:

```
python secrecon.py
```

### Direct Tool Access

Run a specific tool directly:

```
python secrecon.py --tool 1  # Run Credential Scanner
```

Tool numbers:
1. Credential Scanner
2. DAST Scanner
3. OWASP Scanner
4. Leaked API Scanner
5. HTTP vs HTTPS Analyzer
6. Subdomain Analyzer
7. Port Scanner

## 📊 Output

Each tool generates detailed reports in various formats:

- Excel files with color-coded risk levels
- JSON data for integration with other tools
- Terminal output for immediate feedback

Reports are saved in the `reports` directory by default.

## 📚 Documentation

For detailed usage instructions for each tool, see:

- [Credential Scanner Documentation](docs/credential_scanner.md)
- [DAST Scanner Documentation](docs/dast_scanner.md)
- [OWASP Scanner Documentation](docs/owasp_scanner.md)
- [Leaked API Scanner Documentation](docs/leaked_api.md)
- [HTTP vs HTTPS Analyzer Documentation](docs/http_analyzer.md)
- [Subdomain Analyzer Documentation](docs/subdomain_analyzer.md)
- [Port Scanner Documentation](docs/port_scanner.md)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This framework is intended for security professionals and authorized testing only. Always ensure you have permission to scan the target systems. The authors are not responsible for misuse or damage caused by this tool.

## 🔗 Acknowledgments

- OWASP Foundation for security guidelines and ZAP
- Contributors to the original tools that have been integrated
- The security community for continuous feedback and improvements

## 📬 Contact
If you have any questions or feedback, please open an issue or contact me **@usualdork**
