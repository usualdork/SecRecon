#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced URL Credential Scanner

A comprehensive framework for systematically analyzing URLs to identify exposed sensitive information,
with particular emphasis on API credentials, authentication tokens, and cryptographic keys.
"""

import re
import os
import sys
import json
import time
import argparse
import logging
import concurrent.futures
import csv
import hashlib
from urllib.parse import urlparse, parse_qs, urljoin
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Set, Optional, Tuple, Any, Union, Iterator
from datetime import datetime
from enum import Enum

import requests
from requests.exceptions import RequestException, Timeout, ConnectionError, TooManyRedirects
import tldextract
from bs4 import BeautifulSoup, Comment
import validators
import urllib3
from colorama import Fore, Style, init as colorama_init


# Initialize colorama for cross-platform colored terminal output
colorama_init()

# Suppress insecure request warnings for non-verified SSL requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CredentialType(Enum):
    """Enumeration of credential and sensitive information types."""
    API_KEY = "API Key"
    AUTH_TOKEN = "Authentication Token"
    PASSWORD = "Password"
    EMAIL = "Email Address"
    PHONE = "Phone Number"
    IP_ADDRESS = "IP Address"
    SSH_KEY = "SSH Key"
    PGP_KEY = "PGP Key"
    CERTIFICATE = "Certificate"
    DB_CONNECTION = "Database Connection String"
    ACCESS_TOKEN = "Access Token"
    OAUTH_TOKEN = "OAuth Token"
    JWT = "JSON Web Token"
    AWS_KEY = "AWS Access Key"
    GOOGLE_API = "Google API Key"
    AZURE_KEY = "Azure Key"
    GITHUB_TOKEN = "GitHub Token"
    STRIPE_KEY = "Stripe API Key"
    TWILIO_KEY = "Twilio API Key"
    SLACK_TOKEN = "Slack Token"
    GENERIC_SECRET = "Generic Secret"


class ConfidenceLevel(Enum):
    """Confidence levels for identified credentials."""
    LOW = 0.3
    MEDIUM = 0.6
    HIGH = 0.9
    VERIFIED = 1.0


@dataclass
class CredentialMatch:
    """Data structure for representing identified credential instances."""
    credential_type: CredentialType
    value: str
    context: str
    url: str
    source_element: str = ""
    line_number: Optional[int] = None
    confidence: float = 0.5  # Default to medium confidence
    is_verified: bool = False
    hash: str = field(init=False)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def __post_init__(self):
        """Generate a hash of the credential for deduplication and reference."""
        self.hash = hashlib.sha256(f"{self.credential_type.value}:{self.value}:{self.url}".encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = asdict(self)
        result['credential_type'] = self.credential_type.value
        result['timestamp'] = self.timestamp.isoformat()
        return result
    
    def get_redacted_value(self, show_chars: int = 4) -> str:
        """Return a redacted version of the credential for display."""
        if len(self.value) <= show_chars * 2:
            return "*" * len(self.value)
        return self.value[:show_chars] + "*" * (len(self.value) - show_chars * 2) + self.value[-show_chars:]


class PatternRegistry:
    """Comprehensive repository of regex patterns for identifying various credential types."""
    
    # Email addresses
    EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    
    # Phone numbers (international formats)
    PHONE_PATTERN = r'(\+\d{1,3}[-.\s]?)?(\(\d{1,4}\)|\d{1,4})[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,4}'
    
    # IP addresses (IPv4 and IPv6)
    IPV4_PATTERN = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    IPV6_PATTERN = r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}'
    
    # API Key patterns (by provider)
    API_KEY_PATTERNS = {
        # Cloud Providers
        'AWS Access Key': r'(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        'AWS Secret Key': r'[0-9a-zA-Z/+]{40}',
        'AWS Session Token': r'FQoG[a-zA-Z0-9/+]{38}',
        'Google API': r'AIza[0-9A-Za-z\-_]{35}',
        'Google OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
        'Google Cloud Platform API Key': r'[A-Za-z0-9_]{32}',
        'Google OAuth Access Token': r'ya29\.[0-9A-Za-z\-_]+',
        'Azure Storage Account Key': r'[a-zA-Z0-9+/]{88}==',
        'Azure Connection String': r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=core\.windows\.net',
        'Azure AD Client Secret': r'[a-zA-Z0-9-~_]{34}',
        'Azure AD Application ID': r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}',
        
        # Version Control
        'GitHub': r'gh[pousr]_[0-9a-zA-Z]{36}',
        'GitHub OAuth': r'gho_[0-9a-zA-Z]{36}',
        'GitHub App': r'ghu_[0-9a-zA-Z]{36}',
        'GitHub Refresh': r'ghr_[0-9a-zA-Z]{76}',
        'GitLab Personal Access Token': r'glpat-[0-9a-zA-Z\-]{20}',
        'GitLab OAuth': r'gloa-[0-9a-zA-Z\-]{20}',
        
        # Payment Processing
        'Stripe API Key': r'(?:sk|pk|rk)_(test|live)_[0-9a-zA-Z]{24,34}',
        'Stripe Publishable Key': r'pk_(test|live)_[0-9a-zA-Z]{24,34}',
        'Square Access Token': r'sq0atp-[0-9A-Za-z\-_]{22}',
        'Square OAuth Secret': r'sq0csp-[0-9A-Za-z\-_]{43}',
        'PayPal Braintree Access Token': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
        
        # Communications
        'Twilio API Key': r'SK[0-9a-fA-F]{32}',
        'Twilio Account SID': r'AC[a-zA-Z0-9]{32}',
        'Twilio Auth Token': r'[a-zA-Z0-9]{32}',
        'SendGrid API Key': r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
        'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',
        'Slack API Token': r'xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}',
        'Slack Webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
        
        # Social Media
        'Facebook Access Token': r'EAACEdEose0cBA[0-9A-Za-z]+',
        'Facebook OAuth': r'[A-Za-z0-9]{50}',
        'Twitter API Key': r'[a-zA-Z0-9]{25}',
        'Twitter OAuth': r'[0-9a-zA-Z]{35,44}',
        'Instagram API Key': r'[0-9a-f]{7}\.([0-9a-f]{8})\.([0-9a-f]{8})',
        
        # Data & Analytics
        'Algolia API Key': r'[a-zA-Z0-9]{32}',
        'Heroku API Key': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
        'New Relic License Key': r'[0-9a-fA-F]{40}',
        'Firebase Database': r'[a-zA-Z0-9_-]{256}',
        
        # Hashing & Encryption
        'Generic API Key': r'(api|key|token|secret|password)[^a-zA-Z0-9][a-zA-Z0-9_\-]{16,64}'
    }
    
    # Authentication tokens
    AUTH_TOKEN_PATTERNS = {
        'JWT': r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
        'Refresh Token': r'refresh_token=[a-zA-Z0-9%._-]+',
        'OAuth': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
        'Bearer Token': r'bearer\s+[a-zA-Z0-9_\-.]+',
        'Access Token': r'access_token=([^&]+)',
        'Session Token': r'session[_\-]?token[=:]["\'](.*?)["\']',
        'Authentication Token': r'auth[_\-]?token[=:]["\'](.*?)["\']',
        'Token Pattern': r'[\'"][a-f0-9]{32,}[\'"]'
    }
    
    # Database connection strings
    DB_CONNECTION_PATTERNS = {
        'MySQL': r'mysql:\/\/[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9.-]+:[0-9]+\/[a-zA-Z0-9_]+',
        'PostgreSQL': r'postgres(?:ql)?:\/\/[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9.-]+:[0-9]+\/[a-zA-Z0-9_]+',
        'MongoDB': r'mongodb(?:\+srv)?:\/\/[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9.-]+(?::[0-9]+)?\/[a-zA-Z0-9_]+',
        'SQLite': r'sqlite:\/\/[a-zA-Z0-9_/.]+',
        'Oracle': r'oracle:\/\/[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9.-]+:[0-9]+\/[a-zA-Z0-9_]+',
        'Redis': r'redis:\/\/[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9.-]+:[0-9]+',
        'Cassandra': r'cassandra:\/\/[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9.-]+:[0-9]+\/[a-zA-Z0-9_]+',
        'Generic Connection String': r'(?:host|server)=[^;]+;(?:user|uid)=[^;]+;(?:password|pwd)=[^;]+'
    }
    
    # Password patterns
    PASSWORD_PATTERNS = {
        'Generic Password': r'password[=:]["\'](.*?)["\']',
        'Shell ENV Password': r'export\s+[A-Z_]+=["\'](.*?)["\']',
        'PHP Config Password': r'\$(?:db)?pass(?:word)?\s*=\s*["\'](.*?)["\']',
        'Django Settings': r'SECRET_KEY\s*=\s*["\'](.*?)["\']',
        'Rails Secret': r'secret_key_base:\s*["\'](.*?)["\']'
    }
    
    # Cryptographic keys and certificates
    CRYPTO_PATTERNS = {
        'Private Key': r'-----BEGIN (?:RSA|DSA|EC|PGP|GPG|) PRIVATE KEY( BLOCK)?-----[a-zA-Z0-9\s/+=]+-----END (?:RSA|DSA|EC|PGP|GPG|) PRIVATE KEY( BLOCK)?-----',
        'Public Key': r'-----BEGIN (?:RSA|DSA|EC|PGP|GPG|) PUBLIC KEY( BLOCK)?-----[a-zA-Z0-9\s/+=]+-----END (?:RSA|DSA|EC|PGP|GPG|) PUBLIC KEY( BLOCK)?-----',
        'SSH Private Key': r'-----BEGIN OPENSSH PRIVATE KEY-----[a-zA-Z0-9\s/+=]+-----END OPENSSH PRIVATE KEY-----',
        'Certificate': r'-----BEGIN CERTIFICATE-----[a-zA-Z0-9\s/+=]+-----END CERTIFICATE-----',
        'PGP Key': r'-----BEGIN PGP PRIVATE KEY BLOCK-----[a-zA-Z0-9\s/+=]+-----END PGP PRIVATE KEY BLOCK-----'
    }
    
    # JavaScript hardcoded credentials
    JS_CREDENTIAL_PATTERNS = {
        'API Key in JS': r'(?:api|auth|auth_)(?:_?key|token|secret)[\'"\s:=]+([\'"][a-zA-Z0-9_\-\.]{16,}[\'"])',
        'AWS Key in JS': r'(?:accessKeyId|secretAccessKey)[\'"\s:=]+([\'"][a-zA-Z0-9/+]{20,}[\'"])',
        'Firebase Config': r'apiKey[\'":\s]+["\'](AIza[0-9A-Za-z\-_]{35})["\']',
        'Hard-coded Secret': r'(?:secret|token|password|key)[\'":\s]+["\']((?!null|undefined|false|true|function)[a-zA-Z0-9_\-\.@#\$%\^&\*]{8,})["\']'
    }
    
    # URL query parameters that might contain credentials
    URL_PARAM_PATTERNS = {
        'Auth Param': r'(?:access_token|auth|auth_token|api_key|apikey|password|pw|token|secret|key)=([^&]{8,})',
        'Bearer Token In URL': r'bearer=([^&]{8,})',
        'Session ID': r'(?:session|sid)=([^&]{16,})'
    }
    
    # Headers that might contain credentials
    HEADER_PATTERNS = {
        'Authorization': r'Authorization:\s*(?:Basic|Bearer|API-Key|Token)\s+([a-zA-Z0-9/+=._-]+)',
        'API Key Header': r'(?:X-Api-Key|api-key|x-api-token|x-auth-token):\s*([a-zA-Z0-9/+=._-]+)'
    }


class ContentAnalyzer:
    """Analyzes different content types for credential extraction."""
    
    def __init__(self, scanner):
        """Initialize with reference to parent scanner for access to patterns."""
        self.scanner = scanner
        self.logger = logging.getLogger(__name__)
    
    def analyze_html(self, content: str, url: str) -> List[CredentialMatch]:
        """
        Analyze HTML content for credentials.
        
        This method examines:
        - Script tags for hardcoded API keys
        - Meta tags for access tokens
        - Form fields for password/authentication inputs
        - HTML comments for developer notes containing credentials
        - Data attributes that might contain sensitive information
        """
        results = []
        # Add null check for content
        if not content:
            self.logger.debug(f"Empty HTML content received from {url}")
            return results
            
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Check script tags
            for script in soup.find_all('script'):
                if script.string:
                    js_results = self.analyze_javascript(script.string, url)
                    for result in js_results:
                        result.source_element = f"<script> tag"
                        results.append(result)
            
            # Check meta tags
            for meta in soup.find_all('meta'):
                if meta.get('content') and (meta.get('name') or meta.get('property')):
                    name = meta.get('name') or meta.get('property')
                    content_value = meta.get('content')
                    
                    # Check if meta tag contains sensitive information
                    scan_results = self.scanner.scan_text(content_value, url)
                    if scan_results:  # Add null check
                        for cred_type, matches in scan_results.items():
                            for match in matches:
                                match.source_element = f"<meta name='{name}'>"
                                match.confidence = min(match.confidence + 0.1, 1.0)
                                results.append(match)
            
            # Check form inputs
            for form in soup.find_all('form'):
                for input_field in form.find_all('input'):
                    # Check input names and values that might contain or reveal sensitive data
                    if input_field.get('type') in ['password', 'hidden']:
                        field_name = input_field.get('name', '')
                        field_value = input_field.get('value', '')
                        
                        # Check for revealing field names
                        sensitive_names = ['api', 'key', 'token', 'secret', 'auth', 'password', 'credentials']
                        if any(s in field_name.lower() for s in sensitive_names) and field_value:
                            results.append(CredentialMatch(
                                credential_type=CredentialType.GENERIC_SECRET,
                                value=field_value,
                                context=f"Form input field '{field_name}'",
                                url=url,
                                source_element=f"<input name='{field_name}'>",
                                confidence=0.7
                            ))
            
            # Check comments for potential developer notes containing credentials
            comments = soup.find_all(string=lambda text: isinstance(text, Comment))
            for comment in comments:
                comment_str = str(comment)
                comment_results = self.scanner.scan_text(comment_str, url)
                if comment_results:  # Add null check
                    for cred_type, matches in comment_results.items():
                        for match in matches:
                            match.source_element = "HTML comment"
                            match.confidence = min(match.confidence + 0.2, 1.0)
                            results.append(match)
            
            # Check data attributes
            for element in soup.find_all(attrs=lambda attrs: any(attr for attr in attrs if attr.startswith('data-'))):
                for attr_name, attr_value in element.attrs.items():
                    if attr_name.startswith('data-'):
                        # Fix the find method - it was incorrectly using a tuple
                        if any(s in attr_name.lower() for s in ['key', 'token', 'auth', 'secret']):
                            scan_results = self.scanner.scan_text(attr_value, url)
                            if scan_results and any(matches for matches in scan_results.values()):
                                for cred_type, matches in scan_results.items():
                                    if matches:
                                        for match in matches:
                                            match.source_element = f"data attribute: {attr_name}"
                                            results.append(match)

        except Exception as e:
            self.logger.error(f"Error analyzing HTML from {url}: {str(e)}")
            
        return results
    
    def analyze_javascript(self, content: str, url: str) -> List[CredentialMatch]:
        """
        Analyze JavaScript content for hardcoded credentials.
        
        This method looks for:
        - API key assignments
        - Configuration objects
        - Initialization parameters
        - AJAX request headers
        """
        results = []
        
        # Check for all JS credential patterns
        for pattern_name, pattern in PatternRegistry.JS_CREDENTIAL_PATTERNS.items():
            for match in re.finditer(pattern, content):
                credential_value = match.group(1).strip('\'"')
                # Skip if too short or likely false positive
                if len(credential_value) < 8 or credential_value in ['undefined', 'null', 'false', 'true']:
                    continue
                
                # Determine credential type based on context
                cred_type = CredentialType.GENERIC_SECRET
                if 'api' in pattern_name.lower():
                    cred_type = CredentialType.API_KEY
                elif 'aws' in pattern_name.lower():
                    cred_type = CredentialType.AWS_KEY
                
                context = content[max(0, match.start() - 30):min(len(content), match.end() + 30)]
                
                # Calculate confidence based on key characteristics
                confidence = 0.5
                if len(credential_value) >= 20:  # Longer keys are more likely to be real
                    confidence += 0.1
                if any(c in credential_value for c in ['_', '-', '.']) and any(c.isdigit() for c in credential_value):
                    confidence += 0.1  # More complex keys are more likely real
                
                results.append(CredentialMatch(
                    credential_type=cred_type,
                    value=credential_value,
                    context=context,
                    url=url,
                    source_element="JavaScript",
                    confidence=confidence
                ))
                
        # Look for fetch/AJAX calls with credentials
        ajax_headers_pattern = r'(?:headers|Authorization)[\s:]*{[^}]*((?:"[^"]*")|(?:\'[^\']*\'))\s*:\s*((?:"[^"]*")|(?:\'[^\']*\'))}' 
        for match in re.finditer(ajax_headers_pattern, content):
            header_name = match.group(1)
            header_value = match.group(2)
            
            if header_name.lower() in ['authorization', 'x-api-key', 'api-key', 'token'] and len(header_value) > 8:
                results.append(CredentialMatch(
                    credential_type=CredentialType.API_KEY,
                    value=header_value,
                    context=f"AJAX header: {header_name}",
                    url=url,
                    source_element="JavaScript AJAX call",
                    confidence=0.7
                ))
        
        return results
    
    def analyze_json(self, content: str, url: str) -> List[CredentialMatch]:
        """
        Analyze JSON content for credentials.
        
        Looks for:
        - Configuration files
        - API responses containing tokens
        - Authentication responses
        """
        results = []
        
        try:
            json_data = json.loads(content)
            # Recursively search through JSON structure
            self._scan_json_object(json_data, "", url, results)
        except json.JSONDecodeError:
            self.logger.debug(f"Invalid JSON content in {url}")
        
        return results
    
    def _scan_json_object(self, obj: Any, path: str, url: str, results: List[CredentialMatch]) -> None:
        """Recursively scan a JSON object for credentials."""
        if isinstance(obj, dict):
            for key, value in obj.items():
                new_path = f"{path}.{key}" if path else key
                # Check if the key suggests a credential
                sensitive_keys = ['api_key', 'apikey', 'secret', 'password', 'token', 'auth', 'key', 'credentials']
                
                if isinstance(value, str) and any(s in key.lower() for s in sensitive_keys):
                    # Determine credential type based on key name
                    cred_type = CredentialType.GENERIC_SECRET
                    if 'api' in key.lower():
                        cred_type = CredentialType.API_KEY
                    elif 'aws' in key.lower():
                        cred_type = CredentialType.AWS_KEY
                    elif 'token' in key.lower() or 'auth' in key.lower():
                        cred_type = CredentialType.AUTH_TOKEN
                    
                    # Skip values that are too short
                    if len(value) >= 8:
                        results.append(CredentialMatch(
                            credential_type=cred_type,
                            value=value,
                            context=f"JSON key: {new_path}",
                            url=url,
                            source_element="JSON data",
                            confidence=0.7
                        ))
                
                # Continue recursion
                self._scan_json_object(value, new_path, url, results)
        
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                new_path = f"{path}[{i}]"
                self._scan_json_object(item, new_path, url, results)


class ConfigValidator:
    """Validator for API credentials and tokens to check if they are valid."""
    
    def __init__(self, timeout: int = 5):
        """Initialize with timeout for validation requests."""
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
    
    def validate_credential(self, credential: CredentialMatch) -> bool:
        """
        Attempt to validate if a credential is real by making test API calls.
        
        Returns:
            bool: True if credential appears valid, False otherwise
        """
        # Skip validation for certain credential types
        if credential.credential_type in [CredentialType.EMAIL, CredentialType.PHONE, CredentialType.IP_ADDRESS]:
            return False
        
        try:
            if credential.credential_type == CredentialType.AWS_KEY:
                return self._validate_aws_key(credential.value)
            elif credential.credential_type == CredentialType.GOOGLE_API:
                return self._validate_google_api_key(credential.value)
            elif credential.credential_type == CredentialType.GITHUB_TOKEN:
                return self._validate_github_token(credential.value)
            # Add more specific validators here
            
            # Default validation method
            return False
        except Exception as e:
            self.logger.debug(f"Validation error for {credential.credential_type}: {str(e)}")
            return False
    
    def _validate_aws_key(self, key: str) -> bool:
        """Validate AWS API key format without making authorized AWS API calls."""
        # Only validate format to avoid making unauthorized AWS API calls
        aws_key_pattern = r'^(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}$'
        return bool(re.match(aws_key_pattern, key))
    
    def _validate_google_api_key(self, key: str) -> bool:
        """Validate Google API key with a minimal test request."""
        try:
            # Use a simple test API call to validate key format
            url = f"https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={key}"
            response = requests.get(url, timeout=self.timeout)
            # If we get specific error about invalid token format, key is likely valid format
            return 'invalid_token' in response.text
        except:
            return False
    
    def _validate_github_token(self, token: str) -> bool:
        """Validate GitHub token format."""
        # Only validate format to avoid making unauthorized GitHub API calls
        github_token_pattern = r'^gh[pousr]_[0-9a-zA-Z]{36}$'
        return bool(re.match(github_token_pattern, token))


class CredentialScanner:
    """Advanced scanner implementation for credential identification across URL content."""
    
    def __init__(self, 
                 timeout: int = 10, 
                 user_agent: str = None, 
                 verify_ssl: bool = True,
                 max_depth: int = 1,
                 max_urls_per_domain: int = 100,
                 max_concurrent_requests: int = 10,
                 validate_credentials: bool = False):
        """
        Initialize the scanner with configuration parameters.
        
        Args:
            timeout: HTTP request timeout in seconds
            user_agent: Custom User-Agent string for HTTP requests
            verify_ssl: Whether to verify SSL certificates
            max_depth: Maximum crawl depth for linked resources
            max_urls_per_domain: Maximum URLs to scan per domain
            max_concurrent_requests: Maximum concurrent HTTP requests
            validate_credentials: Whether to attempt to validate found credentials
        """
        self.timeout = timeout
        self.user_agent = user_agent or 'CredentialScanner/1.0'
        self.verify_ssl = verify_ssl
        self.max_depth = max_depth
        self.max_urls_per_domain = max_urls_per_domain
        self.max_concurrent_requests = max_concurrent_requests
        self.validate_credentials = validate_credentials
        
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        self.content_analyzer = ContentAnalyzer(self)
        self.config_validator = ConfigValidator()
        
        # Track processed URLs to avoid duplicates
        self.processed_urls = set()
        self.domain_url_count = {}
        
        # Compile regex patterns for performance
        self.compiled_patterns = self._compile_patterns()
    
    def _compile_patterns(self) -> Dict[str, Dict[str, re.Pattern]]:
        """Compile all regex patterns for efficient matching."""
        patterns = {
            'basic': {},
            'api_keys': {},
            'auth_tokens': {},
            'db_connections': {},
            'passwords': {},
            'crypto': {},
            'url_params': {},
            'headers': {}
        }
        
        # Basic patterns
        patterns['basic']['email'] = re.compile(PatternRegistry.EMAIL_PATTERN, re.IGNORECASE)
        patterns['basic']['phone'] = re.compile(PatternRegistry.PHONE_PATTERN)
        patterns['basic']['ipv4'] = re.compile(PatternRegistry.IPV4_PATTERN)
        patterns['basic']['ipv6'] = re.compile(PatternRegistry.IPV6_PATTERN)
        
        # API Keys
        for name, pattern in PatternRegistry.API_KEY_PATTERNS.items():
            patterns['api_keys'][name] = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        
        # Auth Tokens
        for name, pattern in PatternRegistry.AUTH_TOKEN_PATTERNS.items():
            patterns['auth_tokens'][name] = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        
        # DB Connections
        for name, pattern in PatternRegistry.DB_CONNECTION_PATTERNS.items():
            patterns['db_connections'][name] = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        
        # Passwords
        for name, pattern in PatternRegistry.PASSWORD_PATTERNS.items():
            patterns['passwords'][name] = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        
        # Cryptographic keys
        for name, pattern in PatternRegistry.CRYPTO_PATTERNS.items():
            patterns['crypto'][name] = re.compile(pattern, re.DOTALL | re.MULTILINE)
        
        # URL parameters
        for name, pattern in PatternRegistry.URL_PARAM_PATTERNS.items():
            patterns['url_params'][name] = re.compile(pattern)
        
        # Headers
        for name, pattern in PatternRegistry.HEADER_PATTERNS.items():
            patterns['headers'][name] = re.compile(pattern)
        
        return patterns
    
    def scan_urls_from_file(self, filepath: str) -> Dict[str, List[CredentialMatch]]:
        """
        Scan a list of URLs from a text file.
        
        Args:
            filepath: Path to file containing URLs (one per line)
            
        Returns:
            Dictionary mapping URLs to lists of credential matches
        """
        self.logger.info(f"Reading URLs from file: {filepath}")
        results = {}
        
        try:
            with open(filepath, 'r') as file:
                urls = [line.strip() for line in file if line.strip()]
                
            self.logger.info(f"Found {len(urls)} URLs in file")
            results = self.scan_urls(urls)
            
        except (IOError, OSError) as e:
            self.logger.error(f"Error reading file {filepath}: {str(e)}")
        
        return results
    
    def scan_urls(self, urls: List[str]) -> Dict[str, List[CredentialMatch]]:
        """
        Scan multiple URLs for credentials.
        
        Args:
            urls: List of URLs to scan
            
        Returns:
            Dictionary mapping URLs to lists of credential matches
        """
        results = {}
        total_urls = len(urls)
        
        self.logger.info(f"Starting scan of {total_urls} URLs")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_concurrent_requests) as executor:
            future_to_url = {executor.submit(self.scan_url, url): url for url in urls}
            
            for i, future in enumerate(concurrent.futures.as_completed(future_to_url)):
                url = future_to_url[future]
                
                try:
                    url_results = future.result()
                    if url_results:
                        results[url] = url_results
                    
                    # Log progress
                    if (i + 1) % 10 == 0 or (i + 1) == total_urls:
                        self.logger.info(f"Processed {i + 1}/{total_urls} URLs")
                
                except Exception as e:
                    self.logger.error(f"Error scanning URL {url}: {str(e)}")
        
        self.logger.info(f"Completed scanning {total_urls} URLs")
        return results
    
    def scan_url(self, url: str, depth: int = 0) -> List[CredentialMatch]:
        """
        Scan a single URL for credentials.
        
        Args:
            url: The URL to scan
            depth: Current crawl depth
            
        Returns:
            List of credential matches found
        """
        if not url or url in self.processed_urls:
            return []
        
        # Normalize URL
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = f"http://{url}"
            parsed_url = urlparse(url)
        
        # Extract domain for tracking
        domain = parsed_url.netloc
        if domain in self.domain_url_count and self.domain_url_count[domain] >= self.max_urls_per_domain:
            self.logger.debug(f"Skipping URL {url}: reached maximum limit for domain {domain}")
            return []
        
        # Mark as processed
        self.processed_urls.add(url)
        self.domain_url_count[domain] = self.domain_url_count.get(domain, 0) + 1
        
        results = []
        
        # Check URL parameters first
        param_results = self.scan_url_parameters(parsed_url)
        results.extend(param_results)
        
        try:
            # Fetch URL content
            self.logger.debug(f"Requesting URL: {url}")
            response = self.session.get(
                url, 
                timeout=self.timeout, 
                headers={'User-Agent': self.user_agent},
                verify=self.verify_ssl,
                allow_redirects=True
            )
            
            # Add status code check
            if response.status_code != 200:
                self.logger.warning(f"Non-200 status code ({response.status_code}) for URL: {url}")
                return results
                
            # Check if response content is empty
            if not response.text:
                self.logger.warning(f"Empty response content from URL: {url}")
                return results
                
            # Check response headers
            header_results = self.scan_headers(response.headers, url)
            results.extend(header_results)
            
            # Process content based on type
            content_type = response.headers.get('Content-Type', '').lower()
            
            if 'text/html' in content_type:
                html_results = self.content_analyzer.analyze_html(response.text, url)
                results.extend(html_results)
                
                # If we're below max depth, extract and queue links
                if depth < self.max_depth:
                    linked_urls = self.extract_links(response.text, url)
                    for linked_url in linked_urls:
                        if linked_url not in self.processed_urls:
                            # Process linked URL recursively
                            linked_results = self.scan_url(linked_url, depth + 1)
                            results.extend(linked_results)
            
            elif 'application/json' in content_type:
                json_results = self.content_analyzer.analyze_json(response.text, url)
                results.extend(json_results)
            
            elif 'javascript' in content_type:
                js_results = self.content_analyzer.analyze_javascript(response.text, url)
                results.extend(js_results)
            
            else:
                # For other content types, simple text scan
                text_scan_results = self.scan_text(response.text, url)
                # Add null check before iterating
                if text_scan_results:
                    for cred_type, matches in text_scan_results.items():
                        results.extend(matches)
        
        except (RequestException, ConnectionError, Timeout, TooManyRedirects) as e:
            self.logger.warning(f"Error fetching URL {url}: {str(e)}")
        except Exception as e:
            self.logger.error(f"Unexpected error scanning {url}: {str(e)}")
        
        # Validate found credentials if enabled
        if self.validate_credentials and results:
            self._validate_credentials(results)
        
        return results
    
    def scan_text(self, text: str, url: str) -> Dict[CredentialType, List[CredentialMatch]]:
        """
        Scan text content for credentials using regex patterns.
        
        Args:
            text: Text to scan
            url: Source URL
            
        Returns:
            Dictionary mapping credential types to lists of matches
        """
        results = {}
        
        # Add null check for text parameter
        if not text:
            self.logger.debug(f"Empty text content received from {url}")
            return results
            
        try:
            # Check basic patterns (email, phone, IPs)
            self._check_basic_patterns(text, url, results)
            
            # Check API keys (high priority focus)
            self._check_api_keys(text, url, results)
            
            # Check authentication tokens
            self._check_auth_tokens(text, url, results)
            
            # Check database connection strings
            self._check_db_connections(text, url, results)
            
            # Check password patterns
            self._check_password_patterns(text, url, results)
            
            # Check cryptographic keys
            self._check_crypto_patterns(text, url, results)
            
        except Exception as e:
            self.logger.error(f"Error scanning text from {url}: {str(e)}")
        
        # Always return a dictionary, even if empty
        return results
    
    def _check_basic_patterns(self, text: str, url: str, results: Dict[CredentialType, List[CredentialMatch]]) -> None:
        """Check text for basic credential patterns."""
        # Check for emails
        for match in self.compiled_patterns['basic']['email'].finditer(text):
            email = match.group(0)
            context = text[max(0, match.start() - 30):min(len(text), match.end() + 30)]
            
            match_obj = CredentialMatch(
                credential_type=CredentialType.EMAIL,
                value=email,
                context=context,
                url=url,
                confidence=0.8
            )
            
            if CredentialType.EMAIL not in results:
                results[CredentialType.EMAIL] = []
            results[CredentialType.EMAIL].append(match_obj)
        
        # Check for phone numbers
        for match in self.compiled_patterns['basic']['phone'].finditer(text):
            phone = match.group(0)
            context = text[max(0, match.start() - 30):min(len(text), match.end() + 30)]
            
            # Skip very short matches that are likely false positives
            if len(phone) < 10:  # Filter potential false positives (dates, simple numeric sequences)
                continue
                
            match_obj = CredentialMatch(
                credential_type=CredentialType.PHONE,
                value=phone,
                context=context,
                url=url,
                confidence=0.6  # Lower confidence due to potential false positives
            )
            
            if CredentialType.PHONE not in results:
                results[CredentialType.PHONE] = []
            results[CredentialType.PHONE].append(match_obj)
        
        # Check for IP addresses
        for pattern_name, pattern in [('ipv4', 'IPV4_PATTERN'), ('ipv6', 'IPV6_PATTERN')]:
            for match in self.compiled_patterns['basic'][pattern_name].finditer(text):
                ip = match.group(0)
                context = text[max(0, match.start() - 30):min(len(text), match.end() + 30)]
                
                match_obj = CredentialMatch(
                    credential_type=CredentialType.IP_ADDRESS,
                    value=ip,
                    context=context,
                    url=url,
                    confidence=0.7
                )
                
                if CredentialType.IP_ADDRESS not in results:
                    results[CredentialType.IP_ADDRESS] = []
                results[CredentialType.IP_ADDRESS].append(match_obj)
    
    def _check_api_keys(self, text: str, url: str, results: Dict[CredentialType, List[CredentialMatch]]) -> None:
        """Check text for API key patterns - high priority focus."""
        for name, pattern in self.compiled_patterns['api_keys'].items():
            for match in pattern.finditer(text):
                # Extract the API key from the match
                api_key = match.group(0)
                
                # For some patterns, we need to extract a specific group
                if match.lastindex and match.lastindex > 0:
                    api_key = match.group(1)
                
                # Skip if key seems invalid
                if len(api_key) < 8:
                    continue
                    
                context = text[max(0, match.start() - 40):min(len(text), match.end() + 40)]
                
                # Determine credential type based on provider
                cred_type = CredentialType.API_KEY
                if 'aws' in name.lower():
                    cred_type = CredentialType.AWS_KEY
                elif 'google' in name.lower():
                    cred_type = CredentialType.GOOGLE_API
                elif 'azure' in name.lower():
                    cred_type = CredentialType.AZURE_KEY
                elif 'github' in name.lower():
                    cred_type = CredentialType.GITHUB_TOKEN
                elif 'stripe' in name.lower():
                    cred_type = CredentialType.STRIPE_KEY
                elif 'twilio' in name.lower():
                    cred_type = CredentialType.TWILIO_KEY
                elif 'slack' in name.lower():
                    cred_type = CredentialType.SLACK_TOKEN
                
                # Set confidence based on pattern specificity
                confidence = 0.6  # Default confidence
                if 'generic' not in name.lower():
                    confidence = 0.8  # Higher confidence for specific provider patterns
                
                match_obj = CredentialMatch(
                    credential_type=cred_type,
                    value=api_key,
                    context=context,
                    url=url,
                    confidence=confidence
                )
                
                if cred_type not in results:
                    results[cred_type] = []
                results[cred_type].append(match_obj)
    
    def _check_auth_tokens(self, text: str, url: str, results: Dict[CredentialType, List[CredentialMatch]]) -> None:
        """Check text for authentication token patterns."""
        for name, pattern in self.compiled_patterns['auth_tokens'].items():
            for match in pattern.finditer(text):
                token = match.group(0)
                
                # For some patterns, we need to extract a specific group
                if match.lastindex and match.lastindex > 0:
                    token = match.group(1)
                
                # Skip if token seems invalid
                if len(token) < 8:
                    continue
                    
                context = text[max(0, match.start() - 30):min(len(text), match.end() + 30)]
                
                # Determine credential type based on token type
                cred_type = CredentialType.AUTH_TOKEN
                if 'jwt' in name.lower():
                    cred_type = CredentialType.JWT
                elif 'oauth' in name.lower():
                    cred_type = CredentialType.OAUTH_TOKEN
                elif 'access' in name.lower():
                    cred_type = CredentialType.ACCESS_TOKEN
                
                match_obj = CredentialMatch(
                    credential_type=cred_type,
                    value=token,
                    context=context,
                    url=url,
                    confidence=0.7
                )
                
                if cred_type not in results:
                    results[cred_type] = []
                results[cred_type].append(match_obj)
    
    def _check_db_connections(self, text: str, url: str, results: Dict[CredentialType, List[CredentialMatch]]) -> None:
        """Check text for database connection string patterns."""
        for name, pattern in self.compiled_patterns['db_connections'].items():
            for match in pattern.finditer(text):
                conn_string = match.group(0)
                context = text[max(0, match.start() - 30):min(len(text), match.end() + 30)]
                
                match_obj = CredentialMatch(
                    credential_type=CredentialType.DB_CONNECTION,
                    value=conn_string,
                    context=context,
                    url=url,
                    confidence=0.9  # High confidence for DB connection strings
                )
                
                if CredentialType.DB_CONNECTION not in results:
                    results[CredentialType.DB_CONNECTION] = []
                results[CredentialType.DB_CONNECTION].append(match_obj)
    
    def _check_password_patterns(self, text: str, url: str, results: Dict[CredentialType, List[CredentialMatch]]) -> None:
        """Check text for password patterns."""
        for name, pattern in self.compiled_patterns['passwords'].items():
            for match in pattern.finditer(text):
                if match.lastindex and match.lastindex > 0:
                    password = match.group(1)
                else:
                    password = match.group(0)
                    
                # Skip very common or obviously not passwords
                if password.lower() in ['password', 'null', 'undefined', '123456']:
                    continue
                    
                context = text[max(0, match.start() - 30):min(len(text), match.end() + 30)]
                
                match_obj = CredentialMatch(
                    credential_type=CredentialType.PASSWORD,
                    value=password,
                    context=context,
                    url=url,
                    confidence=0.7
                )
                
                if CredentialType.PASSWORD not in results:
                    results[CredentialType.PASSWORD] = []
                results[CredentialType.PASSWORD].append(match_obj)
    
    def _check_crypto_patterns(self, text: str, url: str, results: Dict[CredentialType, List[CredentialMatch]]) -> None:
        """Check text for cryptographic key patterns."""
        for name, pattern in self.compiled_patterns['crypto'].items():
            for match in pattern.finditer(text):
                key = match.group(0)
                context = text[max(0, match.start() - 10):min(len(text), match.end() + 10)]
                
                # Determine credential type based on key type
                cred_type = CredentialType.GENERIC_SECRET
                if 'private' in name.lower():
                    if 'ssh' in name.lower():
                        cred_type = CredentialType.SSH_KEY
                    else:
                        cred_type = CredentialType.PGP_KEY
                elif 'certificate' in name.lower():
                    cred_type = CredentialType.CERTIFICATE
                
                match_obj = CredentialMatch(
                    credential_type=cred_type,
                    value=key,
                    context=context,
                    url=url,
                    confidence=0.9  # High confidence for crypto keys
                )
                
                if cred_type not in results:
                    results[cred_type] = []
                results[cred_type].append(match_obj)
    
    def scan_url_parameters(self, parsed_url) -> List[CredentialMatch]:
        """
        Scan URL parameters for credentials.
        
        Args:
            parsed_url: Parsed URL object
            
        Returns:
            List of credential matches found in URL parameters
        """
        results = []
        
        # Validate input
        if not parsed_url or not hasattr(parsed_url, 'query') or not parsed_url.query:
            return results
            
        # Parse query parameters
        try:
            query_params = parse_qs(parsed_url.query)
            url_str = parsed_url.geturl()
            
            # Check parameter names for sensitive information
            sensitive_param_names = [
                'api_key', 'apikey', 'key', 'token', 'access_token', 'auth', 
                'secret', 'password', 'pwd', 'credentials', 'session'
            ]
            
            for param, values in query_params.items():
                param_lower = param.lower()
                
                # Check if parameter name suggests sensitive information
                is_sensitive_param = any(sensitive in param_lower for sensitive in sensitive_param_names)
                
                for value in values:
                    # Skip empty values
                    if not value:
                        continue
                        
                    # Skip short values or clearly non-credential values
                    if len(value) < 8 or value.lower() in ['null', 'undefined', 'false', 'true']:
                        continue
                    
                    # Higher confidence for parameters with sensitive names
                    confidence = 0.8 if is_sensitive_param else 0.5
                    
                    # Determine credential type based on parameter name
                    cred_type = CredentialType.GENERIC_SECRET
                    if 'api' in param_lower:
                        cred_type = CredentialType.API_KEY
                    elif 'token' in param_lower or 'auth' in param_lower:
                        cred_type = CredentialType.AUTH_TOKEN
                    elif 'password' in param_lower or 'pwd' in param_lower:
                        cred_type = CredentialType.PASSWORD
                    
                    results.append(CredentialMatch(
                        credential_type=cred_type,
                        value=value,
                        context=f"URL parameter: {param}",
                        url=url_str,
                        confidence=confidence
                    ))
            
            # Use regex patterns for URL parameters
            for name, pattern in self.compiled_patterns['url_params'].items():
                try:
                    for match in pattern.finditer(parsed_url.query):
                        if match and match.groups():
                            if match.lastindex and match.lastindex > 0:
                                value = match.group(1)
                            else:
                                value = match.group(0)
                            
                            # Skip empty or short values
                            if not value or len(value) < 8:
                                continue
                            
                            # Determine credential type based on pattern name
                            cred_type = CredentialType.GENERIC_SECRET
                            if 'bearer' in name.lower() or 'token' in name.lower():
                                cred_type = CredentialType.AUTH_TOKEN
                            elif 'api' in name.lower():
                                cred_type = CredentialType.API_KEY
                            elif 'session' in name.lower():
                                cred_type = CredentialType.AUTH_TOKEN
                            
                            results.append(CredentialMatch(
                                credential_type=cred_type,
                                value=value,
                                context=f"URL query: {match.group(0)}",
                                url=url_str,
                                confidence=0.7
                            ))
                except Exception as e:
                    self.logger.debug(f"Error matching pattern {name} on URL query: {str(e)}")
        except Exception as e:
            self.logger.error(f"Error scanning URL parameters: {str(e)}")
        
        return results
    
    def scan_headers(self, headers: Dict[str, str], url: str) -> List[CredentialMatch]:
        """
        Scan HTTP headers for credentials.
        
        Args:
            headers: HTTP response headers
            url: Source URL
            
        Returns:
            List of credential matches found in headers
        """
        results = []
        
        # Convert headers to string for regex scanning
        header_str = '\n'.join([f"{k}: {v}" for k, v in headers.items()])
        
        for name, pattern in self.compiled_patterns['headers'].items():
            for match in pattern.finditer(header_str):
                if match.lastindex and match.lastindex > 0:
                    value = match.group(1)
                else:
                    value = match.group(0)
                
                # Skip short values
                if len(value) < 8:
                    continue
                
                # Extract header name from match
                header_line = match.group(0)
                header_name = header_line.split(':')[0]
                
                # Determine credential type based on header
                cred_type = CredentialType.GENERIC_SECRET
                if header_name.lower() == 'authorization':
                    cred_type = CredentialType.AUTH_TOKEN
                    # Check for common authorization types
                    if value.startswith('Bearer '):
                        value = value[7:]  # Remove "Bearer " prefix
                    elif value.startswith('Basic '):
                        value = value[6:]  # Remove "Basic " prefix
                elif 'api' in header_name.lower():
                    cred_type = CredentialType.API_KEY
                
                results.append(CredentialMatch(
                    credential_type=cred_type,
                    value=value,
                    context=f"HTTP header: {header_name}",
                    url=url,
                    confidence=0.8  # High confidence for authorization headers
                ))
        
        return results
    
    def extract_links(self, html_content: str, base_url: str) -> List[str]:
        """
        Extract links from HTML content.
        
        Args:
            html_content: HTML content to parse
            base_url: Base URL for resolving relative links
            
        Returns:
            List of absolute URLs found in the HTML
        """
        links = []
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            base_domain = urlparse(base_url).netloc
            
            # Extract links from <a> tags
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href'].strip()
                
                # Skip empty, javascript, anchor, or mailto links
                if not href or href.startswith(('javascript:', '#', 'mailto:', 'tel:')):
                    continue
                
                # Resolve relative URLs
                absolute_url = urljoin(base_url, href)
                parsed_url = urlparse(absolute_url)
                
                # Only follow links in the same domain
                if parsed_url.netloc == base_domain:
                    links.append(absolute_url)
            
            # Limit number of links to avoid excessive crawling
            return links[:100]
            
        except Exception as e:
            self.logger.warning(f"Error extracting links from {base_url}: {str(e)}")
            return []
    
    def _validate_credentials(self, credentials: List[CredentialMatch]) -> None:
        """
        Attempt to validate found credentials.
        
        Args:
            credentials: List of credential matches to validate
        """
        for credential in credentials:
            is_valid = self.config_validator.validate_credential(credential)
            if is_valid:
                credential.is_verified = True
                credential.confidence = 1.0
                self.logger.info(f"Validated {credential.credential_type.value} in {credential.url}")


class OutputFormatter:
    """Formats scan results in various output formats."""
    
    @staticmethod
    def format_terminal(results: Dict[str, List[CredentialMatch]], show_context: bool = True) -> str:
        """
        Format results for terminal output with color highlighting.
        
        Args:
            results: Dictionary mapping URLs to lists of credential matches
            show_context: Whether to include context in the output
            
        Returns:
            Formatted string for terminal output
        """
        if not results:
            return f"{Fore.YELLOW}No credentials found.{Style.RESET_ALL}"
        
        output = []
        total_credentials = sum(len(matches) for matches in results.values())
        
        output.append(f"{Fore.GREEN}Found {total_credentials} potential credentials across {len(results)} URLs.{Style.RESET_ALL}\n")
        
        for url, matches in results.items():
            output.append(f"{Fore.BLUE}URL: {url}{Style.RESET_ALL}")
            
            for match in matches:
                confidence_color = Fore.GREEN if match.confidence >= 0.8 else Fore.YELLOW if match.confidence >= 0.5 else Fore.RED
                verified_str = f"{Fore.GREEN}[VERIFIED]{Style.RESET_ALL} " if match.is_verified else ""
                
                output.append(f"  {verified_str}{Fore.CYAN}{match.credential_type.value}:{Style.RESET_ALL} {match.get_redacted_value()} {confidence_color}(Confidence: {match.confidence:.1f}){Style.RESET_ALL}")
                
                if show_context and match.context:
                    context = match.context.replace('\n', ' ').strip()
                    if len(context) > 100:
                        context = context[:97] + "..."
                    output.append(f"    {Fore.MAGENTA}Context:{Style.RESET_ALL} {context}")
                
                if match.source_element:
                    output.append(f"    {Fore.MAGENTA}Source:{Style.RESET_ALL} {match.source_element}")
                
                output.append("")
        
        return "\n".join(output)
    
    @staticmethod
    def format_json(results: Dict[str, List[CredentialMatch]]) -> str:
        """
        Format results as JSON.
        
        Args:
            results: Dictionary mapping URLs to lists of credential matches
            
        Returns:
            JSON-formatted string
        """
        json_results = {}
        
        for url, matches in results.items():
            json_results[url] = [match.to_dict() for match in matches]
        
        return json.dumps(json_results, indent=2)
    
    @staticmethod
    def format_csv(results: Dict[str, List[CredentialMatch]]) -> str:
        """
        Format results as CSV.
        
        Args:
            results: Dictionary mapping URLs to lists of credential matches
            
        Returns:
            CSV-formatted string
        """
        output = []
        output.append("url,credential_type,value,context,confidence,verified,timestamp")
        
        for url, matches in results.items():
            for match in matches:
                # Escape and quote CSV fields
                # Utilize alternative quotation delimiters for structural clarity
                quoted_context = f"\"{match.context.replace('\"', '\"\"').replace('\n', ' ')}\""
                # Delimiter substitution methodology
                quoted_value = f"\"{match.get_redacted_value().replace('\"', '\"\"')}\""
                
                row = [
                    url,
                    match.credential_type.value,
                    quoted_value,
                    quoted_context,
                    str(match.confidence),
                    str(match.is_verified),
                    match.timestamp.isoformat()
                ]
                
                output.append(",".join(row))
        
        return "\n".join(output)
    
    @staticmethod
    def save_to_file(content: str, filepath: str) -> bool:
        """
        Save content to file.
        
        Args:
            content: Content to save
            filepath: Target file path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(filepath, 'w', encoding='utf-8') as file:
                file.write(content)
            return True
        except (IOError, OSError) as e:
            logging.error(f"Error writing to file {filepath}: {str(e)}")
            return False


class URLCredentialScannerCLI:
    """Command-line interface for URL Credential Scanner."""
    
    def __init__(self):
        """Initialize the CLI parser."""
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create and configure command-line argument parser."""
        parser = argparse.ArgumentParser(
            description="URL Credential Scanner - Find exposed sensitive information in URLs",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        
        # Input options
        input_group = parser.add_argument_group('Input Options')
        input_source = input_group.add_mutually_exclusive_group(required=True)
        input_source.add_argument('-u', '--url', help='Single URL to scan')
        input_source.add_argument('-f', '--file', help='File containing URLs to scan (one per line)')
        
        # Scanning options
        scan_group = parser.add_argument_group('Scanning Options')
        scan_group.add_argument('-d', '--depth', type=int, default=1, help='Maximum crawl depth (0 = no crawling)')
        scan_group.add_argument('-t', '--timeout', type=int, default=10, help='HTTP request timeout in seconds')
        scan_group.add_argument('--user-agent', default='CredentialScanner/1.0', help='User agent string')
        scan_group.add_argument('--no-verify-ssl', action='store_true', help='Disable SSL certificate verification')
        scan_group.add_argument('--max-urls', type=int, default=100, help='Maximum URLs to scan per domain')
        scan_group.add_argument('--max-concurrent', type=int, default=10, help='Maximum concurrent requests')
        scan_group.add_argument('--validate', action='store_true', help='Attempt to validate found credentials')
        
        # Output options
        output_group = parser.add_argument_group('Output Options')
        output_group.add_argument('-o', '--output', help='Output file path')
        output_group.add_argument('--format', choices=['text', 'json', 'csv'], default='text', help='Output format')
        output_group.add_argument('--no-context', action='store_true', help='Hide context in terminal output')
        
        # Logging options
        log_group = parser.add_argument_group('Logging Options')
        log_group.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO',
                              help='Logging level')
        log_group.add_argument('--log-file', help='Log file path')
        
        return parser
    
    def run(self, args=None) -> int:
        """
        Run the URL credential scanner with provided arguments.
        
        Args:
            args: Command-line arguments (if None, sys.argv is used)
            
        Returns:
            Exit code (0 for success, non-zero for errors)
        """
        args = self.parser.parse_args(args)
        
        # Configure logging
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        log_level = getattr(logging, args.log_level)
        
        if args.log_file:
            logging.basicConfig(filename=args.log_file, level=log_level, format=log_format)
        else:
            logging.basicConfig(level=log_level, format=log_format)
        
        try:
            # Initialize scanner
            scanner = CredentialScanner(
                timeout=args.timeout,
                user_agent=args.user_agent,
                verify_ssl=not args.no_verify_ssl,
                max_depth=args.depth,
                max_urls_per_domain=args.max_urls,
                max_concurrent_requests=args.max_concurrent,
                validate_credentials=args.validate
            )
            
            # Scan URLs
            if args.url:
                results = scanner.scan_urls([args.url])
            else:
                results = scanner.scan_urls_from_file(args.file)
            
            # Format and output results
            if args.format == 'json':
                formatted_results = OutputFormatter.format_json(results)
            elif args.format == 'csv':
                formatted_results = OutputFormatter.format_csv(results)
            else:
                formatted_results = OutputFormatter.format_terminal(results, not args.no_context)
            
            # Output results
            if args.output:
                if OutputFormatter.save_to_file(formatted_results, args.output):
                    print(f"Results saved to {args.output}")
                else:
                    print(f"Error saving results to {args.output}")
                    return 1
            else:
                print(formatted_results)
            
            return 0
        
        except KeyboardInterrupt:
            print("\nScan interrupted by user.")
            return 130
        except Exception as e:
            logging.error(f"Unexpected error: {str(e)}")
            return 1


def main():
    """Main entry point for the URL credential scanner."""
    cli = URLCredentialScannerCLI()
    sys.exit(cli.run())


if __name__ == "__main__":
    main()