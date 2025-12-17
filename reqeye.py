#!/usr/bin/env python3
"""
ReqEye - HTTP Security Analyzer CLI
Zero dependencies, compatible with Linux/Windows
"""

import sys
import os
import json
import re
import base64
import urllib.parse
import argparse
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional

# Color configuration (ANSI codes)
class Colors:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"
    
    # Windows compatibility
    if os.name == 'nt':
        try:
            import colorama
            colorama.init()
        except ImportError:
            # If no colorama, disable colors
            RESET = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = BRIGHT_WHITE = ""
            BRIGHT_RED = BRIGHT_GREEN = BRIGHT_YELLOW = BRIGHT_BLUE = BRIGHT_MAGENTA = BRIGHT_CYAN = ""

def print_banner():
    """Print ReqEye banner""" # Those double slashes ("\\") where annoying to work with xD
    banner_lines = [
        f"{Colors.BRIGHT_CYAN} _______  _______  _______  _______           _______",
        f"{Colors.BRIGHT_CYAN}(  ____ )(  ____ \\{Colors.BRIGHT_CYAN}(  ___  ){Colors.BRIGHT_CYAN}(  ____ \\{Colors.BRIGHT_CYAN}|\\     /|{Colors.BRIGHT_CYAN}(  ____ \\",
        f"{Colors.BRIGHT_CYAN}| (    )|| (    \\/{Colors.BRIGHT_CYAN}| (   ) |{Colors.BRIGHT_CYAN}| (    \\/{Colors.BRIGHT_CYAN}( \\   / ){Colors.BRIGHT_CYAN}| (    \\/",
        f"{Colors.BRIGHT_CYAN}| (____)|| (__    {Colors.BRIGHT_CYAN}| |   | |{Colors.BRIGHT_CYAN}| (__    {Colors.BRIGHT_CYAN}\\ (_) / {Colors.BRIGHT_CYAN}| (__    ",
        f"{Colors.BRIGHT_CYAN}|     __)|  __)   {Colors.BRIGHT_CYAN}| |   | |{Colors.BRIGHT_CYAN}|  __)    {Colors.BRIGHT_CYAN}\\   /  {Colors.BRIGHT_CYAN}|  __)   ",
        f"{Colors.BRIGHT_CYAN}| (\\ (   | (      {Colors.BRIGHT_CYAN}| | /\\| |{Colors.BRIGHT_CYAN}| (        {Colors.BRIGHT_CYAN}) (   {Colors.BRIGHT_CYAN}| (      ",
        f"{Colors.BRIGHT_CYAN}| ) \\ \\__| (____/\\{Colors.BRIGHT_CYAN}| (_\\ \\ |{Colors.BRIGHT_CYAN}| (____/\\  {Colors.BRIGHT_CYAN}| |   {Colors.BRIGHT_CYAN}| (____/\\",
        f"{Colors.BRIGHT_CYAN}|/   \\__/(_______/{Colors.BRIGHT_CYAN}(____\\/_){Colors.BRIGHT_CYAN}(_______/  {Colors.BRIGHT_CYAN}\\_/   {Colors.BRIGHT_CYAN}(_______/",
        f"{Colors.BRIGHT_MAGENTA}              By URDev | v1.4{Colors.RESET}"
    ]
    print("\n".join(banner_lines))

# Risk score constants for easier tuning
class RiskScores:
    # Critical entry points
    CRITICAL_ENDPOINT = 30
    ADMIN_ENDPOINT = 35
    PASSWORD_RESET = 30
    REGISTRATION = 20
    LOGIN = 25
    
    # High risk entry points
    FILE_UPLOAD = 20
    PAYMENT = 20
    TOKEN_IN_URL = 25
    NO_AUTH_SENSITIVE = 25
    JWT_NONE_ALG = 30
    
    # Medium risk entry points
    SENSITIVE_ACTION = 15
    DANGEROUS_METHOD = 10
    MASS_ASSIGNMENT = 12
    PATH_TRAVERSAL = 18
    IDOR_PATTERN = 15
    
    # Low risk indicators
    VERBOSE_HEADERS = 3
    SQL_KEYWORDS = 3
    XSS_PATTERNS = 3
    DEBUG_HEADERS = 8

class HTTPRequest:
    """Class to parse and store HTTP request"""
    
    def __init__(self, raw_request: str):
        self.raw = raw_request
        self.method = ""
        self.path = ""
        self.full_path = ""
        self.query_params = {}
        self.headers = {}
        self.body = ""
        self.json_body = None
        self.form_body = {}
        self.parse_request()
    
    def parse_request(self):
        lines = self.raw.strip().split('\n')
        
        # Parse first line (method, path)
        first_line = lines[0].strip()
        parts = first_line.split()
        if len(parts) >= 2:
            self.method = parts[0]
            self.full_path = parts[1]
            
            # Separate path and query params
            url_parts = self.full_path.split('?', 1)
            self.path = url_parts[0]
            if len(url_parts) > 1:
                self.query_params = self.parse_query_params(url_parts[1])
        
        # Parse headers
        i = 1
        while i < len(lines) and lines[i].strip():
            if ': ' in lines[i]:
                key, value = lines[i].split(': ', 1)
                self.headers[key] = value
            i += 1
        
        # Parse body (if exists)
        i += 1  # Skip blank line
        if i < len(lines):
            self.body = '\n'.join(lines[i:])
            self.parse_body()
    
    def parse_query_params(self, query_string: str) -> Dict:
        params = {}
        try:
            for param in query_string.split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    params[key] = urllib.parse.unquote(value)
        except:
            pass
        return params
    
    def parse_body(self):
        if not self.body:
            return
        
        # Try to parse as JSON
        try:
            self.json_body = json.loads(self.body)
            return
        except:
            pass
        
        # Try to parse as form data
        if '&' in self.body and '=' in self.body:
            try:
                for item in self.body.split('&'):
                    if '=' in item:
                        key, value = item.split('=', 1)
                        self.form_body[key] = urllib.parse.unquote(value)
            except:
                pass

class SecurityAnalyzer:
    """Security analyzer for HTTP endpoints - Focused on finding entry points"""
    
    # Critical entry points for testing
    CRITICAL_ENTRY_POINTS = [
        # Authentication & Authorization
        r'login', r'signin', r'auth', r'authenticate', r'access',
        r'register', r'signup', r'registration', r'create', r'join',
        r'reset', r'password', r'forgot', r'recovery', r'change',
        r'logout', r'signout', r'session', r'token', r'oauth',
        
        # Administrative functions
        r'admin', r'administrator', r'superuser', r'root', r'system',
        r'manager', r'moderator', r'support', r'staff', r'control',
        r'dashboard', r'panel', r'console', r'backoffice',
        
        # User management
        r'user', r'account', r'profile', r'member', r'customer',
        r'client', r'employee', r'staff',
        
        # Financial operations
        r'payment', r'checkout', r'buy', r'purchase', r'order',
        r'cart', r'basket', r'wallet', r'balance', r'credit',
        r'invoice', r'billing', r'subscription', r'premium',
        
        # Data manipulation
        r'delete', r'remove', r'destroy', r'erase', r'purge',
        r'update', r'edit', r'modify', r'change', r'alter',
        r'create', r'add', r'insert', r'new', r'generate',
        
        # File operations
        r'upload', r'file', r'document', r'image', r'media',
        r'attachment', r'import', r'export', r'download',
        
        # Configuration & Settings
        r'settings', r'config', r'configuration', r'preferences',
        r'setup', r'install', r'initialize', r'reset',
        
        # API endpoints
        r'/api/', r'/v\d+/', r'/graphql', r'/rest/', r'/jsonrpc',
        r'/soap', r'/rpc', r'/webhook', r'/callback',
        
        # Sensitive operations
        r'verify', r'validation', r'confirm', r'activation',
        r'approve', r'reject', r'grant', r'revoke', r'enable',
        r'disable', r'lock', r'unlock', r'ban', r'unban'
    ]
    
    # Parameter names that indicate entry points
    ENTRY_POINT_PARAMS = [
        # Authentication
        'username', 'email', 'password', 'pass', 'pin', 'token',
        'code', 'otp', 'secret', 'key', 'credential',
        
        # Authorization & Roles
        'role', 'admin', 'privilege', 'permission', 'access',
        'level', 'type', 'group', 'team', 'department',
        
        # ID parameters (IDOR vectors)
        'id', 'user_id', 'account_id', 'order_id', 'payment_id',
        'document_id', 'file_id', 'session_id', 'transaction_id',
        
        # State manipulation
        'status', 'state', 'active', 'enabled', 'verified',
        'approved', 'confirmed', 'locked', 'banned',
        
        # Price/amount manipulation
        'price', 'amount', 'total', 'cost', 'value', 'discount',
        'quantity', 'count', 'limit', 'offset',
        
        # File upload parameters
        'file', 'filename', 'path', 'directory', 'upload',
        'content', 'data', 'payload', 'attachment',
        
        # Command/query parameters
        'cmd', 'command', 'exec', 'execute', 'run', 'query',
        'search', 'filter', 'sort', 'order', 'select'
    ]
    
    # JWT claim parameters
    JWT_CLAIMS = ['sub', 'aud', 'iss', 'exp', 'nbf', 'iat', 'jti']
    
    # Dangerous HTTP methods
    DANGEROUS_METHODS = ['PUT', 'DELETE', 'PATCH', 'POST', 'OPTIONS', 'TRACE']
    
    def __init__(self, request: HTTPRequest):
        self.request = request
        self.findings = []
        self.risk_score = 0
        self.endpoint_type = "Generic"
        self.jwt_info = None
        self.endpoint_category = "Unknown"
        self.endpoint_specific_type = "Unknown"
        self.entry_points_found = []
    
    def analyze(self):
        """Run all security analyses focused on finding entry points"""
        self.classify_endpoint()
        self.classify_specific_endpoint()
        self.find_entry_points()
        self.analyze_authentication()
        self.analyze_authorization_vectors()
        self.analyze_idor_vectors()
        self.analyze_injection_vectors()
        self.analyze_file_upload_vectors()
        self.analyze_business_logic_vectors()
        self.calculate_risk_score()
    
    def classify_endpoint(self):
        """Classify endpoint type - Looking for critical entry points"""
        path_lower = self.request.path.lower()
        
        for pattern in self.CRITICAL_ENTRY_POINTS:
            if re.search(pattern, path_lower, re.IGNORECASE):
                self.endpoint_type = "Critical Entry Point"
                self.add_finding(f"🚨 CRITICAL ENTRY POINT: Endpoint matches '{pattern}' pattern", "CRITICAL", Colors.BRIGHT_RED)
                self.risk_score += RiskScores.CRITICAL_ENDPOINT
                self.entry_points_found.append(f"Path pattern: {pattern}")
                break
        
        if self.endpoint_type == "Generic":
            self.add_finding("Endpoint appears to be generic", "INFO", Colors.CYAN)
    
    def classify_specific_endpoint(self):
        """Classify specific endpoint type for targeted testing"""
        path_lower = self.request.path.lower()
        
        # Admin endpoints
        admin_patterns = [r'admin', r'administrator', r'root', r'superuser', r'manager']
        for pattern in admin_patterns:
            if re.search(pattern, path_lower, re.IGNORECASE):
                self.endpoint_category = "Administration"
                self.endpoint_specific_type = "Admin Interface"
                self.add_finding(f"👑 ADMIN INTERFACE: Potential admin endpoint detected", "CRITICAL", Colors.BRIGHT_RED)
                self.risk_score += RiskScores.ADMIN_ENDPOINT
                return
        
        # Registration endpoints
        reg_patterns = [r'register', r'signup', r'registration', r'create', r'join']
        for pattern in reg_patterns:
            if re.search(pattern, path_lower, re.IGNORECASE):
                self.endpoint_category = "Authentication"
                self.endpoint_specific_type = "User Registration"
                self.add_finding(f"📝 REGISTRATION: User registration endpoint", "CRITICAL", Colors.BRIGHT_MAGENTA)
                self.risk_score += RiskScores.REGISTRATION
                return
        
        # Login endpoints
        login_patterns = [r'login', r'signin', r'auth', r'authenticate']
        for pattern in login_patterns:
            if re.search(pattern, path_lower, re.IGNORECASE):
                self.endpoint_category = "Authentication"
                self.endpoint_specific_type = "Login"
                self.add_finding(f"🔐 LOGIN: Authentication endpoint", "CRITICAL", Colors.BRIGHT_MAGENTA)
                self.risk_score += RiskScores.LOGIN
                return
        
        # Password reset endpoints
        reset_patterns = [r'reset', r'forgot', r'recovery', r'change.*password']
        for pattern in reset_patterns:
            if re.search(pattern, path_lower, re.IGNORECASE):
                self.endpoint_category = "Authentication"
                self.endpoint_specific_type = "Password Reset"
                self.add_finding(f"🔑 PASSWORD RESET: Account recovery endpoint", "CRITICAL", Colors.BRIGHT_RED)
                self.risk_score += RiskScores.PASSWORD_RESET
                return
        
        # File upload endpoints
        upload_patterns = [r'upload', r'file', r'document', r'image', r'media']
        for pattern in upload_patterns:
            if re.search(pattern, path_lower, re.IGNORECASE):
                self.endpoint_category = "File Operations"
                self.endpoint_specific_type = "File Upload"
                self.add_finding(f"📁 FILE UPLOAD: Potential file upload endpoint", "HIGH", Colors.BRIGHT_YELLOW)
                self.risk_score += RiskScores.FILE_UPLOAD
                return
        
        # Payment endpoints
        payment_patterns = [r'payment', r'checkout', r'buy', r'purchase', r'order']
        for pattern in payment_patterns:
            if re.search(pattern, path_lower, re.IGNORECASE):
                self.endpoint_category = "Financial"
                self.endpoint_specific_type = "Payment Processing"
                self.add_finding(f"💰 PAYMENT: Financial transaction endpoint", "HIGH", Colors.BRIGHT_YELLOW)
                self.risk_score += RiskScores.PAYMENT
                return
        
        # API endpoints
        api_patterns = [r'/api/', r'/v\d+/', r'/graphql', r'/rest/']
        for pattern in api_patterns:
            if re.search(pattern, path_lower, re.IGNORECASE):
                self.endpoint_category = "API"
                self.endpoint_specific_type = "API Endpoint"
                self.add_finding(f"🔌 API ENDPOINT: API interface detected", "MEDIUM", Colors.YELLOW)
                self.risk_score += 10
                return
    
    def find_entry_points(self):
        """Find all potential entry points in the request"""
        self.entry_points_found = []
        
        # 1. URL Path entry points
        self.find_url_entry_points()
        
        # 2. Query parameter entry points
        self.find_query_param_entry_points()
        
        # 3. Body parameter entry points
        self.find_body_param_entry_points()
        
        # 4. Header entry points
        self.find_header_entry_points()
        
        # 5. Method-based entry points
        self.find_method_entry_points()
        
        # Report summary
        if self.entry_points_found:
            self.add_finding(f"🎯 Found {len(self.entry_points_found)} potential entry points for testing", "INFO", Colors.BRIGHT_CYAN)
    
    def find_url_entry_points(self):
        """Find entry points in URL path"""
        path = self.request.path
        
        # Look for numeric IDs in path (IDOR vectors)
        id_patterns = [r'/\d+', r'/id/\d+', r'/user/\d+', r'/account/\d+']
        for pattern in id_patterns:
            if re.search(pattern, path):
                self.entry_points_found.append(f"URL ID: {re.search(pattern, path).group()}")
                self.add_finding(f"🔢 NUMERIC ID IN URL: Potential IDOR vector", "HIGH", Colors.BRIGHT_YELLOW)
                self.risk_score += RiskScores.IDOR_PATTERN
        
        # Look for UUIDs or tokens in path
        uuid_pattern = r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        if re.search(uuid_pattern, path, re.IGNORECASE):
            self.entry_points_found.append("URL UUID: UUID detected in path")
            self.add_finding(f"🆔 UUID IN URL: Unique identifier in path", "MEDIUM", Colors.YELLOW)
            self.risk_score += 5
        
        # Look for file extensions
        file_ext_pattern = r'\.(php|asp|aspx|jsp|py|rb|pl|sh|exe|bat|cmd)$'
        if re.search(file_ext_pattern, path, re.IGNORECASE):
            self.entry_points_found.append(f"File extension in URL: {path}")
            self.add_finding(f"📄 FILE EXTENSION IN URL: Potential file inclusion", "MEDIUM", Colors.YELLOW)
            self.risk_score += 8
    
    def find_query_param_entry_points(self):
        """Find entry points in query parameters"""
        for param_name, param_value in self.request.query_params.items():
            param_lower = param_name.lower()
            
            # Check if parameter is an entry point
            for entry_point in self.ENTRY_POINT_PARAMS:
                if entry_point in param_lower:
                    self.entry_points_found.append(f"Query param: {param_name}")
                    
                    # Special handling for different types
                    if any(id_word in param_lower for id_word in ['id', 'num', 'ref', 'code']):
                        if param_value.isdigit():
                            self.add_finding(f"🔢 QUERY ID PARAM: '{param_name}' with numeric value - IDOR candidate", "HIGH", Colors.BRIGHT_YELLOW)
                            self.risk_score += RiskScores.IDOR_PATTERN
                    
                    elif 'token' in param_lower or 'key' in param_lower or 'secret' in param_lower:
                        if len(param_value) > 10:
                            self.add_finding(f"🔑 TOKEN IN QUERY: '{param_name}' - Potential token leakage", "HIGH", Colors.BRIGHT_RED)
                            self.risk_score += RiskScores.TOKEN_IN_URL
                    
                    elif 'file' in param_lower or 'path' in param_lower:
                        self.add_finding(f"📁 FILE PARAMETER: '{param_name}' - Potential file inclusion", "MEDIUM", Colors.YELLOW)
                        self.risk_score += 8
                    
                    else:
                        self.add_finding(f"🎯 ENTRY POINT PARAM: '{param_name}' - User-controlled input", "MEDIUM", Colors.YELLOW)
                        self.risk_score += 5
                    break
            
            # Check for path traversal patterns
            if any(pattern in param_value for pattern in ['../', '..\\', '~/']):
                self.entry_points_found.append(f"Path traversal in: {param_name}")
                self.add_finding(f"🗺️ PATH TRAVERSAL: '{param_name}' contains traversal pattern", "HIGH", Colors.BRIGHT_YELLOW)
                self.risk_score += RiskScores.PATH_TRAVERSAL
    
    def find_body_param_entry_points(self):
        """Find entry points in request body"""
        all_params = {}
        
        # Combine all body parameters
        if self.request.json_body and isinstance(self.request.json_body, dict):
            self.extract_params_from_dict(self.request.json_body, all_params)
        
        all_params.update(self.request.form_body)
        
        for param_name, param_value in all_params.items():
            param_lower = param_name.lower()
            
            # Check if parameter is an entry point
            for entry_point in self.ENTRY_POINT_PARAMS:
                if entry_point in param_lower:
                    self.entry_points_found.append(f"Body param: {param_name}")
                    
                    # Special handling
                    if 'role' in param_lower or 'admin' in param_lower or 'privilege' in param_lower:
                        self.add_finding(f"👑 ROLE PARAMETER: '{param_name}' - Privilege escalation vector", "HIGH", Colors.BRIGHT_YELLOW)
                        self.risk_score += 15
                    
                    elif 'password' in param_lower or 'pass' in param_lower:
                        self.add_finding(f"🔐 PASSWORD PARAMETER: '{param_name}' - Authentication vector", "HIGH", Colors.BRIGHT_MAGENTA)
                        self.risk_score += 10
                    
                    elif 'price' in param_lower or 'amount' in param_lower or 'total' in param_lower:
                        self.add_finding(f"💰 PRICE PARAMETER: '{param_name}' - Business logic manipulation", "MEDIUM", Colors.YELLOW)
                        self.risk_score += 12
                    
                    elif 'status' in param_lower or 'state' in param_lower or 'active' in param_lower:
                        self.add_finding(f"🔄 STATUS PARAMETER: '{param_name}' - State manipulation vector", "MEDIUM", Colors.YELLOW)
                        self.risk_score += 10
                    
                    else:
                        self.add_finding(f"🎯 BODY ENTRY POINT: '{param_name}' - User-controlled input", "MEDIUM", Colors.YELLOW)
                        self.risk_score += 5
                    break
            
            # Check for injection patterns (low severity - just indicators)
            if any(pattern in str(param_value).lower() for pattern in ['<script>', 'javascript:', 'onload=']):
                self.add_finding(f"🎨 XSS INDICATOR: '{param_name}' contains XSS patterns", "LOW", Colors.GREEN)
                self.risk_score += RiskScores.XSS_PATTERNS
            
            if any(pattern in str(param_value).lower() for pattern in ['union', 'select', 'insert', 'delete']):
                self.add_finding(f"🗃️ SQL INDICATOR: '{param_name}' contains SQL keywords", "LOW", Colors.GREEN)
                self.risk_score += RiskScores.SQL_KEYWORDS
        
        # Check for mass assignment
        if len(all_params) > 15:
            self.entry_points_found.append(f"Mass assignment: {len(all_params)} parameters")
            self.add_finding(f"📦 MASS ASSIGNMENT: {len(all_params)} parameters - Overwrite vulnerability", "MEDIUM", Colors.YELLOW)
            self.risk_score += RiskScores.MASS_ASSIGNMENT
    
    def find_header_entry_points(self):
        """Find entry points in request headers"""
        headers = self.request.headers
        
        # Authentication headers
        auth_headers = [h for h in headers.keys() 
                       if any(word in h.lower() for word in ['auth', 'token', 'key', 'bearer', 'session'])]
        
        if auth_headers:
            self.entry_points_found.append(f"Auth headers: {', '.join(auth_headers)}")
            self.add_finding(f"🔐 AUTH HEADERS: {len(auth_headers)} authentication headers found", "INFO", Colors.CYAN)
        
        # CSRF token headers
        csrf_headers = [h for h in headers.keys() if 'csrf' in h.lower() or 'xsrf' in h.lower()]
        if csrf_headers:
            self.entry_points_found.append(f"CSRF tokens: {', '.join(csrf_headers)}")
            self.add_finding(f"🛡️ CSRF TOKENS: CSRF protection headers present", "INFO", Colors.GREEN)
        
        # Debug/verbose headers
        debug_headers = ['X-Debug', 'Debug', 'X-Debug-Token', 'X-Php-Ob-Level']
        for header in debug_headers:
            if header in headers:
                self.entry_points_found.append(f"Debug header: {header}")
                self.add_finding(f"🐛 DEBUG HEADER: '{header}' - Potential information leak", "MEDIUM", Colors.YELLOW)
                self.risk_score += RiskScores.DEBUG_HEADERS
        
        # Custom headers that might be attack vectors
        custom_headers = ['X-Forwarded-For', 'X-Real-IP', 'X-Original-URL', 'X-Rewrite-URL']
        for header in custom_headers:
            if header in headers:
                self.entry_points_found.append(f"Custom header: {header}")
                self.add_finding(f"🎭 CUSTOM HEADER: '{header}' - Potential spoofing vector", "INFO", Colors.CYAN)
    
    def find_method_entry_points(self):
        """Find entry points based on HTTP method"""
        if self.request.method in self.DANGEROUS_METHODS:
            self.entry_points_found.append(f"Dangerous method: {self.request.method}")
            
            if self.request.method == 'DELETE':
                self.add_finding(f"🗑️ DELETE METHOD: Data destruction endpoint", "HIGH", Colors.BRIGHT_YELLOW)
                self.risk_score += RiskScores.DANGEROUS_METHOD + 5
            
            elif self.request.method == 'PUT':
                self.add_finding(f"✏️ PUT METHOD: Resource modification endpoint", "HIGH", Colors.BRIGHT_YELLOW)
                self.risk_score += RiskScores.DANGEROUS_METHOD
            
            elif self.request.method == 'PATCH':
                self.add_finding(f"🔧 PATCH METHOD: Partial resource update", "MEDIUM", Colors.YELLOW)
                self.risk_score += RiskScores.DANGEROUS_METHOD
            
            else:
                self.add_finding(f"⚡ {self.request.method} METHOD: State-changing operation", "MEDIUM", Colors.YELLOW)
                self.risk_score += RiskScores.DANGEROUS_METHOD
        
        # GET with body (unusual)
        if self.request.method == 'GET' and (self.request.json_body or self.request.form_body):
            self.entry_points_found.append("GET with body content")
            self.add_finding(f"📤 GET WITH BODY: Unusual pattern - Sensitive data might be logged", "MEDIUM", Colors.YELLOW)
            self.risk_score += 8
    
    def analyze_authentication(self):
        """Analyze authentication vectors"""
        # Check for tokens in URL
        for param, value in self.request.query_params.items():
            if any(word in param.lower() for word in ['token', 'key', 'auth', 'session']):
                if len(value) > 10:
                    self.add_finding(f"🔓 TOKEN IN URL: '{param}' - Authentication bypass vector", "HIGH", Colors.BRIGHT_RED)
                    self.risk_score += RiskScores.TOKEN_IN_URL
        
        # Check for JWT tokens
        self.detect_and_analyze_jwt()
        
        # Check for missing authentication on sensitive endpoints
        sensitive_action = any(pattern in self.request.path.lower() for pattern in self.CRITICAL_ENTRY_POINTS)
        has_auth = any('auth' in h.lower() for h in self.request.headers.keys())
        
        if sensitive_action and not has_auth:
            self.add_finding(f"🚨 NO AUTH ON SENSITIVE ENDPOINT: Potential authorization bypass", "HIGH", Colors.BRIGHT_RED)
            self.risk_score += RiskScores.NO_AUTH_SENSITIVE
    
    def analyze_authorization_vectors(self):
        """Analyze authorization and privilege escalation vectors"""
        all_params = {}
        
        # Get all parameters
        all_params.update(self.request.query_params)
        
        if self.request.json_body and isinstance(self.request.json_body, dict):
            self.extract_params_from_dict(self.request.json_body, all_params)
        
        all_params.update(self.request.form_body)
        
        # Look for role/privilege parameters
        for param_name, param_value in all_params.items():
            param_lower = param_name.lower()
            
            if any(word in param_lower for word in ['role', 'admin', 'privilege', 'permission', 'access', 'level']):
                self.add_finding(f"👑 AUTHORIZATION PARAM: '{param_name}' - Privilege escalation vector", "HIGH", Colors.BRIGHT_YELLOW)
                self.risk_score += 15
                
                # Check if value indicates elevated privileges
                if str(param_value).lower() in ['admin', 'root', 'superuser', 'true', '1']:
                    self.add_finding(f"⚡ ELEVATED VALUE: '{param_name}={param_value}' - Direct privilege assignment", "CRITICAL", Colors.BRIGHT_RED)
                    self.risk_score += 20
    
    def analyze_idor_vectors(self):
        """Analyze IDOR (Insecure Direct Object Reference) vectors"""
        # Numeric IDs in URL path
        if re.search(r'/\d+', self.request.path):
            self.add_finding(f"🔢 IDOR VECTOR: Numeric ID in URL path", "HIGH", Colors.BRIGHT_YELLOW)
            self.risk_score += RiskScores.IDOR_PATTERN
        
        # Check all parameters for ID patterns
        all_params = {}
        all_params.update(self.request.query_params)
        
        if self.request.json_body and isinstance(self.request.json_body, dict):
            self.extract_params_from_dict(self.request.json_body, all_params)
        
        all_params.update(self.request.form_body)
        
        for param_name, param_value in all_params.items():
            param_lower = param_name.lower()
            
            if any(id_word in param_lower for id_word in ['id', 'user_id', 'account_id', 'order_id']):
                if str(param_value).isdigit():
                    self.add_finding(f"🎯 IDOR CANDIDATE: '{param_name}' with numeric ID", "HIGH", Colors.BRIGHT_YELLOW)
                    self.risk_score += RiskScores.IDOR_PATTERN
                
                # Check for sequential IDs
                if str(param_value).isdigit() and int(param_value) < 1000:
                    self.add_finding(f"🔢 SEQUENTIAL ID: '{param_name}={param_value}' - Predictable identifier", "MEDIUM", Colors.YELLOW)
                    self.risk_score += 8
    
    def analyze_injection_vectors(self):
        """Analyze injection attack vectors"""
        all_params = {}
        all_params.update(self.request.query_params)
        
        if self.request.json_body and isinstance(self.request.json_body, dict):
            self.extract_params_from_dict(self.request.json_body, all_params)
        
        all_params.update(self.request.form_body)
        
        # Check for potential injection patterns
        for param_name, param_value in all_params.items():
            param_value_str = str(param_value)
            
            # SQL injection indicators
            sql_patterns = ["'", '"', '--', ';', '/*', '*/']
            sql_keywords = ['union', 'select', 'insert', 'update', 'delete', 'drop', 'create']
            
            if any(pattern in param_value_str for pattern in sql_patterns):
                self.add_finding(f"🗃️ SQL INDICATOR: '{param_name}' contains SQL special characters", "LOW", Colors.GREEN)
                self.risk_score += RiskScores.SQL_KEYWORDS
            
            if any(keyword in param_value_str.lower() for keyword in sql_keywords):
                self.add_finding(f"🗃️ SQL KEYWORD: '{param_name}' contains SQL keyword", "LOW", Colors.GREEN)
                self.risk_score += RiskScores.SQL_KEYWORDS
            
            # XSS indicators
            xss_patterns = ['<script>', '</script>', 'javascript:', 'onload=', 'onerror=', 'onclick=']
            if any(pattern in param_value_str.lower() for pattern in xss_patterns):
                self.add_finding(f"🎨 XSS INDICATOR: '{param_name}' contains XSS patterns", "LOW", Colors.GREEN)
                self.risk_score += RiskScores.XSS_PATTERNS
            
            # Command injection indicators
            cmd_patterns = ['|', '&', ';', '`', '$', '(', ')']
            if any(pattern in param_value_str for pattern in cmd_patterns):
                self.add_finding(f"💻 CMD INDICATOR: '{param_name}' contains command injection characters", "LOW", Colors.GREEN)
                self.risk_score += 3
            
            # Path traversal indicators
            if any(pattern in param_value_str for pattern in ['../', '..\\', '~/']):
                self.add_finding(f"🗺️ PATH TRAVERSAL: '{param_name}' contains directory traversal patterns", "HIGH", Colors.BRIGHT_YELLOW)
                self.risk_score += RiskScores.PATH_TRAVERSAL
    
    def analyze_file_upload_vectors(self):
        """Analyze file upload vectors"""
        # Check content-type for multipart
        content_type = self.request.headers.get('Content-Type', '')
        
        if 'multipart/form-data' in content_type:
            self.add_finding(f"📁 MULTIPART FORM: Potential file upload functionality", "HIGH", Colors.BRIGHT_YELLOW)
            self.risk_score += 15
            
            # Look for file parameters
            all_params = {}
            if self.request.json_body and isinstance(self.request.json_body, dict):
                self.extract_params_from_dict(self.request.json_body, all_params)
            
            all_params.update(self.request.form_body)
            
            for param_name in all_params.keys():
                if any(word in param_name.lower() for word in ['file', 'upload', 'image', 'document']):
                    self.add_finding(f"📤 FILE UPLOAD PARAM: '{param_name}' - File upload vector", "HIGH", Colors.BRIGHT_YELLOW)
                    self.risk_score += 10
    
    def analyze_business_logic_vectors(self):
        """Analyze business logic attack vectors"""
        all_params = {}
        all_params.update(self.request.query_params)
        
        if self.request.json_body and isinstance(self.request.json_body, dict):
            self.extract_params_from_dict(self.request.json_body, all_params)
        
        all_params.update(self.request.form_body)
        
        # Price manipulation
        for param_name, param_value in all_params.items():
            param_lower = param_name.lower()
            
            if any(price_word in param_lower for price_word in ['price', 'amount', 'total', 'cost', 'value']):
                try:
                    float_val = float(param_value)
                    if float_val > 0:
                        self.add_finding(f"💰 PRICE PARAM: '{param_name}' - Business logic manipulation vector", "MEDIUM", Colors.YELLOW)
                        self.risk_score += 12
                        
                        # Check for negative values
                        if float_val < 0:
                            self.add_finding(f"💸 NEGATIVE PRICE: '{param_name}={param_value}' - Potential negative pricing", "HIGH", Colors.BRIGHT_YELLOW)
                            self.risk_score += 15
                except:
                    pass
            
            # Quantity manipulation
            if any(qty_word in param_lower for qty_word in ['quantity', 'qty', 'count', 'number']):
                try:
                    int_val = int(param_value)
                    if int_val > 0:
                        self.add_finding(f"📦 QUANTITY PARAM: '{param_name}' - Quantity manipulation vector", "MEDIUM", Colors.YELLOW)
                        self.risk_score += 10
                        
                        # Check for large quantities
                        if int_val > 1000:
                            self.add_finding(f"🏭 LARGE QUANTITY: '{param_name}={param_value}' - Potential integer overflow", "MEDIUM", Colors.YELLOW)
                            self.risk_score += 8
                except:
                    pass
    
    def extract_params_from_dict(self, data: Dict, result: Dict, prefix: str = ""):
        """Extract parameters from nested dict"""
        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key
            
            if isinstance(value, dict):
                self.extract_params_from_dict(value, result, full_key)
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        self.extract_params_from_dict(item, result, f"{full_key}[{i}]")
                    else:
                        result[f"{full_key}[{i}]"] = str(item)
            else:
                result[full_key] = str(value)
    
    def detect_and_analyze_jwt(self):
        """Detect and analyze JWT tokens"""
        # Look in headers
        for header_name, header_value in self.request.headers.items():
            if any(word in header_name.lower() for word in ['auth', 'token', 'jwt', 'bearer']):
                if self.is_jwt(header_value):
                    self.jwt_info = self.analyze_jwt(header_value)
                    return
        
        # Look in parameters
        all_params = {}
        all_params.update(self.request.query_params)
        
        if self.request.json_body and isinstance(self.request.json_body, dict):
            self.extract_params_from_dict(self.request.json_body, all_params)
        
        all_params.update(self.request.form_body)
        
        for param_value in all_params.values():
            if self.is_jwt(str(param_value)):
                self.jwt_info = self.analyze_jwt(str(param_value))
                self.add_finding(f"🔓 JWT IN PARAMETER: Token found outside headers - Security misconfiguration", "HIGH", Colors.BRIGHT_RED)
                self.risk_score += RiskScores.TOKEN_IN_URL
                return
    
    def is_jwt(self, token: str) -> bool:
        """Check if token is JWT"""
        if not token or len(token) < 10:
            return False
        
        clean_token = token.replace("Bearer ", "")
        parts = clean_token.split('.')
        return len(parts) == 3
    
    def analyze_jwt(self, token: str) -> Dict:
        """Analyze JWT token"""
        clean_token = token.replace("Bearer ", "")
        parts = clean_token.split('.')
        
        try:
            header_json = base64.urlsafe_b64decode(parts[0] + '==').decode('utf-8')
            header = json.loads(header_json)
            
            payload_json = base64.urlsafe_b64decode(parts[1] + '==').decode('utf-8')
            payload = json.loads(payload_json)
            
            result = {
                'header': header,
                'payload': payload,
                'token': clean_token[:20] + "..." if len(clean_token) > 20 else clean_token
            }
            
            # Check for weak algorithms
            alg = header.get('alg', 'unknown')
            if alg == 'none':
                self.add_finding(f"⚡ JWT NONE ALGORITHM: 'alg=none' - Critical security flaw", "CRITICAL", Colors.BRIGHT_RED)
                self.risk_score += RiskScores.JWT_NONE_ALG
            elif alg == 'HS256':
                self.add_finding(f"🔧 JWT WEAK ALGORITHM: 'alg=HS256' - Consider algorithm confusion", "MEDIUM", Colors.YELLOW)
                self.risk_score += 5
            
            # Check for sensitive claims
            for claim in self.JWT_CLAIMS:
                if claim in payload:
                    self.add_finding(f"🎫 JWT CLAIM: '{claim}' present in token", "INFO", Colors.CYAN)
            
            return result
            
        except Exception as e:
            return {'error': str(e)}
    
    def calculate_risk_score(self):
        """Calculate final risk score"""
        self.risk_score = min(self.risk_score, 100)
    
    def add_finding(self, description: str, severity: str, color: str = Colors.WHITE):
        """Add a finding with custom color"""
        self.findings.append({
            'description': description,
            'severity': severity,
            'color': color,
            'timestamp': datetime.now().isoformat()
        })
    
    def get_risk_level(self) -> str:
        """Get risk level"""
        if self.risk_score >= 70:
            return "CRITICAL"
        elif self.risk_score >= 50:
            return "HIGH"
        elif self.risk_score >= 30:
            return "MEDIUM"
        elif self.risk_score >= 15:
            return "LOW"
        return "INFO"
    
    def print_report(self):
        """Print colorful report to terminal"""
        print(f"\n{Colors.BRIGHT_CYAN}╔{'═'*70}╗")
        print(f"║{'🚀 SECURITY ENTRY POINT ANALYSIS':^69}║")
        print(f"╚{'═'*70}╝{Colors.RESET}\n")
        
        print(f"{Colors.BRIGHT_BLUE}📍 Endpoint:{Colors.RESET} {self.request.method} {Colors.CYAN}{self.request.full_path}{Colors.RESET}")
        print(f"{Colors.BRIGHT_BLUE}🎯 Type:{Colors.RESET} {self.endpoint_type}")
        print(f"{Colors.BRIGHT_BLUE}📁 Category:{Colors.RESET} {self.endpoint_category}")
        print(f"{Colors.BRIGHT_BLUE}🔍 Specific:{Colors.RESET} {self.endpoint_specific_type}")
        print(f"{Colors.BRIGHT_BLUE}⚠️  Risk Score:{Colors.RESET} {self.get_colored_risk()}\n")
        
        # Entry Points Summary
        if self.entry_points_found:
            print(f"{Colors.BRIGHT_MAGENTA}🎯 ENTRY POINTS FOUND ({len(self.entry_points_found)}):{Colors.RESET}")
            for i, point in enumerate(self.entry_points_found[:10], 1):
                print(f"  {Colors.CYAN}{i:2}.{Colors.RESET} {point}")
            if len(self.entry_points_found) > 10:
                print(f"  {Colors.CYAN}... and {len(self.entry_points_found) - 10} more{Colors.RESET}")
            print()
        
        # JWT Info
        if self.jwt_info and 'error' not in self.jwt_info:
            print(f"{Colors.BRIGHT_YELLOW}🔐 JWT ANALYSIS:{Colors.RESET}")
            print(f"  Algorithm: {Colors.CYAN}{self.jwt_info['header'].get('alg', 'unknown')}{Colors.RESET}")
            print(f"  Claims: {Colors.CYAN}{', '.join(self.jwt_info['payload'].keys())[:50]}{Colors.RESET}\n")
        
        # Findings with colors
        if self.findings:
            print(f"{Colors.BRIGHT_GREEN}🔎 FINDINGS ({len(self.findings)}):{Colors.RESET}")
            
            # Group by severity with emojis
            severity_emojis = {
                'CRITICAL': '🚨',
                'HIGH': '⚠️ ',
                'MEDIUM': '🔧',
                'LOW': '📝',
                'INFO': 'ℹ️ '
            }
            
            findings_by_severity = {}
            for finding in self.findings:
                severity = finding['severity']
                if severity not in findings_by_severity:
                    findings_by_severity[severity] = []
                findings_by_severity[severity].append(finding)
            
            # Print by severity order
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
            for severity in severity_order:
                if severity in findings_by_severity:
                    emoji = severity_emojis.get(severity, '•')
                    print(f"\n{Colors.BRIGHT_WHITE}{emoji} {severity}:{Colors.RESET}")
                    for finding in findings_by_severity[severity]:
                        color = finding.get('color', Colors.WHITE)
                        print(f"  {color}→{Colors.RESET} {finding['description']}")
        else:
            print(f"{Colors.GREEN}✅ No security findings detected.{Colors.RESET}")
        
        # Testing Recommendations
        print(f"\n{Colors.BRIGHT_CYAN}🧪 TESTING RECOMMENDATIONS:{Colors.RESET}")
        
        if self.endpoint_category == "Administration":
            print(f"  {Colors.YELLOW}• Test for privilege escalation{Colors.RESET}")
            print(f"  {Colors.YELLOW}• Test horizontal access control{Colors.RESET}")
            print(f"  {Colors.YELLOW}• Test admin-only functionality{Colors.RESET}")
        
        elif self.endpoint_category == "Authentication":
            if "Registration" in self.endpoint_specific_type:
                print(f"  {Colors.YELLOW}• Test user enumeration{Colors.RESET}")
                print(f"  {Colors.YELLOW}• Test weak password policies{Colors.RESET}")
                print(f"  {Colors.YELLOW}• Test account confirmation bypass{Colors.RESET}")
            elif "Login" in self.endpoint_specific_type:
                print(f"  {Colors.YELLOW}• Test brute force protection{Colors.RESET}")
                print(f"  {Colors.YELLOW}• Test credential stuffing{Colors.RESET}")
                print(f"  {Colors.YELLOW}• Test account lockout bypass{Colors.RESET}")
        
        elif self.endpoint_category == "Financial":
            print(f"  {Colors.YELLOW}• Test business logic flaws{Colors.RESET}")
            print(f"  {Colors.YELLOW}• Test price manipulation{Colors.RESET}")
            print(f"  {Colors.YELLOW}• Test quantity tampering{Colors.RESET}")
        
        elif self.endpoint_category == "File Operations":
            print(f"  {Colors.YELLOW}• Test file type restrictions{Colors.RESET}")
            print(f"  {Colors.YELLOW}• Test file size limits{Colors.RESET}")
            print(f"  {Colors.YELLOW}• Test path traversal{Colors.RESET}")
        
        else:
            print(f"  {Colors.YELLOW}• Test IDOR vulnerabilities{Colors.RESET}")
            print(f"  {Colors.YELLOW}• Test parameter tampering{Colors.RESET}")
            print(f"  {Colors.YELLOW}• Test authorization bypass{Colors.RESET}")
        
        # Quick Test Cases
        print(f"\n{Colors.BRIGHT_MAGENTA}⚡ QUICK TEST CASES:{Colors.RESET}")
        if self.entry_points_found:
            print(f"  {Colors.CYAN}1.{Colors.RESET} Test ID manipulation for IDOR")
            print(f"  {Colors.CYAN}2.{Colors.RESET} Test role parameter for privilege escalation")
            print(f"  {Colors.CYAN}3.{Colors.RESET} Test price/quantity parameters")
        
        print(f"\n{Colors.CYAN}📅 Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
        print(f"{Colors.CYAN}💡 Note: All findings require manual verification{Colors.RESET}")
    
    def get_colored_risk(self) -> str:
        """Get colored risk level"""
        level = self.get_risk_level()
        color = {
            'CRITICAL': Colors.BRIGHT_RED,
            'HIGH': Colors.RED,
            'MEDIUM': Colors.YELLOW,
            'LOW': Colors.GREEN,
            'INFO': Colors.CYAN
        }.get(level, Colors.RESET)
        
        return f"{color}{self.risk_score}/100 ({level}){Colors.RESET}"

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='ReqEye - HTTP Security Analyzer CLI - Zero dependencies security tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s parse request.txt          # Parse and display request
  %(prog)s analyze request.txt        # Analyze security entry points
  %(prog)s mutate request.txt         # Generate mutated requests
  %(prog)s diff resp1.txt resp2.txt   # Compare responses
  %(prog)s report request.txt         # Generate full report
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Parser command
    parse_parser = subparsers.add_parser('parse', help='Parse HTTP request')
    parse_parser.add_argument('file', help='File containing HTTP request')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze security entry points')
    analyze_parser.add_argument('file', help='File containing HTTP request')
    
    # Mutate command
    mutate_parser = subparsers.add_parser('mutate', help='Generate mutated requests')
    mutate_parser.add_argument('file', help='File containing HTTP request')
    mutate_parser.add_argument('--idor', action='store_true', help='Generate IDOR variants')
    mutate_parser.add_argument('--auth', action='store_true', help='Generate auth variants')
    mutate_parser.add_argument('--roles', action='store_true', help='Generate role variants')
    mutate_parser.add_argument('--payloads', action='store_true', help='Generate payload variants')
    mutate_parser.add_argument('--registration', action='store_true', help='Generate registration variants')
    mutate_parser.add_argument('--all', action='store_true', help='Generate all variants')
    
    # Diff command
    diff_parser = subparsers.add_parser('diff', help='Compare responses')
    diff_parser.add_argument('file1', help='First response file')
    diff_parser.add_argument('file2', help='Second response file')
    
    # Report command
    report_parser = subparsers.add_parser('report', help='Generate report')
    report_parser.add_argument('file', help='File containing HTTP request')
    report_parser.add_argument('-o', '--output', default='security_report.txt', help='Output file')
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command in ['parse', 'analyze', 'mutate', 'report']:
            with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
                raw_request = f.read()
            
            request = HTTPRequest(raw_request)
            
            if args.command == 'parse':
                print(f"{Colors.BRIGHT_CYAN}🔍 PARSED REQUEST:{Colors.RESET}")
                print(f"{Colors.BRIGHT_BLUE}Method:{Colors.RESET} {Colors.CYAN}{request.method}{Colors.RESET}")
                print(f"{Colors.BRIGHT_BLUE}Path:{Colors.RESET} {Colors.CYAN}{request.path}{Colors.RESET}")
                print(f"{Colors.BRIGHT_BLUE}Query Params:{Colors.RESET} {Colors.CYAN}{len(request.query_params)}{Colors.RESET}")
                for k, v in request.query_params.items():
                    print(f"  {Colors.YELLOW}{k}:{Colors.RESET} {v[:50]}{'...' if len(v) > 50 else ''}")
                print(f"{Colors.BRIGHT_BLUE}Headers:{Colors.RESET} {Colors.CYAN}{len(request.headers)}{Colors.RESET}")
                for k, v in request.headers.items():
                    print(f"  {Colors.YELLOW}{k}:{Colors.RESET} {v[:80]}{'...' if len(v) > 80 else ''}")
                if request.body:
                    print(f"{Colors.BRIGHT_BLUE}Body length:{Colors.RESET} {Colors.CYAN}{len(request.body)} characters{Colors.RESET}")
                    print(f"{Colors.BRIGHT_BLUE}Body preview:{Colors.RESET}")
                    print(f"{Colors.CYAN}{request.body[:200]}...{Colors.RESET}")
            
            elif args.command == 'analyze':
                analyzer = SecurityAnalyzer(request)
                analyzer.analyze()
                analyzer.print_report()
            
            elif args.command == 'mutate':
                # Implementación básica de mutación
                print(f"{Colors.BRIGHT_CYAN}🛠️  MUTATION MODULE{Colors.RESET}")
                print(f"{Colors.YELLOW}Note: Mutation module requires full implementation{Colors.RESET}")
            
            elif args.command == 'report':
                analyzer = SecurityAnalyzer(request)
                analyzer.analyze()
                # ReportGenerator.generate_txt_report(analyzer, args.output)
                print(f"{Colors.GREEN}📄 Report generation requires full implementation{Colors.RESET}")
        
        elif args.command == 'diff':
            print(f"{Colors.BRIGHT_CYAN}🔄 RESPONSE COMPARISON{Colors.RESET}")
            print(f"{Colors.YELLOW}Note: Response comparison requires full implementation{Colors.RESET}")
    
    except FileNotFoundError:
        print(f"{Colors.RED}❌ Error: File not found{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}❌ Error: {e}{Colors.RESET}")

if __name__ == "__main__":
    main()
