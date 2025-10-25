import requests
import time
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
from src.generator.payload_generator import PayloadGenerator

# Advanced vulnerability detection patterns
VULNERABILITY_PATTERNS = {
    'sql_injection': {
        'patterns': [
            r'sql syntax', r'mysql.*error', r'oracle.*error', r'postgresql.*error',
            r'microsoft sql', r'odbc.*error', r'jdbc.*error', r'sqlite.*error',
            r'union.*select', r'information_schema', r'database error'
        ],
        'severity': 'High',
        'description': 'SQL Injection'
    },
    'xss_reflected': {
        'patterns': [
            r'<script[^>]*>.*?</script>', r'javascript:', r'on\w+\s*=',
            r'<iframe[^>]*>.*?</iframe>', r'<object[^>]*>.*?</object>',
            r'<embed[^>]*>.*?</embed>', r'<form[^>]*>.*?</form>',
            r'document\.cookie', r'document\.domain', r'alert\s*\('
        ],
        'severity': 'High',
        'description': 'Cross-Site Scripting (XSS)'
    },
    'command_injection': {
        'patterns': [
            r'uid=\d+', r'gid=\d+', r'/bin/bash', r'/bin/sh',
            r'command not found', r'permission denied', r'sudo:', r'su:',
            r'root:', r'/etc/passwd', r'/etc/shadow'
        ],
        'severity': 'High',
        'description': 'Command Injection'
    },
    'path_traversal': {
        'patterns': [
            r'root:', r'/etc/', r'/home/', r'/var/', r'/usr/',
            r'C:\\\\', r'D:\\\\', r'E:\\\\', r'boot\.ini', r'web\.config'
        ],
        'severity': 'Medium',
        'description': 'Path Traversal'
    },
    'ldap_injection': {
        'patterns': [
            r'ldap.*error', r'(&(.*)(\\).*))', r'objectclass', r'dc=',
            r'ou=', r'cn=', r'LDAP syntax'
        ],
        'severity': 'Medium',
        'description': 'LDAP Injection'
    },
    'xxe': {
        'patterns': [
            r'<!ENTITY', r'<!DOCTYPE', r'SYSTEM\s+', r'PUBLIC\s+',
            r'xml.*error', r'entity.*error'
        ],
        'severity': 'Medium',
        'description': 'XML External Entity (XXE)'
    }
}

def check_response(response):
    """Analyzes the HTTP response for potential vulnerability indicators using advanced pattern matching."""
    
    status_code = response.status_code
    response_time = response.elapsed.total_seconds()
    response_text = response.text.lower()
    response_headers = {k.lower(): v.lower() for k, v in response.headers.items()}
    
    # Check status codes
    if status_code >= 500:
        return "High - Server Error (5xx)"
    elif status_code == 403:
        return "Medium - Forbidden (403) - Possible Path Traversal"
    elif status_code == 302 or status_code == 301:
        # Check for potential open redirect
        location = response_headers.get('location', '')
        if 'http' in location and not location.startswith(response.url.rstrip('/').lower()):
            return "Medium - Redirect - Potential Open Redirect"
    
    # Check response time for timing attacks
    if response_time > 5.0:
        return "Medium - Slow Response Time (>5s) - Possible Timing Attack"
    
    # Advanced pattern matching for various vulnerabilities
    for vuln_type, vuln_info in VULNERABILITY_PATTERNS.items():
        for pattern in vuln_info['patterns']:
            if re.search(pattern, response_text, re.IGNORECASE):
                return f"{vuln_info['severity']} - Potential {vuln_info['description']}"
    
    # Check for information disclosure in headers
    sensitive_headers = ['server', 'x-powered-by', 'x-aspnet-version', 'x-debug-token']
    for header in sensitive_headers:
        if header in response_headers:
            return "Low - Information Disclosure in Headers"
    
    # Check for directory listing
    if '<title>Index of' in response_text or 'directory listing' in response_text:
        return "Low - Directory Listing Enabled"
    
    # Check for backup files
    backup_patterns = [r'\.bak$', r'\.backup$', r'\.old$', r'~$', r'#.*#$']
    url_path = urlparse(response.url).path.lower()
    for pattern in backup_patterns:
        if re.search(pattern, url_path):
            return "Low - Potential Backup File Exposure"
    
    # Check for error pages that might leak information
    error_indicators = ['stack trace', 'debug', 'exception', 'traceback', 'fatal error']
    for indicator in error_indicators:
        if indicator in response_text:
            return "Medium - Error Information Disclosure"
    
    return None

class WebFuzzer:
    """
    Manages the fuzzing process against a target URL.
    """
    def __init__(self, base_url, max_workers=5):
        self.base_url = base_url
        self.payload_generator = PayloadGenerator() # Use our generator
        self.max_workers = max_workers
        self.session = requests.Session() # Use a session for potential cookie handling
        self.session.headers.update({
            'User-Agent': 'AI-Smart-Fuzzer/0.1'
        })
        self.lock = threading.Lock()  # For thread-safe result collection

    def fuzz_parameter(self, path, param_name, num_payloads=50, method='GET'):
        """
        Fuzzes a single URL parameter (GET or POST) using multi-threading.
        
        Args:
            path (str): The path on the target (e.g., '/search').
            param_name (str): The name of the parameter to fuzz (e.g., 'query').
            num_payloads (int): How many fuzzing attempts to make.
            method (str): HTTP method to use ('GET' or 'POST').
        """
        if method.upper() not in ['GET', 'POST']:
            raise ValueError("Method must be 'GET' or 'POST'")
            
        target_url = urljoin(self.base_url, path)
        method_upper = method.upper()
        print(f"\n--- Fuzzing Parameter '{param_name}' at {target_url} using {method_upper} ({self.max_workers} threads) ---")
        
        vulnerabilities_found = []
        start_time = time.time()
        
        # Generate all payloads first
        payloads = [self.payload_generator.generate_payload() for _ in range(num_payloads)]
        
        # Use ThreadPoolExecutor for concurrent requests
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_payload = {
                executor.submit(self._send_fuzz_request, target_url, param_name, payload, method_upper): payload 
                for payload in payloads
            }
            
            completed_count = 0
            for future in as_completed(future_to_payload):
                completed_count += 1
                payload = future_to_payload[future]
                
                try:
                    result = future.result()
                    if result:
                        with self.lock:
                            vulnerabilities_found.append(result)
                            print(f"[!] Potential Vulnerability Found!")
                            print(f"  Payload: {payload}")
                            print(f"  Indicator: {result['indicator']}")
                            print(f"  Status Code: {result['status_code']}")
                            print(f"  URL: {result['url']}")
                            
                except Exception as e:
                    print(f"  Error processing payload '{payload}': {e}")
                
                # Print progress occasionally
                if completed_count % 10 == 0:
                    print(f"  Progress: {completed_count}/{num_payloads} payloads completed...")

        elapsed_time = time.time() - start_time
        print(f"--- Fuzzing for '{param_name}' complete. Found {len(vulnerabilities_found)} potential issues in {elapsed_time:.2f}s ---")
        return vulnerabilities_found

    def _send_fuzz_request(self, target_url, param_name, payload, method):
        """
        Sends a single fuzzing request and returns vulnerability result if found.
        
        Args:
            target_url (str): The full URL to target.
            param_name (str): The parameter name to fuzz.
            payload (str): The payload to send.
            method (str): HTTP method ('GET' or 'POST').
            
        Returns:
            dict or None: Vulnerability details if found, None otherwise.
        """
        try:
            # Create a new session for each thread to avoid issues
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'AI-Smart-Fuzzer/0.1'
            })
            
            if method == 'GET':
                params = {param_name: payload}
                response = session.get(target_url, params=params, timeout=5)
            else:  # POST
                data = {param_name: payload}
                response = session.post(target_url, data=data, timeout=5)
            
            # Analyze response
            vulnerability = check_response(response)
            
            if vulnerability:
                return {
                    'payload': payload,
                    'indicator': vulnerability,
                    'url': response.url,
                    'method': method,
                    'status_code': response.status_code
                }
                
        except requests.exceptions.RequestException as e:
            pass
            
        return None


if __name__ == "__main__":
    print("WebFuzzer class defined. Ready for integration in main.py.")
    print("Remember to set up a safe test environment before running.")