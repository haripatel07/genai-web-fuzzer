import requests
import time
from urllib.parse import urlparse, urljoin
from src.generator.payload_generator import PayloadGenerator

# Simple check for potential vulnerabilities based on response
def check_response(response):
    """Analyzes the HTTP response for potential vulnerability indicators."""
    
    status_code = response.status_code
    response_time = response.elapsed.total_seconds()
    
    # High-severity indicators
    if status_code >= 500: # Server errors (5xx) often indicate crashes
        return "High - Server Error (5xx)"
    if "sql syntax" in response.text.lower() or "mysql" in response.text.lower():
        return "High - Potential SQL Injection"
    if "<script>alert" in response.text.lower(): # Simple check for reflected XSS
         return "High - Potential XSS"
         
    # Medium-severity indicators
    if response_time > 3.0: # Unusually long response time
        return "Medium - Slow Response Time"
    if status_code == 403: # Forbidden - might indicate path traversal success
        return "Medium - Forbidden (403)"
        
    # Low-severity / Informational
    if status_code == 404: # Not Found
        return None # Usually not interesting unless looking for hidden paths
        
    # Default: No obvious vulnerability found
    return None

class WebFuzzer:
    """
    Manages the fuzzing process against a target URL.
    """
    def __init__(self, base_url):
        self.base_url = base_url
        self.payload_generator = PayloadGenerator() # Use our generator
        self.session = requests.Session() # Use a session for potential cookie handling
        self.session.headers.update({
            'User-Agent': 'AI-Smart-Fuzzer/0.1'
        })

    def fuzz_parameter(self, path, param_name, num_payloads=50):
        """
        Fuzzes a single URL parameter (GET or POST - starting with GET).
        
        Args:
            path (str): The path on the target (e.g., '/search').
            param_name (str): The name of the parameter to fuzz (e.g., 'query').
            num_payloads (int): How many fuzzing attempts to make.
        """
        target_url = urljoin(self.base_url, path)
        print(f"\n--- Fuzzing Parameter '{param_name}' at {target_url} ---")
        
        vulnerabilities_found = []

        for i in range(num_payloads):
            payload = self.payload_generator.generate_payload()
            
            # --- Send request with payload (GET example) ---
            params = {param_name: payload}
            try:
                response = self.session.get(target_url, params=params, timeout=5)
                
                # --- Analyze response ---
                vulnerability = check_response(response)
                
                if vulnerability:
                    print(f"[!] Potential Vulnerability Found!")
                    print(f"  Payload: {payload}")
                    print(f"  Indicator: {vulnerability}")
                    print(f"  Status Code: {response.status_code}")
                    print(f"  URL: {response.url}")
                    vulnerabilities_found.append({
                        'payload': payload,
                        'indicator': vulnerability,
                        'url': response.url
                    })
                    
                # Print progress occasionally
                if (i + 1) % 10 == 0:
                    print(f"  Progress: {i + 1}/{num_payloads} payloads sent...")

            except requests.exceptions.RequestException as e:
                print(f"  Error sending request with payload '{payload}': {e}")
                
            time.sleep(0.1) # Small delay to avoid overwhelming the server

        print(f"--- Fuzzing for '{param_name}' complete. Found {len(vulnerabilities_found)} potential issues. ---")
        return vulnerabilities_found

# --- Simple test ---
if __name__ == "__main__":
    # *** DO NOT RUN AGAINST A LIVE WEBSITE WITHOUT PERMISSION ***
    # We need a safe local target for testing. For now, this just shows structure.
    print("WebFuzzer class defined. Ready for integration in main.py.")
    print("Remember to set up a safe test environment before running.")
    # Example usage (DON'T RUN YET):
    # fuzzer = WebFuzzer("http://localhost:8080") 
    # fuzzer.fuzz_parameter("/search", "query", num_payloads=20)